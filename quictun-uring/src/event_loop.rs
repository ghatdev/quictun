use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use quinn_proto::{ClientConfig, ServerConfig};
use tracing::info;

use crate::bufpool::BUF_SIZE;
use crate::quic_loop;
use crate::udp;
use crate::wakeup::EventFd;

/// Channel capacity for cross-thread packet queues.
const CHANNEL_CAP: usize = 256;

/// How the QUIC endpoint should be set up.
pub enum EndpointSetup {
    Connector {
        remote_addr: SocketAddr,
        client_config: ClientConfig,
    },
    Listener {
        server_config: Arc<ServerConfig>,
    },
}

/// Run the two-thread io_uring data plane.
///
/// Spawns a TUN thread and a QUIC thread, each with its own io_uring ring.
/// Cross-thread communication via bounded crossbeam channels + eventfd wakeups.
pub fn run(tun_fd: RawFd, local_addr: SocketAddr, setup: EndpointSetup) -> Result<()> {
    // 0. Set TUN fd to non-blocking for io_uring.
    set_nonblocking(tun_fd).context("failed to set TUN fd non-blocking")?;

    // 1. Create UDP socket.
    let (udp_fd, remote_addr, first_packet, first_packet_len) = match &setup {
        EndpointSetup::Connector { remote_addr, .. } => {
            let fd = udp::create_udp(local_addr, *remote_addr)
                .context("failed to create connected UDP socket")?;
            let bind = udp::local_addr(&fd)?;
            info!(bind = %bind, remote = %remote_addr, "UDP socket ready (connector)");
            (fd, *remote_addr, Vec::new(), 0)
        }
        EndpointSetup::Listener { .. } => {
            // Bind-only socket, then blocking recvfrom to learn peer address.
            let fd = udp::create_udp_unbound(local_addr)
                .context("failed to create unbound UDP socket")?;
            let bind = udp::local_addr(&fd)?;
            info!(bind = %bind, "UDP socket bound, waiting for first packet (listener)");

            // Temporarily set blocking for recvfrom.
            set_blocking(fd.as_raw_fd()).context("failed to set UDP fd blocking")?;

            let mut buf = vec![0u8; BUF_SIZE];
            let (n, peer) =
                udp::recvfrom_first(&fd, &mut buf).context("recvfrom_first failed")?;
            info!(peer = %peer, bytes = n, "received first packet, connecting to peer");

            // Connect to the learned peer address.
            udp::connect_to_peer(&fd, peer).context("failed to connect to learned peer")?;

            // Set back to non-blocking for io_uring.
            set_nonblocking(fd.as_raw_fd()).context("failed to set UDP fd non-blocking")?;

            (fd, peer, buf, n)
        }
    };

    let udp_raw = udp_fd.as_raw_fd();

    // 2. Create cross-thread channels + eventfds.
    let (to_quic_tx, to_quic_rx) = crossbeam_channel::bounded(CHANNEL_CAP);
    let (to_tun_tx, to_tun_rx) = crossbeam_channel::bounded(CHANNEL_CAP);

    let tun_wake = EventFd::new().context("failed to create TUN eventfd")?;
    let quic_wake = EventFd::new().context("failed to create QUIC eventfd")?;

    // 3. Build QUIC thread setup.
    let quic_setup = match setup {
        EndpointSetup::Connector {
            remote_addr,
            client_config,
        } => quic_loop::Setup::Connector(quic_loop::ConnectorSetup {
            remote_addr,
            client_config,
        }),
        EndpointSetup::Listener { server_config } => {
            quic_loop::Setup::Listener(quic_loop::ListenerSetup {
                server_config,
                remote_addr,
                first_packet,
                first_packet_len,
            })
        }
    };

    // 4. Shared shutdown flag.
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_tun = shutdown.clone();

    // 5. Spawn threads.
    // Both threads need references to both eventfds. Create explicit references
    // so the move closures copy the references (which are Copy) rather than
    // trying to move the EventFds themselves.
    let tun_wake_ref = &tun_wake;
    let quic_wake_ref = &quic_wake;

    thread::scope(|s| {
        let tun_handle = s.spawn(move || {
            crate::tun_loop::run(
                tun_fd,
                to_quic_tx,
                to_tun_rx,
                tun_wake_ref,
                quic_wake_ref,
                shutdown_tun,
            )
        });

        let quic_handle = s.spawn(move || {
            quic_loop::run(
                udp_raw,
                quic_setup,
                to_quic_rx,
                to_tun_tx,
                quic_wake_ref,
                tun_wake_ref,
            )
        });

        // Wait for QUIC thread first (it owns the connection lifecycle).
        // When it exits (connection lost / error), signal TUN thread to stop.
        let quic_result = quic_handle.join();
        shutdown.store(true, Ordering::Relaxed);

        // Wake TUN thread so it exits submit_and_wait.
        tun_wake.wake();

        let tun_result = tun_handle.join();

        // Propagate errors.
        match quic_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e).context("QUIC thread error"),
            Err(_) => return Err(anyhow::anyhow!("QUIC thread panicked")),
        }
        match tun_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e).context("TUN thread error"),
            Err(_) => return Err(anyhow::anyhow!("TUN thread panicked")),
        }

        Ok(())
    })
}

/// Set a file descriptor to non-blocking mode.
fn set_nonblocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_GETFL");
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_SETFL O_NONBLOCK");
    }
    Ok(())
}

/// Set a file descriptor to blocking mode.
fn set_blocking(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_GETFL");
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(std::io::Error::last_os_error()).context("fcntl F_SETFL blocking");
    }
    Ok(())
}
