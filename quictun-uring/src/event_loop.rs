use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::BytesMut;
use quinn_proto::{ClientConfig, ServerConfig};
use tracing::info;

use crate::bufpool::BUF_SIZE;
use crate::shared::{self, QuicState};
use crate::timer::Timer;
use crate::udp;

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

/// Run the direction-split io_uring data plane.
///
/// Spawns an outbound thread (TUN→QUIC→UDP) and an inbound thread (UDP→QUIC→TUN),
/// each with its own io_uring ring. Shared QUIC state protected by a Mutex.
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

    // 2. Build QuicState.
    let server_config = match &setup {
        EndpointSetup::Listener { server_config } => Some(server_config.clone()),
        EndpointSetup::Connector { .. } => None,
    };

    let mut quic_state = QuicState::new(remote_addr, server_config);

    // Connector: initiate connection.
    if let EndpointSetup::Connector {
        remote_addr,
        client_config,
    } = setup
    {
        let (handle, conn) = quic_state
            .endpoint
            .connect(Instant::now(), client_config, remote_addr, "quictun")
            .map_err(|e| anyhow::anyhow!("connect failed: {e:?}"))?;
        quic_state.ch = Some(handle);
        quic_state.connection = Some(conn);
    }

    // Listener: feed the first packet.
    if first_packet_len > 0 {
        let data = BytesMut::from(&first_packet[..first_packet_len]);
        let mut response_buf: Vec<u8> = Vec::new();
        let now = Instant::now();

        if let Some(event) = quic_state.endpoint.handle(
            now,
            remote_addr,
            None,
            None,
            data,
            &mut response_buf,
        ) {
            // Accept the connection. Response transmits are discarded (pre-thread).
            // Pending handshake transmits remain in the Connection and will be
            // drained by the outbound thread's initial drive() call.
            shared::handle_datagram_event(&mut quic_state, event, &mut response_buf);
        }
    }

    let quic = Mutex::new(quic_state);

    // 3. Create shared timer (inbound thread owns it, outbound can arm it).
    let timer = Timer::new().context("failed to create timerfd")?;

    // 4. Create shutdown eventfd.
    let shutdown_fd = create_eventfd().context("failed to create shutdown eventfd")?;
    let shutdown_raw = shutdown_fd.as_raw_fd();

    // 5. Spawn threads.
    thread::scope(|s| {
        let quic_ref = &quic;
        let timer_ref = &timer;

        let outbound_handle = s.spawn(move || {
            crate::outbound::run(tun_fd, udp_raw, quic_ref, timer_ref, shutdown_raw)
        });

        let inbound_handle = s.spawn(move || {
            crate::inbound::run(tun_fd, udp_raw, quic_ref, timer_ref, shutdown_raw)
        });

        // Wait for inbound thread first (it owns connection lifecycle via timer/handle_timeout).
        let inbound_result = inbound_handle.join();

        // Signal outbound thread to stop via eventfd.
        write_eventfd(&shutdown_fd);

        let outbound_result = outbound_handle.join();

        // Propagate errors.
        match inbound_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e).context("inbound thread error"),
            Err(_) => return Err(anyhow::anyhow!("inbound thread panicked")),
        }
        match outbound_result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e).context("outbound thread error"),
            Err(_) => return Err(anyhow::anyhow!("outbound thread panicked")),
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

/// Create a non-blocking eventfd for shutdown signaling.
fn create_eventfd() -> Result<OwnedFd> {
    let raw = unsafe { libc::eventfd(0, libc::EFD_NONBLOCK | libc::EFD_CLOEXEC) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error()).context("eventfd() failed");
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Write to an eventfd to signal shutdown.
fn write_eventfd(fd: &OwnedFd) {
    let val: u64 = 1;
    unsafe {
        libc::write(
            fd.as_raw_fd(),
            &val as *const u64 as *const libc::c_void,
            8,
        );
    }
}
