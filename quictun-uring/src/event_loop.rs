use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::Arc;
use std::thread;
use std::time::Instant;

use anyhow::{Context, Result};
use quinn_proto::{ClientConfig, ServerConfig};
use tracing::info;

use crate::shared::QuicState;
use crate::timer::Timer;
use crate::udp;

/// Channel capacity for TUN packets from reader → engine.
/// Provides backpressure: reader drops packets when full (same as
/// tokio parallel behavior when send_datagram fails under congestion).
const CHANNEL_CAPACITY: usize = 512;

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

/// Run the lock-free io_uring data plane.
///
/// When `cores` is 1, spawns one reader + engine pair (single connection).
/// When `cores` > 1, spawns N pairs — each with its own TUN queue, UDP socket,
/// QUIC connection, and io_uring rings. Listener uses ports listen_port through
/// listen_port+N-1; connector connects to each.
///
/// When `sqpoll` is true, all rings use IORING_SETUP_SQPOLL (requires root).
pub fn run(
    tun_fds: Vec<RawFd>,
    local_addr: SocketAddr,
    setup: EndpointSetup,
    sqpoll: bool,
    pool_size: usize,
) -> Result<()> {
    let cores = tun_fds.len();

    // Set all TUN fds to non-blocking for io_uring.
    for &fd in &tun_fds {
        set_nonblocking(fd).context("failed to set TUN fd non-blocking")?;
    }

    // Build per-core state: (udp_fd, quic_state, server_config) for each core.
    // Connector: QuicState is Some (connection already initiated).
    // Listener: QuicState is None (first-packet handling moved to engine thread
    //           so all cores block in parallel instead of sequentially).
    let mut core_state: Vec<(OwnedFd, Option<QuicState>)> = Vec::with_capacity(cores);
    let server_config: Option<Arc<ServerConfig>> = match &setup {
        EndpointSetup::Listener { server_config } => Some(server_config.clone()),
        _ => None,
    };

    match &setup {
        EndpointSetup::Connector {
            remote_addr,
            client_config,
        } => {
            // Connector: each core creates its own UDP socket + QUIC connection.
            // Core i connects to remote_addr port + i.
            for i in 0..cores {
                let remote = if cores > 1 {
                    SocketAddr::new(remote_addr.ip(), remote_addr.port() + i as u16)
                } else {
                    *remote_addr
                };

                let udp_fd = udp::create_udp(local_addr, remote)
                    .with_context(|| format!("core {i}: failed to create UDP socket"))?;
                let bind = udp::local_addr(&udp_fd)?;
                info!(core = i, bind = %bind, remote = %remote, "UDP socket ready (connector)");

                let mut quic = QuicState::new(remote, None);
                let (handle, conn) = quic
                    .endpoint
                    .connect(Instant::now(), client_config.clone(), remote, "quictun")
                    .map_err(|e| anyhow::anyhow!("core {i}: connect failed: {e:?}"))?;
                quic.ch = Some(handle);
                quic.connection = Some(conn);

                core_state.push((udp_fd, Some(quic)));
            }
        }
        EndpointSetup::Listener { .. } => {
            // Listener: each core binds to listen_port + i.
            // First-packet handling is deferred to each engine thread so all
            // cores block in parallel (fixes sequential 7s+ startup delay).
            for i in 0..cores {
                let listen_addr = if cores > 1 {
                    SocketAddr::new(local_addr.ip(), local_addr.port() + i as u16)
                } else {
                    local_addr
                };

                let udp_fd = udp::create_udp_unbound(listen_addr)
                    .with_context(|| format!("core {i}: failed to create UDP socket"))?;
                let bind = udp::local_addr(&udp_fd)?;
                info!(core = i, bind = %bind, "UDP socket bound (listener, waiting deferred to engine)");

                core_state.push((udp_fd, None));
            }
        }
    }

    // Create per-core resources and spawn threads.
    thread::scope(|s| {
        let mut engine_handles = Vec::with_capacity(cores);
        let mut reader_handles = Vec::with_capacity(cores);
        // Keep OwnedFds alive for the duration of all threads.
        // Threads use raw fd values; the OwnedFds here own the lifecycle.
        let mut shutdown_fds: Vec<OwnedFd> = Vec::with_capacity(cores);
        let mut udp_fds: Vec<OwnedFd> = Vec::with_capacity(cores);
        let mut notify_fds: Vec<OwnedFd> = Vec::with_capacity(cores);

        for (i, ((udp_fd, quic_state), &tun_fd)) in
            core_state.into_iter().zip(tun_fds.iter()).enumerate()
        {
            let udp_raw = udp_fd.as_raw_fd();
            udp_fds.push(udp_fd);

            let timer = Timer::new()
                .with_context(|| format!("core {i}: failed to create timerfd"))?;
            let shutdown_fd = create_eventfd()
                .with_context(|| format!("core {i}: failed to create shutdown eventfd"))?;
            let shutdown_raw = shutdown_fd.as_raw_fd();
            let notify_fd = create_eventfd()
                .with_context(|| format!("core {i}: failed to create notify eventfd"))?;
            let notify_raw = notify_fd.as_raw_fd();

            shutdown_fds.push(shutdown_fd);
            notify_fds.push(notify_fd);

            let (tx, rx) = crossbeam_channel::bounded(CHANNEL_CAPACITY);

            let core_id = i;
            let sqp = sqpoll;

            let ps = pool_size;
            let reader_h = s.spawn(move || {
                pin_to_core(core_id);
                crate::reader::run(tun_fd, tx, notify_raw, shutdown_raw, sqp, ps)
            });

            let ps = pool_size;
            let sc = server_config.clone();
            let engine_h = s.spawn(move || {
                pin_to_core(core_id);
                crate::engine::run(
                    tun_fd, udp_raw, quic_state, sc, timer, rx, notify_raw, shutdown_raw, sqp, ps,
                )
            });

            reader_handles.push(reader_h);
            engine_handles.push(engine_h);
        }

        // Wait for all engine threads (they own connection lifecycle).
        let mut first_error: Option<anyhow::Error> = None;
        for (i, handle) in engine_handles.into_iter().enumerate() {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_error.is_none() {
                        first_error =
                            Some(e.context(format!("engine thread {i} error")));
                    }
                }
                Err(_) => {
                    if first_error.is_none() {
                        first_error =
                            Some(anyhow::anyhow!("engine thread {i} panicked"));
                    }
                }
            }
        }

        // Signal all reader threads to stop.
        for fd in &shutdown_fds {
            write_eventfd(fd);
        }

        for (i, handle) in reader_handles.into_iter().enumerate() {
            match handle.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_error.is_none() {
                        first_error =
                            Some(e.context(format!("reader thread {i} error")));
                    }
                }
                Err(_) => {
                    if first_error.is_none() {
                        first_error =
                            Some(anyhow::anyhow!("reader thread {i} panicked"));
                    }
                }
            }
        }

        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    })
}

/// Pin the calling thread to a specific CPU core.
fn pin_to_core(core_id: usize) {
    unsafe {
        let mut set: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut set);
        libc::CPU_SET(core_id, &mut set);
        let ret = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &set);
        if ret == 0 {
            tracing::debug!(core = core_id, "pinned thread to core");
        } else {
            tracing::warn!(core = core_id, "failed to pin thread to core (non-fatal)");
        }
    }
}

/// Set a file descriptor to non-blocking mode.
pub(crate) fn set_nonblocking(fd: RawFd) -> Result<()> {
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
pub(crate) fn set_blocking(fd: RawFd) -> Result<()> {
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

/// Create a non-blocking eventfd.
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
