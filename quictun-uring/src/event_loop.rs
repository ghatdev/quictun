use std::net::SocketAddr;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use io_uring::{IoUring, opcode, types};
use quinn_proto::{
    ClientConfig, ConnectionHandle, DatagramEvent, Endpoint, EndpointConfig, Event, ServerConfig,
};
use tracing::{debug, info, warn};

use crate::bufpool::{
    self, BUF_SIZE, BufferPool, OP_TIMER, OP_TUN_READ, OP_TUN_WRITE, OP_UDP_RECV, OP_UDP_SEND,
};
use crate::timer::Timer;
use crate::udp;

/// Number of initial read SQEs to prime for each fd.
const PREFILL_READS: usize = 32;

/// Ring size (must be power of 2).
const RING_SIZE: u32 = 256;

/// Role of this endpoint in the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Connector,
    Listener,
}

/// Run the io_uring data plane event loop (blocking, single-threaded).
///
/// This replaces the tokio event loop for TUN ↔ QUIC forwarding on Linux.
/// Uses quinn-proto directly (synchronous state machine) and batches all I/O
/// through io_uring's submission/completion queues.
pub fn run(
    tun_fd: RawFd,
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    role: Role,
    client_config: Option<ClientConfig>,
    server_config: Option<Arc<ServerConfig>>,
) -> Result<()> {
    // 0. Set TUN fd to non-blocking.
    // io_uring handles EAGAIN on non-blocking fds by auto-polling and retrying.
    // Without this, reads go to io_uring's io-wq worker threads which block.
    set_nonblocking(tun_fd).context("failed to set TUN fd non-blocking")?;

    // 1. Create UDP socket (connected to remote).
    let udp_fd = udp::create_udp(local_addr, remote_addr).context("failed to create UDP socket")?;
    let udp_raw = udp_fd.as_raw_fd();
    let local_bind = udp::local_addr(&udp_fd)?;
    info!(bind = %local_bind, remote = %remote_addr, "UDP socket ready");

    // 2. Create io_uring ring.
    let mut ring = IoUring::new(RING_SIZE).context("failed to create io_uring")?;

    // 3. Create timerfd.
    let timer = Timer::new().context("failed to create timerfd")?;
    let timer_fd = timer.raw_fd();

    // 4. Create buffer pool.
    let mut pool = BufferPool::new();

    // Timer read buffer — 8 bytes for timerfd expiration count.
    let mut timer_buf = [0u8; 8];

    // Transmit scratch buffer for quinn-proto's poll_transmit.
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);

    // Response buffer for endpoint.handle / endpoint.accept.
    let mut response_buf: Vec<u8> = Vec::new();

    // 5. Create quinn-proto Endpoint + Connection.
    let ep_config = Arc::new(EndpointConfig::default());
    let mut endpoint = Endpoint::new(ep_config, server_config.clone(), true, None);

    let mut _state;

    // Connector: initiate connection immediately.
    // Listener: wait for incoming connection in the event loop.
    let (mut ch, mut connection): (Option<ConnectionHandle>, Option<quinn_proto::Connection>) =
        if role == Role::Connector {
            let config = client_config.context("connector requires client_config")?;
            let (handle, conn) = endpoint
                .connect(Instant::now(), config, remote_addr, "quictun")
                .map_err(|e| anyhow::anyhow!("connect failed: {e:?}"))?;
            _state = LoopState::Handshaking;
            (Some(handle), Some(conn))
        } else {
            info!(bind = %local_bind, "waiting for incoming connection");
            _state = LoopState::WaitingForConnection;
            (None, None)
        };

    // 6. Submit initial SQEs.

    // Prime UDP recv SQEs.
    for _ in 0..PREFILL_READS {
        submit_udp_recv(&mut ring, &mut pool, udp_raw)?;
    }

    // Submit timer read SQE.
    submit_timer_read(&mut ring, timer_fd, &mut timer_buf)?;

    // If connector, drain initial transmits (handshake Initial packet) and prime TUN reads.
    if let Some(ref mut conn) = connection {
        drain_transmits(conn, &mut ring, &mut pool, udp_raw, &mut transmit_buf)?;

        // Update timer.
        if let Some(deadline) = conn.poll_timeout() {
            timer.arm(deadline);
        }
    }

    // 7. Main event loop.
    info!("entering io_uring event loop");

    loop {
        // Submit pending SQEs and wait for at least 1 CQE.
        ring.submit_and_wait(1)
            .context("submit_and_wait failed")?;

        // Process all available CQEs.
        // Collect into a vec to release the borrow on the ring.
        let cqes: Vec<_> = ring.completion().collect();
        let now = Instant::now();

        for cqe in cqes {
            let user_data = cqe.user_data();
            let result = cqe.result();
            let op = bufpool::decode_op(user_data);
            let idx = bufpool::decode_index(user_data);

            match op {
                OP_TUN_READ => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "TUN read error");
                        pool.free(idx);
                        submit_tun_read(&mut ring, &mut pool, tun_fd)?;
                        continue;
                    }
                    let len = result as usize;
                    let data = Bytes::copy_from_slice(pool.slice(idx, len));
                    pool.free(idx);

                    // TUN packet → QUIC datagram (encrypt + queue).
                    if let Some(ref mut conn) = connection {
                        let max = conn.datagrams().max_size().unwrap_or(1200);
                        if len > max {
                            warn!(packet_size = len, max, "dropping oversized TUN packet");
                        } else {
                            if let Err(e) = conn.datagrams().send(data, true) {
                                debug!(error = ?e, "datagrams.send failed (dropped)");
                            }
                        }
                    }

                    // Resubmit TUN read.
                    submit_tun_read(&mut ring, &mut pool, tun_fd)?;
                }

                OP_TUN_WRITE => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "TUN write error");
                    }
                    pool.free(idx);
                }

                OP_UDP_RECV => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "UDP recv error");
                        pool.free(idx);
                        submit_udp_recv(&mut ring, &mut pool, udp_raw)?;
                        continue;
                    }
                    let len = result as usize;
                    let data = BytesMut::from(pool.slice(idx, len));
                    pool.free(idx);

                    // Feed to quinn-proto endpoint.
                    match endpoint.handle(now, remote_addr, None, None, data, &mut response_buf) {
                        Some(DatagramEvent::ConnectionEvent(event_ch, event)) => {
                            if let Some(ref mut conn) = connection {
                                if ch == Some(event_ch) {
                                    conn.handle_event(event);
                                }
                            }
                        }
                        Some(DatagramEvent::NewConnection(incoming)) => {
                            if role == Role::Listener && connection.is_none() {
                                match endpoint.accept(incoming, now, &mut response_buf, server_config.clone()) {
                                    Ok((new_ch, new_conn)) => {
                                        info!(remote = %remote_addr, "accepted incoming connection");
                                        ch = Some(new_ch);
                                        connection = Some(new_conn);
                                        _state = LoopState::Handshaking;
                                    }
                                    Err(e) => {
                                        warn!(error = ?e.cause, "failed to accept connection");
                                        if let Some(transmit) = e.response {
                                            send_transmit_immediate(
                                                &mut ring, &mut pool, udp_raw,
                                                &transmit, &response_buf,
                                            )?;
                                        }
                                    }
                                }
                            } else {
                                endpoint.ignore(incoming);
                            }
                        }
                        Some(DatagramEvent::Response(transmit)) => {
                            send_transmit_immediate(
                                &mut ring, &mut pool, udp_raw,
                                &transmit, &response_buf,
                            )?;
                        }
                        None => {}
                    }
                    response_buf.clear();

                    // Resubmit UDP recv.
                    submit_udp_recv(&mut ring, &mut pool, udp_raw)?;
                }

                OP_UDP_SEND => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        debug!(error = %err, "UDP send error");
                    }
                    pool.free(idx);
                }

                OP_TIMER => {
                    if let Some(ref mut conn) = connection {
                        conn.handle_timeout(now);
                    }
                    submit_timer_read(&mut ring, timer_fd, &mut timer_buf)?;
                }

                _ => {
                    warn!(op, "unknown op in CQE");
                }
            }

            // Drive connection state after EACH CQE — not just at end of batch.
            // This ensures transmits are produced immediately when datagrams are queued,
            // and incoming datagrams are delivered to TUN without waiting for the full batch.
            drive_connection(
                &mut connection, ch, &mut endpoint, &mut ring, &mut pool,
                tun_fd, udp_raw, &mut transmit_buf, &timer, &mut _state,
            )?;
        }

        // Flush all pending SQEs to the kernel immediately.
        ring.submit().context("submit flush failed")?;
    }
}

/// Internal state of the event loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LoopState {
    WaitingForConnection,
    Handshaking,
    Forwarding,
}

/// Drive connection state: process endpoint events, app events, drain transmits, update timer.
/// Called after each CQE to minimize latency between queueing a datagram and sending it.
#[allow(clippy::too_many_arguments)]
fn drive_connection(
    connection: &mut Option<quinn_proto::Connection>,
    ch: Option<ConnectionHandle>,
    endpoint: &mut Endpoint,
    ring: &mut IoUring,
    pool: &mut BufferPool,
    tun_fd: RawFd,
    udp_fd: RawFd,
    transmit_buf: &mut Vec<u8>,
    timer: &Timer,
    state: &mut LoopState,
) -> Result<()> {
    let (Some(conn), Some(conn_ch)) = (connection.as_mut(), ch) else {
        return Ok(());
    };

    // Process endpoint events.
    while let Some(event) = conn.poll_endpoint_events() {
        if let Some(conn_event) = endpoint.handle_event(conn_ch, event) {
            conn.handle_event(conn_event);
        }
    }

    // Process application events.
    while let Some(event) = conn.poll() {
        match event {
            Event::Connected => {
                info!("QUIC connection established");
                *state = LoopState::Forwarding;
                for _ in 0..PREFILL_READS {
                    submit_tun_read(ring, pool, tun_fd)?;
                }
            }
            Event::DatagramReceived => {
                while let Some(datagram) = conn.datagrams().recv() {
                    submit_tun_write(ring, pool, tun_fd, &datagram)?;
                }
            }
            Event::DatagramsUnblocked => {}
            Event::ConnectionLost { reason } => {
                info!(reason = %reason, "connection lost");
                std::process::exit(0);
            }
            Event::HandshakeDataReady | Event::Stream(_) => {}
        }
    }

    // Drain transmit queue.
    drain_transmits(conn, ring, pool, udp_fd, transmit_buf)?;

    // Update timer.
    match conn.poll_timeout() {
        Some(deadline) => timer.arm(deadline),
        None => timer.disarm(),
    }

    Ok(())
}

/// Submit a TUN read SQE.
fn submit_tun_read(ring: &mut IoUring, pool: &mut BufferPool, tun_fd: RawFd) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            debug!("buffer pool exhausted, skipping TUN read submit");
            return Ok(());
        }
    };
    let entry = opcode::Read::new(types::Fd(tun_fd), pool.ptr(idx), BUF_SIZE as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_TUN_READ, idx));

    unsafe { ring.submission().push(&entry) }.map_err(|_| anyhow::anyhow!("SQ full (tun read)"))?;
    Ok(())
}

/// Submit a TUN write SQE with the given data.
fn submit_tun_write(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    tun_fd: RawFd,
    data: &[u8],
) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("buffer pool exhausted, dropping TUN write");
            return Ok(());
        }
    };
    // Copy data into the pool buffer.
    let dst = unsafe { std::slice::from_raw_parts_mut(pool.ptr(idx), BUF_SIZE) };
    let len = data.len().min(BUF_SIZE);
    dst[..len].copy_from_slice(&data[..len]);

    let entry = opcode::Write::new(types::Fd(tun_fd), pool.ptr(idx), len as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_TUN_WRITE, idx));

    unsafe { ring.submission().push(&entry) }.map_err(|_| anyhow::anyhow!("SQ full (tun write)"))?;
    Ok(())
}

/// Submit a UDP recv SQE.
fn submit_udp_recv(ring: &mut IoUring, pool: &mut BufferPool, udp_fd: RawFd) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            debug!("buffer pool exhausted, skipping UDP recv submit");
            return Ok(());
        }
    };
    let entry = opcode::Read::new(types::Fd(udp_fd), pool.ptr(idx), BUF_SIZE as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_UDP_RECV, idx));

    unsafe { ring.submission().push(&entry) }.map_err(|_| anyhow::anyhow!("SQ full (udp recv)"))?;
    Ok(())
}

/// Submit a UDP send SQE with the given data.
fn submit_udp_send(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    udp_fd: RawFd,
    data: &[u8],
) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("buffer pool exhausted, dropping UDP send");
            return Ok(());
        }
    };
    let dst = unsafe { std::slice::from_raw_parts_mut(pool.ptr(idx), BUF_SIZE) };
    let len = data.len().min(BUF_SIZE);
    dst[..len].copy_from_slice(&data[..len]);

    let entry = opcode::Write::new(types::Fd(udp_fd), pool.ptr(idx), len as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx));

    unsafe { ring.submission().push(&entry) }.map_err(|_| anyhow::anyhow!("SQ full (udp send)"))?;
    Ok(())
}

/// Submit a timerfd read SQE.
fn submit_timer_read(
    ring: &mut IoUring,
    timer_fd: RawFd,
    buf: &mut [u8; 8],
) -> Result<()> {
    let entry = opcode::Read::new(types::Fd(timer_fd), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_TIMER, 0));

    unsafe { ring.submission().push(&entry) }.map_err(|_| anyhow::anyhow!("SQ full (timer)"))?;
    Ok(())
}

/// Drain all pending transmits from a connection and submit as UDP send SQEs.
fn drain_transmits(
    conn: &mut quinn_proto::Connection,
    ring: &mut IoUring,
    pool: &mut BufferPool,
    udp_fd: RawFd,
    buf: &mut Vec<u8>,
) -> Result<()> {
    let now = Instant::now();
    loop {
        buf.clear();
        match conn.poll_transmit(now, 1, buf) {
            Some(transmit) => {
                submit_udp_send(ring, pool, udp_fd, &buf[..transmit.size])?;
            }
            None => break,
        }
    }
    Ok(())
}

/// Send a response transmit immediately (for stateless resets, version negotiation, etc.).
fn send_transmit_immediate(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    udp_fd: RawFd,
    transmit: &quinn_proto::Transmit,
    buf: &[u8],
) -> Result<()> {
    submit_udp_send(ring, pool, udp_fd, &buf[..transmit.size])
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
