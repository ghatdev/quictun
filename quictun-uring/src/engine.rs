use std::os::fd::RawFd;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::Bytes;
use crossbeam_channel::Receiver;
use io_uring::{IoUring, opcode, types};
use tracing::{debug, info, warn};

use crate::bufpool::{
    self, BUF_SIZE, BufferPool, OP_SHUTDOWN, OP_TIMER, OP_TUN_WRITE, OP_UDP_RECV, OP_UDP_SEND,
    OP_WAKE,
};
use crate::shared::{self, QuicState};
use crate::timer::Timer;

/// Number of UDP recv SQEs to keep in flight.
const PREFILL_READS: usize = 32;

/// io_uring ring size for the engine thread.
const RING_SIZE: u32 = 256;

// Registered fd indices for the engine thread.
const FD_UDP: u32 = 0;
const FD_TUN: u32 = 1;
const FD_TIMER: u32 = 2;
const FD_NOTIFY: u32 = 3;
const FD_SHUTDOWN: u32 = 4;

/// Run the engine thread: owns all QUIC state exclusively (no Mutex).
///
/// Handles three event sources via io_uring:
/// - UDP recv: incoming QUIC packets → endpoint.handle() → drive()
/// - Timer: connection timeouts → handle_timeout() → drive()
/// - Channel (via eventfd): TUN packets from reader → send_datagram() → drive()
///
/// Uses registered fds and registered buffers for reduced kernel overhead.
pub fn run(
    tun_fd: RawFd,
    udp_fd: RawFd,
    mut quic: QuicState,
    timer: Timer,
    rx: Receiver<Vec<u8>>,
    notify_fd: RawFd,
    shutdown_fd: RawFd,
    sqpoll: bool,
) -> Result<()> {
    let mut ring = if sqpoll {
        IoUring::builder()
            .setup_sqpoll(1000)
            .build(RING_SIZE)
            .context("engine: failed to create io_uring with SQPOLL")?
    } else {
        IoUring::new(RING_SIZE).context("engine: failed to create io_uring")?
    };

    let mut pool = BufferPool::new();

    let timer_fd = timer.raw_fd();
    let mut timer_buf = [0u8; 8];
    let mut response_buf: Vec<u8> = Vec::new();

    // Register file descriptors for zero-overhead fd lookups.
    let fds = [udp_fd, tun_fd, timer_fd, notify_fd, shutdown_fd];
    ring.submitter()
        .register_files(&fds)
        .context("engine: failed to register files")?;

    // Register buffer pool for zero-copy I/O.
    pool.register(&ring)?;

    info!(sqpoll, "engine: io_uring initialized (registered fds + buffers)");

    // Prime UDP recv SQEs.
    for _ in 0..PREFILL_READS {
        submit_udp_recv(&mut ring, &mut pool)?;
    }

    // Submit timer read SQE.
    submit_timer_read(&mut ring, &mut timer_buf)?;

    // Submit channel notification eventfd read.
    let mut notify_buf = [0u8; 8];
    submit_notify_read(&mut ring, &mut notify_buf)?;

    // Submit shutdown eventfd read.
    let mut shutdown_buf = [0u8; 8];
    submit_shutdown_read(&mut ring, &mut shutdown_buf)?;

    // Drain initial handshake transmits (connector ClientHello / listener ServerHello).
    if quic.connection.is_some() {
        let result = shared::drive(&mut quic);
        do_io(&mut ring, &mut pool, &timer, &result, &[])?;
    }

    // Arm timer from initial connection state (connector may have a pending timeout).
    if let Some(conn) = quic.connection.as_mut() {
        if let Some(deadline) = conn.poll_timeout() {
            timer.arm(deadline);
        }
    }

    info!("engine: entering io_uring event loop");
    let mut stats_udp_recvs: u64 = 0;
    let mut stats_datagrams: u64 = 0;
    let mut stats_transmits: u64 = 0;
    let mut stats_timers: u64 = 0;
    let mut stats_channel_wakes: u64 = 0;
    let mut stats_channel_packets: u64 = 0;
    let mut stats_sends_ok: u64 = 0;
    let mut stats_sends_fail: u64 = 0;
    let mut stats_last = std::time::Instant::now();

    loop {
        ring.submit_and_wait(1)
            .context("engine: submit_and_wait failed")?;

        let cqes: Vec<_> = ring.completion().collect();

        for cqe in cqes {
            let user_data = cqe.user_data();
            let result = cqe.result();
            let op = bufpool::decode_op(user_data);
            let idx = bufpool::decode_index(user_data);

            match op {
                OP_UDP_RECV => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "engine: UDP recv error");
                        pool.free(idx);
                        submit_udp_recv(&mut ring, &mut pool)?;
                        continue;
                    }
                    stats_udp_recvs += 1;
                    let len = result as usize;
                    let data = bytes::BytesMut::from(pool.slice(idx, len));
                    pool.free(idx);

                    // Handle incoming packet, drive state machine.
                    let now = Instant::now();
                    let remote_addr = quic.remote_addr;

                    let mut resp_tx = Vec::new();
                    if let Some(event) = quic.endpoint.handle(
                        now,
                        remote_addr,
                        None,
                        None,
                        data,
                        &mut response_buf,
                    ) {
                        resp_tx =
                            shared::handle_datagram_event(&mut quic, event, &mut response_buf);
                    }
                    response_buf.clear();

                    let drive_result = shared::drive(&mut quic);
                    stats_datagrams += drive_result.datagrams.len() as u64;
                    stats_transmits += drive_result.transmits.len() as u64;

                    // Resubmit UDP recv.
                    submit_udp_recv(&mut ring, &mut pool)?;

                    if drive_result.connection_lost {
                        info!("engine: connection lost, signaling shutdown");
                        signal_shutdown(shutdown_fd);
                        return Ok(());
                    }
                    do_io(
                        &mut ring,
                        &mut pool,
                        &timer,
                        &drive_result,
                        &resp_tx,
                    )?;
                }

                OP_TIMER => {
                    stats_timers += 1;
                    let now = Instant::now();
                    if let Some(conn) = quic.connection.as_mut() {
                        conn.handle_timeout(now);
                    }
                    let drive_result = shared::drive(&mut quic);
                    stats_transmits += drive_result.transmits.len() as u64;

                    // Resubmit timer read.
                    submit_timer_read(&mut ring, &mut timer_buf)?;

                    if drive_result.connection_lost {
                        info!("engine: connection lost (timeout), signaling shutdown");
                        signal_shutdown(shutdown_fd);
                        return Ok(());
                    }
                    do_io(
                        &mut ring,
                        &mut pool,
                        &timer,
                        &drive_result,
                        &[],
                    )?;
                }

                OP_WAKE => {
                    stats_channel_wakes += 1;

                    // Drain all packets from the channel in one batch.
                    let mut batch_count: u64 = 0;
                    while let Ok(packet) = rx.try_recv() {
                        batch_count += 1;
                        if let Some(conn) = quic.connection.as_mut() {
                            if conn.is_handshaking() {
                                continue;
                            }
                            let max = conn.datagrams().max_size().unwrap_or(1200);
                            if packet.len() > max {
                                debug!(
                                    packet_size = packet.len(),
                                    max, "engine: dropping oversized TUN packet"
                                );
                            } else {
                                let data = Bytes::from(packet);
                                match conn.datagrams().send(data, true) {
                                    Ok(()) => stats_sends_ok += 1,
                                    Err(e) => {
                                        debug!(error = ?e, "engine: datagrams.send failed");
                                        stats_sends_fail += 1;
                                    }
                                }
                            }
                        }
                    }
                    stats_channel_packets += batch_count;

                    // Single drive() call for the entire batch.
                    let drive_result = shared::drive(&mut quic);
                    stats_transmits += drive_result.transmits.len() as u64;

                    // Resubmit channel eventfd read.
                    submit_notify_read(&mut ring, &mut notify_buf)?;

                    if drive_result.connection_lost {
                        info!("engine: connection lost, signaling shutdown");
                        signal_shutdown(shutdown_fd);
                        return Ok(());
                    }
                    do_io(
                        &mut ring,
                        &mut pool,
                        &timer,
                        &drive_result,
                        &[],
                    )?;
                }

                OP_UDP_SEND => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        debug!(error = %err, "engine: UDP send error");
                    }
                    pool.free(idx);
                }

                OP_TUN_WRITE => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "engine: TUN write error");
                    }
                    pool.free(idx);
                }

                OP_SHUTDOWN => {
                    debug!("engine: shutdown signal received");
                    return Ok(());
                }

                _ => {
                    warn!(op, "engine: unknown op in CQE");
                }
            }
        }

        if stats_last.elapsed() >= std::time::Duration::from_secs(2) {
            info!(
                udp_recvs = stats_udp_recvs,
                datagrams = stats_datagrams,
                transmits = stats_transmits,
                timers = stats_timers,
                channel_wakes = stats_channel_wakes,
                channel_packets = stats_channel_packets,
                sends_ok = stats_sends_ok,
                sends_fail = stats_sends_fail,
                free_bufs = pool.available(),
                "engine: stats"
            );
            stats_udp_recvs = 0;
            stats_datagrams = 0;
            stats_transmits = 0;
            stats_timers = 0;
            stats_channel_wakes = 0;
            stats_channel_packets = 0;
            stats_sends_ok = 0;
            stats_sends_fail = 0;
            stats_last = std::time::Instant::now();
        }

        ring.submit().context("engine: submit flush failed")?;
    }
}

/// Perform I/O operations from a DriveResult.
fn do_io(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    timer: &Timer,
    result: &shared::DriveResult,
    response_transmits: &[(usize, [u8; BUF_SIZE])],
) -> Result<()> {
    // Write decrypted datagrams to TUN.
    for datagram in &result.datagrams {
        submit_tun_write(ring, pool, datagram)?;
    }

    // Send UDP packets (from drive: ACKs, retransmits, etc.).
    for (len, data) in &result.transmits {
        submit_udp_send(ring, pool, &data[..*len])?;
    }

    // Send response transmits (from endpoint.handle: version negotiation, etc.).
    for (len, data) in response_transmits {
        submit_udp_send(ring, pool, &data[..*len])?;
    }

    // Update timer.
    match result.timer_deadline {
        Some(deadline) => timer.arm(deadline),
        None => timer.disarm(),
    }

    Ok(())
}

/// Submit a UDP recv using registered fd + registered buffer.
fn submit_udp_recv(ring: &mut IoUring, pool: &mut BufferPool) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            debug!("engine: buffer pool exhausted, skipping UDP recv submit");
            return Ok(());
        }
    };
    let entry =
        opcode::ReadFixed::new(types::Fixed(FD_UDP), pool.ptr(idx), BUF_SIZE as u32, idx as u16)
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_RECV, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("engine: SQ full (udp recv)"))?;
    Ok(())
}

/// Submit a UDP send using registered fd + registered buffer.
fn submit_udp_send(ring: &mut IoUring, pool: &mut BufferPool, data: &[u8]) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("engine: buffer pool exhausted, dropping UDP send");
            return Ok(());
        }
    };
    let dst = unsafe { std::slice::from_raw_parts_mut(pool.ptr(idx), BUF_SIZE) };
    let len = data.len().min(BUF_SIZE);
    dst[..len].copy_from_slice(&data[..len]);

    let entry =
        opcode::WriteFixed::new(types::Fixed(FD_UDP), pool.ptr(idx), len as u32, idx as u16)
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("engine: SQ full (udp send)"))?;
    Ok(())
}

/// Submit a TUN write using registered fd + registered buffer.
fn submit_tun_write(ring: &mut IoUring, pool: &mut BufferPool, data: &[u8]) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("engine: buffer pool exhausted, dropping TUN write");
            return Ok(());
        }
    };
    let dst = unsafe { std::slice::from_raw_parts_mut(pool.ptr(idx), BUF_SIZE) };
    let len = data.len().min(BUF_SIZE);
    dst[..len].copy_from_slice(&data[..len]);

    let entry =
        opcode::WriteFixed::new(types::Fixed(FD_TUN), pool.ptr(idx), len as u32, idx as u16)
            .build()
            .user_data(bufpool::encode_user_data(OP_TUN_WRITE, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("engine: SQ full (tun write)"))?;
    Ok(())
}

/// Submit a timer read using registered fd (non-pool buffer).
fn submit_timer_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_TIMER), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_TIMER, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("engine: SQ full (timer)"))?;
    Ok(())
}

/// Submit a channel notification eventfd read using registered fd (non-pool buffer).
fn submit_notify_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_NOTIFY), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_WAKE, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("engine: SQ full (notify)"))?;
    Ok(())
}

/// Submit a shutdown eventfd read using registered fd (non-pool buffer).
fn submit_shutdown_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_SHUTDOWN), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_SHUTDOWN, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("engine: SQ full (shutdown)"))?;
    Ok(())
}

/// Write to the shutdown eventfd to wake the reader thread.
fn signal_shutdown(fd: RawFd) {
    let val: u64 = 1;
    unsafe {
        libc::write(fd, &val as *const u64 as *const libc::c_void, 8);
    }
}
