use std::os::fd::{AsRawFd, RawFd};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::{Bytes, BytesMut};
use crossbeam_channel::{Receiver, Sender};
use io_uring::{IoUring, cqueue, opcode, squeue::Flags, types};
use quinn_proto::ServerConfig;
use tracing::{debug, info, warn};

use crate::bufpool::{
    self, BUF_GROUP_UDP, BUF_SIZE, BufferPool, OP_PROVIDE_BUF, OP_SHUTDOWN, OP_TIMER, OP_TUN_WRITE,
    OP_UDP_RECV, OP_UDP_SEND, OP_WAKE, ProvidedPool,
};
use crate::event_loop::{set_blocking, set_nonblocking};
use crate::shared::{self, QuicState};
use crate::timer::Timer;
use crate::udp;

/// io_uring ring size for the engine thread.
/// 1024 handles burst SQE pushes where a single CQE batch can generate
/// reprovide + TUN write + drain_transmits SQEs exceeding smaller ring sizes.
const RING_SIZE: u32 = 1024;

// Registered fd indices for the engine thread.
const FD_UDP: u32 = 0;
const FD_TUN: u32 = 1;
const FD_TIMER: u32 = 2;
const FD_NOTIFY: u32 = 3;
const FD_SHUTDOWN: u32 = 4;

/// Run the engine thread: owns all QUIC state exclusively (no Mutex).
///
/// Handles three event sources via io_uring:
/// - UDP recv: incoming QUIC packets → endpoint.handle()
/// - Timer: connection timeouts → handle_timeout()
/// - Channel (via eventfd): TUN packets from reader → send_datagram()
///
/// Events are batched: all CQEs are handled first (feeding quinn state machine),
/// then a single process_events() + drain_transmits() produces I/O for the batch.
/// This coalesces ACKs (N packets → 1 ACK instead of N ACKs).
///
/// Uses registered fds and registered buffers for reduced kernel overhead.
pub fn run(
    tun_fd: RawFd,
    udp_fd: RawFd,
    quic: Option<QuicState>,
    server_config: Option<Arc<ServerConfig>>,
    timer: Timer,
    rx: Receiver<Vec<u8>>,
    notify_fd: RawFd,
    shutdown_fd: RawFd,
    sqpoll: bool,
    sqpoll_cpu: Option<u32>,
    pool_size: usize,
    zero_copy: bool,
    ring_fd_tx: Option<Sender<RawFd>>,
) -> Result<()> {
    // Resolve QuicState: connector has it ready, listener must wait for first packet.
    let mut quic = if let Some(qs) = quic {
        qs
    } else {
        // Listener: blocking wait for first packet (runs in parallel across cores).
        let server_config = server_config.expect("listener engine requires server_config");
        set_blocking(udp_fd).context("engine: failed to set blocking for first-packet recv")?;

        let mut buf = vec![0u8; BUF_SIZE];
        let (n, peer) =
            udp::recvfrom_first_raw(udp_fd, &mut buf).context("engine: recvfrom_first failed")?;
        info!(peer = %peer, bytes = n, "engine: received first packet");

        udp::connect_to_peer_raw(udp_fd, peer).context("engine: connect_to_peer failed")?;
        set_nonblocking(udp_fd)
            .context("engine: failed to set non-blocking after first-packet recv")?;

        // Feed the first packet to the QUIC endpoint.
        let mut qs = QuicState::new(peer, Some(server_config));
        let data = BytesMut::from(&buf[..n]);
        let mut response_buf: Vec<u8> = Vec::new();
        if let Some(event) =
            qs.endpoint
                .handle(Instant::now(), peer, None, None, data, &mut response_buf)
        {
            shared::handle_datagram_event(&mut qs, event, &mut response_buf);
        }
        qs
    };

    let mut ring = if sqpoll {
        let mut builder = IoUring::builder();
        builder.setup_sqpoll(1000);
        if let Some(cpu) = sqpoll_cpu {
            builder.setup_sqpoll_cpu(cpu);
        }
        builder
            .build(RING_SIZE)
            .context("engine: failed to create io_uring with SQPOLL")?
    } else {
        IoUring::new(RING_SIZE).context("engine: failed to create io_uring")?
    };

    // Signal ring fd to reader so it can attach_wq to our SQPOLL thread.
    if let Some(tx) = ring_fd_tx {
        let _ = tx.send(ring.as_raw_fd());
    }

    // Registered buffer pool for sends + TUN writes (WriteFixed).
    let mut pool = BufferPool::new(pool_size);

    // Provided buffer pool for multishot UDP recv (kernel-managed).
    let recv_pool = ProvidedPool::new(pool_size, BUF_GROUP_UDP);

    let timer_fd = timer.raw_fd();
    let mut timer_buf = [0u8; 8];
    let mut response_buf: Vec<u8> = Vec::new();

    // Register file descriptors for zero-overhead fd lookups.
    let fds = [udp_fd, tun_fd, timer_fd, notify_fd, shutdown_fd];
    ring.submitter()
        .register_files(&fds)
        .context("engine: failed to register files")?;

    // Register send/TUN buffer pool (SendZc when --zero-copy, WriteFixed otherwise).
    pool.register(&ring)?;

    info!(
        sqpoll,
        "engine: io_uring initialized (registered fds + buffers)"
    );

    // Provide all recv buffers to kernel (single SQE).
    provide_all_buffers(&mut ring, &recv_pool)?;

    // Submit one multishot recv (replaces 32× ReadFixed).
    submit_multishot_recv(&mut ring, &recv_pool)?;
    let mut multishot_active = true;

    // Submit timer read SQE.
    submit_timer_read(&mut ring, &mut timer_buf)?;

    // Submit channel notification eventfd read.
    let mut notify_buf = [0u8; 8];
    submit_notify_read(&mut ring, &mut notify_buf)?;

    // Submit shutdown eventfd read.
    let mut shutdown_buf = [0u8; 8];
    submit_shutdown_read(&mut ring, &mut shutdown_buf)?;

    // Pre-allocate reusable buffers (avoids per-iteration allocation).
    let mut drive_result = shared::DriveResult::new();
    let mut resp_transmits: Vec<(usize, [u8; BUF_SIZE])> = Vec::new();
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);

    // Drain initial handshake transmits (connector ClientHello / listener ServerHello).
    if quic.connection.is_some() {
        shared::process_events(&mut quic, &mut drive_result);
        for dg in &drive_result.datagrams {
            submit_tun_write(&mut ring, &mut pool, dg)?;
        }
        drain_transmits(
            &mut quic,
            &mut ring,
            &mut pool,
            &mut transmit_buf,
            zero_copy,
        )?;
        update_timer(&mut quic, &timer);
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
    let mut stats_tx_stalls: u64 = 0;
    let mut stats_last = std::time::Instant::now();

    loop {
        // submit_and_wait submits all accumulated SQEs AND waits for ≥1 CQE.
        // With SQPOLL: SQE submission is free (kernel polls shared memory),
        // but we still need io_uring_enter(GETEVENTS) to block-wait for CQEs.
        // Busy-polling the CQ would eliminate this syscall but requires a
        // dedicated core — not possible when reader shares the same core.
        ring.submit_and_wait(1)
            .context("engine: submit_and_wait failed")?;

        let cqes: Vec<_> = ring.completion().collect();

        // Phase 1: Handle all events (no drive/IO yet).
        // Feed packets into quinn state machine, accumulate response transmits.
        let mut had_udp = false;
        let mut had_timer = false;
        let mut had_wake = false;
        resp_transmits.clear();

        for cqe in cqes {
            let user_data = cqe.user_data();
            let result = cqe.result();
            let op = bufpool::decode_op(user_data);
            let idx = bufpool::decode_index(user_data);

            match op {
                OP_UDP_RECV => {
                    if result < 0 {
                        // Multishot cancelled (e.g., -ENOBUFS) or error.
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "engine: multishot recv error");
                        multishot_active = false;
                        continue;
                    }
                    stats_udp_recvs += 1;
                    let flags = cqe.flags();
                    let bid = cqueue::buffer_select(flags)
                        .expect("RecvMulti CQE must have BUFFER_SELECT flag");
                    let len = result as usize;
                    let data = BytesMut::from(recv_pool.slice(bid, len));

                    // Re-provide consumed buffer (SKIP_SUCCESS suppresses CQE).
                    reprovide_buffer(&mut ring, &recv_pool, bid)?;

                    // Feed packet into quinn state machine (no drive yet).
                    let now = Instant::now();
                    let remote_addr = quic.remote_addr;
                    if let Some(event) =
                        quic.endpoint
                            .handle(now, remote_addr, None, None, data, &mut response_buf)
                    {
                        let mut tx =
                            shared::handle_datagram_event(&mut quic, event, &mut response_buf);
                        resp_transmits.append(&mut tx);
                    }
                    response_buf.clear();

                    if !cqueue::more(flags) {
                        multishot_active = false;
                    }
                    had_udp = true;
                }

                OP_TIMER => {
                    stats_timers += 1;
                    let now = Instant::now();
                    if let Some(conn) = quic.connection.as_mut() {
                        conn.handle_timeout(now);
                    }
                    // Resubmit timer read.
                    submit_timer_read(&mut ring, &mut timer_buf)?;
                    had_timer = true;
                }

                OP_WAKE => {
                    stats_channel_wakes += 1;

                    // Drain all packets from the channel — queue into quinn.
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

                    // Resubmit channel eventfd read.
                    submit_notify_read(&mut ring, &mut notify_buf)?;
                    had_wake = true;
                }

                OP_UDP_SEND => {
                    if zero_copy {
                        // SendZc produces 2 CQEs: completion + notification.
                        // Buffer can only be freed on the notification CQE.
                        let flags = cqe.flags();
                        if cqueue::notif(flags) {
                            pool.free(idx);
                        } else if result < 0 {
                            let err = std::io::Error::from_raw_os_error(-result);
                            debug!(error = %err, "engine: UDP send error");
                        }
                    } else {
                        // WriteFixed: single CQE, free immediately.
                        if result < 0 {
                            let err = std::io::Error::from_raw_os_error(-result);
                            debug!(error = %err, "engine: UDP send error");
                        }
                        pool.free(idx);
                    }
                }

                OP_TUN_WRITE => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "engine: TUN write error");
                    }
                    pool.free(idx);
                }

                OP_PROVIDE_BUF => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "engine: provide buffer failed");
                    }
                    // Success CQEs suppressed by SKIP_SUCCESS flag.
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

        // Resubmit multishot recv if it was cancelled.
        if !multishot_active {
            submit_multishot_recv(&mut ring, &recv_pool)?;
            multishot_active = true;
        }

        // Phase 2: Single process_events + I/O for ALL events in this batch.
        // N UDP packets → 1 drive → coalesced ACKs instead of N separate ACKs.
        // Transmits go directly from quinn → buffer pool (1 copy, not 3).
        if had_udp || had_timer || had_wake {
            shared::process_events(&mut quic, &mut drive_result);
            stats_datagrams += drive_result.datagrams.len() as u64;

            if drive_result.connection_lost {
                info!("engine: connection lost, signaling shutdown");
                signal_shutdown(shutdown_fd);
                return Ok(());
            }

            // Write decrypted datagrams to TUN.
            for dg in &drive_result.datagrams {
                submit_tun_write(&mut ring, &mut pool, dg)?;
            }

            // Send response transmits (handshake: version negotiation, etc.).
            for (len, data) in &resp_transmits {
                submit_udp_send(&mut ring, &mut pool, &data[..*len], zero_copy)?;
            }

            // Drain quinn transmits directly to buffer pool → io_uring.
            // Stops early if pool is low (back-pressure), quinn holds the rest.
            let (n, stalled) = drain_transmits(
                &mut quic,
                &mut ring,
                &mut pool,
                &mut transmit_buf,
                zero_copy,
            )?;
            stats_transmits += n as u64;
            if stalled {
                stats_tx_stalls += 1;
            }

            // Update timer from connection state.
            update_timer(&mut quic, &timer);
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
                tx_stalls = stats_tx_stalls,
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
            stats_tx_stalls = 0;
            stats_last = std::time::Instant::now();
        }
    }
}

/// Minimum free buffers to reserve for recv resubmits and TUN writes.
/// Prevents transmit drain from starving the receive path.
const RESERVED_BUFS: usize = 64;

/// Drain quinn-proto transmit queue directly into buffer pool + io_uring SQEs.
///
/// Path: poll_transmit → transmit_buf (Vec) → pool slot → SendZc/WriteFixed SQE.
/// SendZc (--zero-copy) avoids the kernel-side copy to socket buffer.
///
/// Back-pressure: stops draining when pool is low (≤ RESERVED_BUFS free).
/// Quinn-proto holds remaining transmits internally until the next iteration,
/// when completed send SQEs return buffers to the pool. This prevents the
/// catastrophic pattern of dropping QUIC packets → congestion collapse.
///
/// Returns (drained_count, stalled: bool).
fn drain_transmits(
    quic: &mut QuicState,
    ring: &mut IoUring,
    pool: &mut BufferPool,
    transmit_buf: &mut Vec<u8>,
    zero_copy: bool,
) -> Result<(usize, bool)> {
    let conn = match quic.connection.as_mut() {
        Some(c) => c,
        None => return Ok((0, false)),
    };

    let now = Instant::now();
    let mut count = 0;
    let mut stalled = false;

    loop {
        // Back-pressure: stop if pool is low, leaving headroom for recv/TUN ops.
        // Quinn-proto keeps remaining transmits in its internal queue — they'll
        // be drained next iteration after send completions free buffers.
        if pool.available() <= RESERVED_BUFS {
            stalled = true;
            break;
        }

        transmit_buf.clear();
        match conn.poll_transmit(now, 1, transmit_buf) {
            Some(transmit) => {
                let len = transmit.size;
                submit_udp_send_direct(ring, pool, transmit_buf, len, zero_copy)?;
                count += 1;
            }
            None => break,
        }
    }

    Ok((count, stalled))
}

/// Submit a UDP send by copying data into a pool slot.
///
/// When `zero_copy` is true, uses SendZc (skips kernel-side memcpy, 2 CQEs per send).
/// When false, uses WriteFixed (kernel copies from registered buffer, 1 CQE per send).
///
/// Called by `drain_transmits` which already checks pool availability
/// via back-pressure (RESERVED_BUFS). Should not fail under normal operation.
fn submit_udp_send_direct(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    src: &[u8],
    len: usize,
    zero_copy: bool,
) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            // Should not happen — drain_transmits checks pool.available() > RESERVED_BUFS.
            // If it does, the transmit was already consumed from quinn. Log and continue.
            debug!("engine: unexpected buffer pool exhaustion in send_direct");
            return Ok(());
        }
    };
    let dst = pool.slice_mut(idx);
    let len = len.min(BUF_SIZE);
    dst[..len].copy_from_slice(&src[..len]);

    let entry = if zero_copy {
        opcode::SendZc::new(types::Fixed(FD_UDP), pool.ptr(idx), len as u32)
            .buf_index(Some(idx as u16))
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx))
    } else {
        opcode::WriteFixed::new(types::Fixed(FD_UDP), pool.ptr(idx), len as u32, idx as u16)
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx))
    };

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Update the timer from the current QUIC connection state.
fn update_timer(quic: &mut QuicState, timer: &Timer) {
    if let Some(conn) = quic.connection.as_mut() {
        match conn.poll_timeout() {
            Some(deadline) => timer.arm(deadline),
            None => timer.disarm(),
        }
    }
}

/// Provide all buffers in the recv pool to the kernel as a buffer group.
fn provide_all_buffers(ring: &mut IoUring, recv_pool: &ProvidedPool) -> Result<()> {
    let entry = opcode::ProvideBuffers::new(
        recv_pool.ptr(0),
        BUF_SIZE as i32,
        recv_pool.size() as u16,
        recv_pool.group_id(),
        0, // starting bid
    )
    .build()
    .user_data(bufpool::encode_user_data(OP_PROVIDE_BUF, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a single multishot recv SQE (replaces 32× ReadFixed).
fn submit_multishot_recv(ring: &mut IoUring, recv_pool: &ProvidedPool) -> Result<()> {
    let entry = opcode::RecvMulti::new(types::Fixed(FD_UDP), recv_pool.group_id())
        .build()
        .user_data(bufpool::encode_user_data(OP_UDP_RECV, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Re-provide a single consumed buffer back to the kernel.
/// Uses SKIP_SUCCESS to suppress the CQE on success.
fn reprovide_buffer(ring: &mut IoUring, recv_pool: &ProvidedPool, bid: u16) -> Result<()> {
    let entry = opcode::ProvideBuffers::new(
        recv_pool.ptr(bid),
        BUF_SIZE as i32,
        1,
        recv_pool.group_id(),
        bid,
    )
    .build()
    .flags(Flags::SKIP_SUCCESS)
    .user_data(bufpool::encode_user_data(OP_PROVIDE_BUF, bid as usize));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a UDP send using registered fd + registered buffer.
///
/// When `zero_copy` is true, uses SendZc (2 CQEs). Otherwise uses WriteFixed (1 CQE).
fn submit_udp_send(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    data: &[u8],
    zero_copy: bool,
) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("engine: buffer pool exhausted, dropping UDP send");
            return Ok(());
        }
    };
    let len = data.len().min(BUF_SIZE);
    pool.slice_mut(idx)[..len].copy_from_slice(&data[..len]);

    let entry = if zero_copy {
        opcode::SendZc::new(types::Fixed(FD_UDP), pool.ptr(idx), len as u32)
            .buf_index(Some(idx as u16))
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx))
    } else {
        opcode::WriteFixed::new(types::Fixed(FD_UDP), pool.ptr(idx), len as u32, idx as u16)
            .build()
            .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx))
    };

    push_sqe(ring, &entry)?;
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
    let len = data.len().min(BUF_SIZE);
    pool.slice_mut(idx)[..len].copy_from_slice(&data[..len]);

    let entry =
        opcode::WriteFixed::new(types::Fixed(FD_TUN), pool.ptr(idx), len as u32, idx as u16)
            .build()
            .user_data(bufpool::encode_user_data(OP_TUN_WRITE, idx));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a timer read using registered fd (non-pool buffer).
fn submit_timer_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_TIMER), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_TIMER, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a channel notification eventfd read using registered fd (non-pool buffer).
fn submit_notify_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_NOTIFY), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_WAKE, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Submit a shutdown eventfd read using registered fd (non-pool buffer).
fn submit_shutdown_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_SHUTDOWN), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_SHUTDOWN, 0));

    push_sqe(ring, &entry)?;
    Ok(())
}

/// Push an SQE to the submission queue, flushing if full.
///
/// Without SQPOLL: `submit()` synchronously flushes all pending SQEs via
/// `io_uring_enter()`. The SQ is empty after the call, so one retry suffices.
///
/// With SQPOLL: `submit()` wakes the kernel thread (no-op if already running).
/// The kernel thread on its dedicated core processes SQEs asynchronously,
/// freeing SQ slots as it goes. We spin until a slot opens. Each SQE takes
/// ~100-500ns for the kernel to consume, so even a full ring (1024 entries)
/// drains in <1ms.
fn push_sqe(ring: &mut IoUring, entry: &io_uring::squeue::Entry) -> Result<()> {
    if unsafe { ring.submission().push(entry) }.is_ok() {
        return Ok(());
    }
    // SQ full — wake SQPOLL thread (if idle) and spin until it frees a slot.
    // Non-SQPOLL: submit() synchronously flushes, first spin succeeds.
    // SQPOLL: kernel thread on a dedicated core processes SQEs concurrently.
    ring.submit().context("engine: SQ flush")?;
    loop {
        std::hint::spin_loop();
        if unsafe { ring.submission().push(entry) }.is_ok() {
            return Ok(());
        }
    }
}

/// Write to the shutdown eventfd to wake the reader thread.
fn signal_shutdown(fd: RawFd) {
    let val: u64 = 1;
    unsafe {
        libc::write(fd, &val as *const u64 as *const libc::c_void, 8);
    }
}
