use std::os::fd::RawFd;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result};
use bytes::BytesMut;
use io_uring::{IoUring, opcode, types};
use tracing::{debug, info, warn};

use crate::bufpool::{
    self, BUF_SIZE, BufferPool, OP_SHUTDOWN, OP_TIMER, OP_TUN_WRITE, OP_UDP_RECV, OP_UDP_SEND,
};
use crate::shared::{self, QuicState};
use crate::timer::Timer;

/// Number of UDP recv SQEs to keep in flight.
const PREFILL_READS: usize = 32;

/// io_uring ring size for the inbound thread.
const RING_SIZE: u32 = 256;

/// Run the inbound thread: UDP Recv → QUIC decrypt → TUN Write.
///
/// Also owns the timerfd for connection timeouts. Shares QuicState via Mutex.
pub fn run(
    tun_fd: RawFd,
    udp_fd: RawFd,
    quic: &Mutex<QuicState>,
    timer: &Timer,
    shutdown_fd: RawFd,
) -> Result<()> {
    let mut ring = IoUring::new(RING_SIZE).context("inbound: failed to create io_uring")?;
    let mut pool = BufferPool::new();

    let timer_fd = timer.raw_fd();
    let mut timer_buf = [0u8; 8];
    let mut response_buf: Vec<u8> = Vec::new();

    // Prime UDP recv SQEs.
    for _ in 0..PREFILL_READS {
        submit_udp_recv(&mut ring, &mut pool, udp_fd)?;
    }

    // Submit timer read SQE.
    submit_timer_read(&mut ring, timer_fd, &mut timer_buf)?;

    // Submit shutdown eventfd read.
    let mut shutdown_buf = [0u8; 8];
    submit_shutdown_read(&mut ring, shutdown_fd, &mut shutdown_buf)?;

    // Arm timer from initial connection state (connector may have a pending timeout).
    {
        let mut state = quic.lock().expect("quic mutex poisoned");
        if let Some(conn) = state.connection.as_mut() {
            if let Some(deadline) = conn.poll_timeout() {
                timer.arm(deadline);
            }
        }
    }

    info!("inbound: entering io_uring event loop");
    let mut stats_udp_recvs: u64 = 0;
    let mut stats_datagrams: u64 = 0;
    let mut stats_transmits: u64 = 0;
    let mut stats_timers: u64 = 0;
    let mut stats_last = std::time::Instant::now();

    loop {
        ring.submit_and_wait(1)
            .context("inbound: submit_and_wait failed")?;

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
                        warn!(error = %err, "inbound: UDP recv error");
                        pool.free(idx);
                        submit_udp_recv(&mut ring, &mut pool, udp_fd)?;
                        continue;
                    }
                    stats_udp_recvs += 1;
                    let len = result as usize;
                    let data = BytesMut::from(pool.slice(idx, len));
                    pool.free(idx);

                    // Lock, handle incoming packet, drive state machine, unlock.
                    let (drive_result, response_transmits) = {
                        let mut state = quic.lock().expect("quic mutex poisoned");
                        let now = Instant::now();
                        let remote_addr = state.remote_addr;

                        let mut resp_tx = Vec::new();
                        if let Some(event) = state.endpoint.handle(
                            now,
                            remote_addr,
                            None,
                            None,
                            data,
                            &mut response_buf,
                        ) {
                            resp_tx =
                                shared::handle_datagram_event(&mut state, event, &mut response_buf);
                        }
                        response_buf.clear();

                        let dr = shared::drive(&mut state);
                        (dr, resp_tx)
                    };
                    stats_datagrams += drive_result.datagrams.len() as u64;
                    stats_transmits += drive_result.transmits.len() as u64;

                    // Resubmit UDP recv.
                    submit_udp_recv(&mut ring, &mut pool, udp_fd)?;

                    // I/O after unlock.
                    if drive_result.connection_lost {
                        info!("inbound: connection lost, signaling shutdown");
                        signal_shutdown(shutdown_fd);
                        return Ok(());
                    }
                    do_io(
                        &mut ring,
                        &mut pool,
                        tun_fd,
                        udp_fd,
                        timer,
                        &drive_result,
                        &response_transmits,
                    )?;
                }

                OP_TIMER => {
                    stats_timers += 1;
                    // Lock, handle timeout, drive, unlock.
                    let drive_result = {
                        let mut state = quic.lock().expect("quic mutex poisoned");
                        let now = Instant::now();
                        if let Some(conn) = state.connection.as_mut() {
                            conn.handle_timeout(now);
                        }
                        shared::drive(&mut state)
                    };
                    stats_transmits += drive_result.transmits.len() as u64;

                    // Resubmit timer read.
                    submit_timer_read(&mut ring, timer_fd, &mut timer_buf)?;

                    // I/O after unlock (retransmits, timer update).
                    if drive_result.connection_lost {
                        info!("inbound: connection lost (timeout), signaling shutdown");
                        signal_shutdown(shutdown_fd);
                        return Ok(());
                    }
                    do_io(
                        &mut ring,
                        &mut pool,
                        tun_fd,
                        udp_fd,
                        timer,
                        &drive_result,
                        &[],
                    )?;
                }

                OP_UDP_SEND => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        debug!(error = %err, "inbound: UDP send error");
                    }
                    pool.free(idx);
                }

                OP_TUN_WRITE => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "inbound: TUN write error");
                    }
                    pool.free(idx);
                }

                OP_SHUTDOWN => {
                    debug!("inbound: shutdown signal received");
                    return Ok(());
                }

                _ => {
                    warn!(op, "inbound: unknown op in CQE");
                }
            }
        }

        if stats_last.elapsed() >= std::time::Duration::from_secs(2) {
            info!(
                udp_recvs = stats_udp_recvs,
                datagrams = stats_datagrams,
                transmits = stats_transmits,
                timers = stats_timers,
                free_bufs = pool.available(),
                "inbound: stats"
            );
            stats_udp_recvs = 0;
            stats_datagrams = 0;
            stats_transmits = 0;
            stats_timers = 0;
            stats_last = std::time::Instant::now();
        }

        ring.submit().context("inbound: submit flush failed")?;
    }
}

/// Perform I/O operations from a DriveResult (after releasing the lock).
fn do_io(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    tun_fd: RawFd,
    udp_fd: RawFd,
    timer: &Timer,
    result: &shared::DriveResult,
    response_transmits: &[(usize, [u8; BUF_SIZE])],
) -> Result<()> {
    // Write decrypted datagrams to TUN.
    for datagram in &result.datagrams {
        submit_tun_write(ring, pool, tun_fd, datagram)?;
    }

    // Send UDP packets (from drive: ACKs, retransmits, etc.).
    for (len, data) in &result.transmits {
        submit_udp_send(ring, pool, udp_fd, &data[..*len])?;
    }

    // Send response transmits (from endpoint.handle: version negotiation, etc.).
    for (len, data) in response_transmits {
        submit_udp_send(ring, pool, udp_fd, &data[..*len])?;
    }

    // Update timer.
    match result.timer_deadline {
        Some(deadline) => timer.arm(deadline),
        None => timer.disarm(),
    }

    Ok(())
}

fn submit_udp_recv(ring: &mut IoUring, pool: &mut BufferPool, udp_fd: RawFd) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            debug!("inbound: buffer pool exhausted, skipping UDP recv submit");
            return Ok(());
        }
    };
    let entry = opcode::Read::new(types::Fd(udp_fd), pool.ptr(idx), BUF_SIZE as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_UDP_RECV, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("inbound: SQ full (udp recv)"))?;
    Ok(())
}

fn submit_udp_send(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    udp_fd: RawFd,
    data: &[u8],
) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("inbound: buffer pool exhausted, dropping UDP send");
            return Ok(());
        }
    };
    let dst = unsafe { std::slice::from_raw_parts_mut(pool.ptr(idx), BUF_SIZE) };
    let len = data.len().min(BUF_SIZE);
    dst[..len].copy_from_slice(&data[..len]);

    let entry = opcode::Write::new(types::Fd(udp_fd), pool.ptr(idx), len as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_UDP_SEND, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("inbound: SQ full (udp send)"))?;
    Ok(())
}

fn submit_tun_write(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    tun_fd: RawFd,
    data: &[u8],
) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            warn!("inbound: buffer pool exhausted, dropping TUN write");
            return Ok(());
        }
    };
    let dst = unsafe { std::slice::from_raw_parts_mut(pool.ptr(idx), BUF_SIZE) };
    let len = data.len().min(BUF_SIZE);
    dst[..len].copy_from_slice(&data[..len]);

    let entry = opcode::Write::new(types::Fd(tun_fd), pool.ptr(idx), len as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_TUN_WRITE, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("inbound: SQ full (tun write)"))?;
    Ok(())
}

fn submit_timer_read(ring: &mut IoUring, timer_fd: RawFd, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fd(timer_fd), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_TIMER, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("inbound: SQ full (timer)"))?;
    Ok(())
}

fn submit_shutdown_read(ring: &mut IoUring, fd: RawFd, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_SHUTDOWN, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("inbound: SQ full (shutdown)"))?;
    Ok(())
}

/// Write to the shutdown eventfd to wake the other thread.
fn signal_shutdown(fd: RawFd) {
    let val: u64 = 1;
    unsafe {
        libc::write(fd, &val as *const u64 as *const libc::c_void, 8);
    }
}
