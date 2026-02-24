use std::os::fd::RawFd;
use std::sync::Mutex;

use anyhow::{Context, Result};
use bytes::Bytes;
use io_uring::{IoUring, opcode, types};
use tracing::{debug, info, warn};

use crate::bufpool::{self, BUF_SIZE, BufferPool, OP_SHUTDOWN, OP_TUN_READ, OP_UDP_SEND};
use crate::shared::{self, QuicState};
use crate::timer::Timer;

/// Number of TUN read SQEs to keep in flight.
const PREFILL_READS: usize = 32;

/// io_uring ring size for the outbound thread.
const RING_SIZE: u32 = 128;

/// Run the outbound thread: TUN Read → QUIC encrypt → UDP Write.
///
/// Owns its own io_uring ring and buffer pool. Shares QuicState via Mutex.
pub fn run(
    tun_fd: RawFd,
    udp_fd: RawFd,
    quic: &Mutex<QuicState>,
    timer: &Timer,
    shutdown_fd: RawFd,
) -> Result<()> {
    let mut ring = IoUring::new(RING_SIZE).context("outbound: failed to create io_uring")?;
    let mut pool = BufferPool::new();

    // Prime TUN read SQEs.
    for _ in 0..PREFILL_READS {
        submit_tun_read(&mut ring, &mut pool, tun_fd)?;
    }

    // Submit shutdown eventfd read.
    let mut shutdown_buf = [0u8; 8];
    submit_shutdown_read(&mut ring, shutdown_fd, &mut shutdown_buf)?;

    // Drain initial handshake transmits (connector ClientHello / listener ServerHello).
    {
        let mut state = quic.lock().expect("quic mutex poisoned");
        if state.connection.is_some() {
            let result = shared::drive(&mut state);
            drop(state);
            do_io(&mut ring, &mut pool, udp_fd, timer, &result)?;
        }
    }

    info!("outbound: entering io_uring event loop");
    loop {
        ring.submit_and_wait(1)
            .context("outbound: submit_and_wait failed")?;

        let cqes: Vec<_> = ring.completion().collect();

        for cqe in cqes {
            let user_data = cqe.user_data();
            let result = cqe.result();
            let op = bufpool::decode_op(user_data);
            let idx = bufpool::decode_index(user_data);

            match op {
                OP_TUN_READ => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "outbound: TUN read error");
                        pool.free(idx);
                        submit_tun_read(&mut ring, &mut pool, tun_fd)?;
                        continue;
                    }
                    let len = result as usize;
                    let packet = Bytes::copy_from_slice(pool.slice(idx, len));
                    pool.free(idx);

                    // Lock, send datagram, drive state machine, unlock.
                    let drive_result = {
                        let mut state = quic.lock().expect("quic mutex poisoned");
                        if let Some(conn) = state.connection.as_mut() {
                            let max = conn.datagrams().max_size().unwrap_or(1200);
                            if packet.len() > max {
                                debug!(
                                    packet_size = packet.len(),
                                    max, "outbound: dropping oversized TUN packet"
                                );
                            } else if let Err(e) = conn.datagrams().send(packet, true) {
                                debug!(error = ?e, "outbound: datagrams.send failed");
                            }
                        }
                        shared::drive(&mut state)
                    };

                    // Resubmit TUN read.
                    submit_tun_read(&mut ring, &mut pool, tun_fd)?;

                    // I/O after unlock.
                    if drive_result.connection_lost {
                        info!("outbound: connection lost, signaling shutdown");
                        signal_shutdown(shutdown_fd);
                        return Ok(());
                    }
                    do_io(&mut ring, &mut pool, udp_fd, timer, &drive_result)?;
                }

                OP_UDP_SEND => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        debug!(error = %err, "outbound: UDP send error");
                    }
                    pool.free(idx);
                }

                OP_SHUTDOWN => {
                    debug!("outbound: shutdown signal received");
                    return Ok(());
                }

                _ => {
                    warn!(op, "outbound: unknown op in CQE");
                }
            }
        }

        ring.submit().context("outbound: submit flush failed")?;
    }
}

/// Perform I/O operations from a DriveResult (after releasing the lock).
fn do_io(
    ring: &mut IoUring,
    pool: &mut BufferPool,
    udp_fd: RawFd,
    timer: &Timer,
    result: &shared::DriveResult,
) -> Result<()> {
    // Send UDP packets.
    for (len, data) in &result.transmits {
        submit_udp_send(ring, pool, udp_fd, &data[..*len])?;
    }

    // Update timer.
    match result.timer_deadline {
        Some(deadline) => timer.arm(deadline),
        None => {}
    }

    Ok(())
}

fn submit_tun_read(ring: &mut IoUring, pool: &mut BufferPool, tun_fd: RawFd) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            debug!("outbound: buffer pool exhausted, skipping TUN read submit");
            return Ok(());
        }
    };
    let entry = opcode::Read::new(types::Fd(tun_fd), pool.ptr(idx), BUF_SIZE as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_TUN_READ, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("outbound: SQ full (tun read)"))?;
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
            warn!("outbound: buffer pool exhausted, dropping UDP send");
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
        .map_err(|_| anyhow::anyhow!("outbound: SQ full (udp send)"))?;
    Ok(())
}

fn submit_shutdown_read(ring: &mut IoUring, fd: RawFd, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fd(fd), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_SHUTDOWN, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("outbound: SQ full (shutdown)"))?;
    Ok(())
}

/// Write to the shutdown eventfd to wake the other thread.
fn signal_shutdown(fd: RawFd) {
    let val: u64 = 1;
    unsafe {
        libc::write(fd, &val as *const u64 as *const libc::c_void, 8);
    }
}
