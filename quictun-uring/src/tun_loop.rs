use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::{Context, Result};
use bytes::Bytes;
use crossbeam_channel::{Receiver, Sender};
use io_uring::{IoUring, opcode, types};
use tracing::{debug, warn};

use crate::bufpool::{self, BUF_SIZE, BufferPool, OP_TUN_READ, OP_TUN_WRITE, OP_WAKE};
use crate::wakeup::EventFd;

/// Number of TUN read SQEs to keep in flight.
const PREFILL_READS: usize = 32;

/// io_uring ring size for the TUN thread.
const RING_SIZE: u32 = 128;

/// Run the TUN I/O thread.
///
/// Reads packets from TUN → sends to QUIC thread via `to_quic`.
/// Receives decrypted packets from QUIC thread via `from_quic` → writes to TUN.
/// The `wake_fd` eventfd is monitored via io_uring to detect channel data.
pub fn run(
    tun_fd: RawFd,
    to_quic: Sender<Bytes>,
    from_quic: Receiver<Bytes>,
    wake_fd: &EventFd,
    quic_wake: &EventFd,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let mut ring = IoUring::new(RING_SIZE).context("tun: failed to create io_uring")?;
    let mut pool = BufferPool::new();

    // Eventfd read buffer (8 bytes for counter).
    let mut wake_buf = [0u8; 8];

    // Prime TUN read SQEs.
    for _ in 0..PREFILL_READS {
        submit_tun_read(&mut ring, &mut pool, tun_fd)?;
    }

    // Submit eventfd read SQE to detect channel data.
    submit_wake_read(&mut ring, wake_fd.raw_fd(), &mut wake_buf)?;

    loop {
        if shutdown.load(Ordering::Relaxed) {
            debug!("tun: shutdown signal received");
            return Ok(());
        }

        ring.submit_and_wait(1)
            .context("tun: submit_and_wait failed")?;

        if shutdown.load(Ordering::Relaxed) {
            debug!("tun: shutdown signal received");
            return Ok(());
        }

        let cqes: Vec<_> = ring.completion().collect();
        let mut sent_to_quic = false;

        for cqe in cqes {
            let user_data = cqe.user_data();
            let result = cqe.result();
            let op = bufpool::decode_op(user_data);
            let idx = bufpool::decode_index(user_data);

            match op {
                OP_TUN_READ => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "tun: read error");
                        pool.free(idx);
                        submit_tun_read(&mut ring, &mut pool, tun_fd)?;
                        continue;
                    }
                    let len = result as usize;
                    let data = Bytes::copy_from_slice(pool.slice(idx, len));
                    pool.free(idx);

                    // Send to QUIC thread. Drop on channel full (correct for IP).
                    if to_quic.try_send(data).is_ok() {
                        sent_to_quic = true;
                    }

                    // Resubmit TUN read.
                    submit_tun_read(&mut ring, &mut pool, tun_fd)?;
                }

                OP_TUN_WRITE => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "tun: write error");
                    }
                    pool.free(idx);
                }

                OP_WAKE => {
                    // Eventfd fired — drain all packets from QUIC thread.
                    while let Ok(data) = from_quic.try_recv() {
                        submit_tun_write(&mut ring, &mut pool, tun_fd, &data)?;
                    }

                    // Resubmit eventfd read.
                    submit_wake_read(&mut ring, wake_fd.raw_fd(), &mut wake_buf)?;
                }

                _ => {
                    warn!(op, "tun: unknown op in CQE");
                }
            }
        }

        // Batch-wake QUIC thread once per iteration if we sent any packets.
        if sent_to_quic {
            quic_wake.wake();
        }

        ring.submit().context("tun: submit flush failed")?;
    }
}

fn submit_tun_read(ring: &mut IoUring, pool: &mut BufferPool, tun_fd: RawFd) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            debug!("tun: buffer pool exhausted, skipping TUN read submit");
            return Ok(());
        }
    };
    let entry = opcode::Read::new(types::Fd(tun_fd), pool.ptr(idx), BUF_SIZE as u32)
        .build()
        .user_data(bufpool::encode_user_data(OP_TUN_READ, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("tun: SQ full (tun read)"))?;
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
            warn!("tun: buffer pool exhausted, dropping TUN write");
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
        .map_err(|_| anyhow::anyhow!("tun: SQ full (tun write)"))?;
    Ok(())
}

fn submit_wake_read(ring: &mut IoUring, wake_fd: RawFd, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fd(wake_fd), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_WAKE, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("tun: SQ full (wake)"))?;
    Ok(())
}
