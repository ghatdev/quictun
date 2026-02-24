use std::os::fd::RawFd;

use anyhow::{Context, Result};
use crossbeam_channel::Sender;
use io_uring::{IoUring, opcode, types};
use tracing::{debug, info, warn};

use crate::bufpool::{self, BUF_SIZE, BufferPool, OP_SHUTDOWN, OP_TUN_READ};

/// Number of TUN read SQEs to keep in flight.
const PREFILL_READS: usize = 32;

/// io_uring ring size for the reader thread.
const RING_SIZE: u32 = 128;

// Registered fd indices for the reader thread.
const FD_TUN: u32 = 0;
const FD_SHUTDOWN: u32 = 1;

/// Run the reader thread: TUN Read → channel → eventfd notify.
///
/// This thread has no QUIC state access. It reads raw packets from the TUN
/// device and sends them to the engine thread via a bounded crossbeam channel.
/// An eventfd signal wakes the engine's io_uring ring to drain the channel.
pub fn run(
    tun_fd: RawFd,
    tx: Sender<Vec<u8>>,
    notify_fd: RawFd,
    shutdown_fd: RawFd,
    sqpoll: bool,
    pool_size: usize,
) -> Result<()> {
    let mut ring = if sqpoll {
        IoUring::builder()
            .setup_sqpoll(1000)
            .build(RING_SIZE)
            .context("reader: failed to create io_uring with SQPOLL")?
    } else {
        IoUring::new(RING_SIZE).context("reader: failed to create io_uring")?
    };

    let mut pool = BufferPool::new(pool_size);

    // Register file descriptors for zero-overhead fd lookups.
    let fds = [tun_fd, shutdown_fd];
    ring.submitter()
        .register_files(&fds)
        .context("reader: failed to register files")?;

    // Register buffer pool for zero-copy I/O.
    pool.register(&ring)?;

    info!(sqpoll, "reader: io_uring initialized (registered fds + buffers)");

    // Prime TUN read SQEs.
    for _ in 0..PREFILL_READS {
        submit_tun_read(&mut ring, &mut pool)?;
    }

    // Submit shutdown eventfd read.
    let mut shutdown_buf = [0u8; 8];
    submit_shutdown_read(&mut ring, &mut shutdown_buf)?;

    info!("reader: entering io_uring event loop");
    let mut stats_tun_reads: u64 = 0;
    let mut stats_sent: u64 = 0;
    let mut stats_dropped: u64 = 0;
    let mut stats_last = std::time::Instant::now();

    loop {
        ring.submit_and_wait(1)
            .context("reader: submit_and_wait failed")?;

        let cqes: Vec<_> = ring.completion().collect();

        let mut sent_any = false;

        for cqe in cqes {
            let user_data = cqe.user_data();
            let result = cqe.result();
            let op = bufpool::decode_op(user_data);
            let idx = bufpool::decode_index(user_data);

            match op {
                OP_TUN_READ => {
                    if result < 0 {
                        let err = std::io::Error::from_raw_os_error(-result);
                        warn!(error = %err, "reader: TUN read error");
                        pool.free(idx);
                        submit_tun_read(&mut ring, &mut pool)?;
                        continue;
                    }
                    stats_tun_reads += 1;
                    let len = result as usize;

                    // Copy packet from buffer pool to Vec<u8> for channel transfer.
                    let packet = pool.slice(idx, len).to_vec();
                    pool.free(idx);

                    // Send to engine via bounded channel. Drop on full (backpressure).
                    match tx.try_send(packet) {
                        Ok(()) => {
                            stats_sent += 1;
                            sent_any = true;
                        }
                        Err(crossbeam_channel::TrySendError::Full(_)) => {
                            stats_dropped += 1;
                        }
                        Err(crossbeam_channel::TrySendError::Disconnected(_)) => {
                            debug!("reader: engine channel disconnected");
                            return Ok(());
                        }
                    }

                    // Resubmit TUN read.
                    submit_tun_read(&mut ring, &mut pool)?;
                }

                OP_SHUTDOWN => {
                    debug!("reader: shutdown signal received");
                    return Ok(());
                }

                _ => {
                    warn!(op, "reader: unknown op in CQE");
                }
            }
        }

        // One eventfd write per CQE batch instead of per-packet.
        if sent_any {
            write_eventfd(notify_fd);
        }

        if stats_last.elapsed() >= std::time::Duration::from_secs(2) {
            info!(
                tun_reads = stats_tun_reads,
                sent = stats_sent,
                dropped = stats_dropped,
                free_bufs = pool.available(),
                "reader: stats"
            );
            stats_tun_reads = 0;
            stats_sent = 0;
            stats_dropped = 0;
            stats_last = std::time::Instant::now();
        }
    }
}

/// Submit a TUN read using registered fd + registered buffer.
fn submit_tun_read(ring: &mut IoUring, pool: &mut BufferPool) -> Result<()> {
    let idx = match pool.alloc() {
        Some(i) => i,
        None => {
            debug!("reader: buffer pool exhausted, skipping TUN read submit");
            return Ok(());
        }
    };
    let entry = opcode::ReadFixed::new(types::Fixed(FD_TUN), pool.ptr(idx), BUF_SIZE as u32, idx as u16)
        .build()
        .user_data(bufpool::encode_user_data(OP_TUN_READ, idx));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("reader: SQ full (tun read)"))?;
    Ok(())
}

/// Submit a shutdown eventfd read using registered fd (non-pool buffer).
fn submit_shutdown_read(ring: &mut IoUring, buf: &mut [u8; 8]) -> Result<()> {
    let entry = opcode::Read::new(types::Fixed(FD_SHUTDOWN), buf.as_mut_ptr(), 8)
        .build()
        .user_data(bufpool::encode_user_data(OP_SHUTDOWN, 0));

    unsafe { ring.submission().push(&entry) }
        .map_err(|_| anyhow::anyhow!("reader: SQ full (shutdown)"))?;
    Ok(())
}

/// Write to the notification eventfd to wake the engine thread.
fn write_eventfd(fd: RawFd) {
    let val: u64 = 1;
    unsafe {
        libc::write(fd, &val as *const u64 as *const libc::c_void, 8);
    }
}
