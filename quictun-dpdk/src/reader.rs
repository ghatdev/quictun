use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crossbeam_channel::Sender;

/// TUN reader thread: blocking read → channel.
///
/// Runs in a dedicated thread.  Reads IP packets from the TUN fd and sends
/// them to the engine via a bounded crossbeam channel.  Packets are dropped
/// when the channel is full (back-pressure).
pub fn run(tun_fd: RawFd, tx: Sender<Vec<u8>>, shutdown: Arc<AtomicBool>) {
    let mut buf = [0u8; 2048];
    let mut pfd = libc::pollfd {
        fd: tun_fd,
        events: libc::POLLIN,
        revents: 0,
    };

    let mut reads: u64 = 0;
    let mut sent: u64 = 0;
    let mut dropped: u64 = 0;
    let mut last_log = std::time::Instant::now();

    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }

        // Poll with 100ms timeout so we can check the shutdown flag.
        let ret = unsafe { libc::poll(&mut pfd, 1, 100) };
        if ret <= 0 {
            continue;
        }

        let n = unsafe { libc::read(tun_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n <= 0 {
            continue;
        }
        reads += 1;

        let pkt = buf[..n as usize].to_vec();
        match tx.try_send(pkt) {
            Ok(()) => sent += 1,
            Err(crossbeam_channel::TrySendError::Full(_)) => dropped += 1,
            Err(crossbeam_channel::TrySendError::Disconnected(_)) => break,
        }

        // Log stats every 2 seconds.
        let now = std::time::Instant::now();
        if now.duration_since(last_log).as_secs() >= 2 {
            tracing::debug!(
                tun_reads = reads,
                sent,
                dropped,
                "dpdk reader stats"
            );
            last_log = now;
        }
    }

    tracing::info!(tun_reads = reads, sent, dropped, "dpdk reader exiting");
}
