//! Simplified BBR congestion control with atomic state for multi-core.
//!
//! Tuned for DATAGRAM-only tunnel traffic (no stream retransmission).
//! Implements loss detection per RFC 9002 §6.1.

use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};

use crate::ack::AtomicBitmap;
use crate::frame::AckFrame;

/// Reorder threshold for loss detection (RFC 9002 §6.1.1).
const REORDER_THRESHOLD: u64 = 3;

/// Size of the sent-packet tracking ring (must be power of 2).
const RING_SIZE: usize = 65536;
const RING_MASK: usize = RING_SIZE - 1;

/// Initial cwnd (RFC 9002 §7.2): min(14720, max(2*MSS, 14720)).
const INITIAL_CWND: u64 = 14720;

/// Minimum cwnd (2 * 1200 = 2400 bytes).
const MIN_CWND: u64 = 2400;

/// BBR gain constants (fixed-point with 8 fractional bits, i.e. ×256).
const BBR_HIGH_GAIN: u64 = 723; // 2.885 * 256 ≈ 723 (STARTUP)
const BBR_DRAIN_GAIN: u64 = 89; // 1/2.885 * 256 ≈ 89
const BBR_STEADY_GAIN: u64 = 256; // 1.0 * 256

/// BBR state phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum BbrPhase {
    Startup = 0,
    Drain = 1,
    ProbeBw = 2,
}

/// Atomic BBR congestion control state.
///
/// All fields are atomic for lock-free multi-core access in Phase 2.
/// Phase 1 runs single-threaded but uses the same atomic API.
pub struct BbrState {
    /// Minimum RTT observed (nanoseconds). Use fetch_min to update.
    pub min_rtt_ns: AtomicU64,
    /// Maximum bandwidth estimate (bytes/sec). Use fetch_max to update.
    pub max_bw: AtomicU64,
    /// Congestion window (bytes).
    pub cwnd: AtomicU64,
    /// Total bytes acknowledged (delivered).
    pub delivered: AtomicU64,
    /// Bytes currently in flight (sent but not yet acked or lost).
    pub inflight: AtomicU64,
    /// Current pacing rate (bytes/sec).
    pub pacing_rate: AtomicU64,
    /// BBR phase (encoded as u64 for atomic ops).
    phase: AtomicU64,
    /// Timestamp of delivered count sample (ns), for BW estimation.
    delivered_time_ns: AtomicU64,
}

impl BbrState {
    pub fn new() -> Self {
        Self {
            min_rtt_ns: AtomicU64::new(u64::MAX),
            max_bw: AtomicU64::new(0),
            cwnd: AtomicU64::new(INITIAL_CWND),
            delivered: AtomicU64::new(0),
            inflight: AtomicU64::new(0),
            pacing_rate: AtomicU64::new(0),
            phase: AtomicU64::new(BbrPhase::Startup as u64),
            delivered_time_ns: AtomicU64::new(0),
        }
    }

    /// Record a sent packet.
    pub fn on_sent(&self, tracker: &SentTracker, pn: u64, size: u16) {
        let idx = (pn as usize) & RING_MASK;
        tracker.sent_sizes[idx].store(size, Ordering::Relaxed);

        // Use coarse monotonic timestamp
        let now_ns = coarse_now_ns();
        tracker.sent_times[idx].store(now_ns, Ordering::Relaxed);
        tracker.sent_bitmap.set(pn);

        self.inflight.fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Process an ACK frame: update RTT, bandwidth, detect losses.
    pub fn on_ack(&self, tracker: &SentTracker, ack: &AckFrame, now_ns: u64) {
        let mut newly_acked_bytes: u64 = 0;
        let mut min_rtt_sample: u64 = u64::MAX;

        // Process each acknowledged range
        for range in &ack.ranges {
            for pn in range.start..range.end {
                // Skip if already acked or never sent
                if tracker.acked_bitmap.test_and_set(pn) {
                    continue;
                }
                if !tracker.sent_bitmap.test(pn) {
                    continue;
                }

                let idx = (pn as usize) & RING_MASK;
                let size = tracker.sent_sizes[idx].load(Ordering::Relaxed) as u64;
                let sent_time = tracker.sent_times[idx].load(Ordering::Relaxed);

                newly_acked_bytes += size;
                self.inflight.fetch_sub(size.min(self.inflight.load(Ordering::Relaxed)), Ordering::Relaxed);

                // RTT sample
                if sent_time > 0 && now_ns > sent_time {
                    let rtt = now_ns - sent_time;
                    min_rtt_sample = min_rtt_sample.min(rtt);
                }
            }
        }

        // Update delivered count
        if newly_acked_bytes > 0 {
            self.delivered.fetch_add(newly_acked_bytes, Ordering::Relaxed);
        }

        // Update min RTT
        if min_rtt_sample < u64::MAX {
            self.min_rtt_ns.fetch_min(min_rtt_sample, Ordering::Relaxed);
        }

        // Bandwidth sample: bytes_delivered / time_interval
        if newly_acked_bytes > 0 {
            let prev_delivered_time = self.delivered_time_ns.swap(now_ns, Ordering::Relaxed);
            if prev_delivered_time > 0 && now_ns > prev_delivered_time {
                let interval_ns = now_ns - prev_delivered_time;
                if interval_ns > 0 {
                    let bw = (newly_acked_bytes * 1_000_000_000) / interval_ns;
                    self.max_bw.fetch_max(bw, Ordering::Relaxed);
                }
            }
        }

        // Loss detection (RFC 9002 §6.1)
        self.detect_losses(tracker, ack.largest_acked);

        // Advance bitmap bases to prevent growing scans.
        // All packets below loss_boundary are either acked or lost.
        if ack.largest_acked >= REORDER_THRESHOLD {
            let new_base = ack.largest_acked - REORDER_THRESHOLD;
            tracker.sent_bitmap.advance_base(new_base);
            tracker.acked_bitmap.advance_base(new_base);
            tracker.lost_bitmap.advance_base(new_base);
        }

        // Phase transitions + cwnd update
        self.update_phase();
    }

    /// Detect lost packets: any sent but unacked packet with
    /// `largest_acked - pn > REORDER_THRESHOLD`.
    fn detect_losses(&self, tracker: &SentTracker, largest_acked: u64) {
        if largest_acked < REORDER_THRESHOLD {
            return;
        }
        let loss_boundary = largest_acked - REORDER_THRESHOLD;
        let base = tracker.sent_bitmap.base();

        // Scan sent packets below the loss boundary
        for pn in base..=loss_boundary {
            if tracker.sent_bitmap.test(pn)
                && !tracker.acked_bitmap.test(pn)
                && !tracker.lost_bitmap.test(pn)
            {
                tracker.lost_bitmap.set(pn);
                let idx = (pn as usize) & RING_MASK;
                let size = tracker.sent_sizes[idx].load(Ordering::Relaxed) as u64;
                self.inflight.fetch_sub(
                    size.min(self.inflight.load(Ordering::Relaxed)),
                    Ordering::Relaxed,
                );
            }
        }
    }

    /// BBR phase transitions and cwnd update.
    fn update_phase(&self) {
        let phase = self.phase.load(Ordering::Relaxed);
        let max_bw = self.max_bw.load(Ordering::Relaxed);
        let min_rtt = self.min_rtt_ns.load(Ordering::Relaxed);
        let inflight = self.inflight.load(Ordering::Relaxed);

        let bdp = if min_rtt < u64::MAX && max_bw > 0 {
            (max_bw * min_rtt) / 1_000_000_000
        } else {
            INITIAL_CWND
        };

        match phase {
            p if p == BbrPhase::Startup as u64 => {
                // STARTUP: cwnd = bdp * high_gain
                let new_cwnd = ((bdp * BBR_HIGH_GAIN) / 256).max(INITIAL_CWND);
                self.cwnd.store(new_cwnd, Ordering::Relaxed);
                self.pacing_rate.store((max_bw * BBR_HIGH_GAIN) / 256, Ordering::Relaxed);

                // Transition to DRAIN when BDP is well-estimated and pipe is full
                if max_bw > 0 && inflight >= bdp {
                    self.phase.store(BbrPhase::Drain as u64, Ordering::Relaxed);
                }
            }
            p if p == BbrPhase::Drain as u64 => {
                // DRAIN: reduce inflight to BDP
                let new_cwnd = ((bdp * BBR_DRAIN_GAIN) / 256).max(MIN_CWND);
                self.cwnd.store(new_cwnd, Ordering::Relaxed);
                self.pacing_rate.store((max_bw * BBR_DRAIN_GAIN) / 256, Ordering::Relaxed);

                if inflight <= bdp {
                    self.phase.store(BbrPhase::ProbeBw as u64, Ordering::Relaxed);
                }
            }
            _ => {
                // PROBE_BW: steady state at 1.0 × BDP
                let new_cwnd = ((bdp * BBR_STEADY_GAIN) / 256).max(MIN_CWND);
                self.cwnd.store(new_cwnd, Ordering::Relaxed);
                self.pacing_rate.store((max_bw * BBR_STEADY_GAIN) / 256, Ordering::Relaxed);
            }
        }
    }

    /// Check if congestion window allows sending.
    pub fn can_send(&self) -> bool {
        self.inflight.load(Ordering::Relaxed) < self.cwnd.load(Ordering::Relaxed)
    }
}

/// Per-packet send metadata ring, indexed by `pn % RING_SIZE`.
pub struct SentTracker {
    pub sent_times: Box<[AtomicU64]>,
    pub sent_sizes: Box<[AtomicU16]>,
    pub sent_bitmap: AtomicBitmap,
    pub acked_bitmap: AtomicBitmap,
    pub lost_bitmap: AtomicBitmap,
}

impl SentTracker {
    pub fn new() -> Self {
        // Allocate directly on heap via Vec to avoid stack overflow
        let mut times = Vec::with_capacity(RING_SIZE);
        times.resize_with(RING_SIZE, || AtomicU64::new(0));
        let mut sizes = Vec::with_capacity(RING_SIZE);
        sizes.resize_with(RING_SIZE, || AtomicU16::new(0));
        Self {
            sent_times: times.into_boxed_slice(),
            sent_sizes: sizes.into_boxed_slice(),
            sent_bitmap: AtomicBitmap::new(),
            acked_bitmap: AtomicBitmap::new(),
            lost_bitmap: AtomicBitmap::new(),
        }
    }
}

/// Coarse monotonic timestamp in nanoseconds.
///
/// Uses std::time::Instant for portability. In the DPDK hot path,
/// this could be replaced with `rte_get_tsc_cycles()` / TSC frequency.
/// Public so callers (engine.rs) can pass a consistent timestamp to `on_ack()`.
pub fn coarse_now_ns() -> u64 {
    use std::time::Instant;
    // Lazy static baseline for converting Instant to nanoseconds
    thread_local! {
        static EPOCH: Instant = Instant::now();
    }
    EPOCH.with(|epoch| epoch.elapsed().as_nanos() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bbr_initial_state() {
        let bbr = BbrState::new();
        assert!(bbr.can_send());
        assert_eq!(bbr.cwnd.load(Ordering::Relaxed), INITIAL_CWND);
        assert_eq!(bbr.inflight.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn bbr_on_sent_tracks_inflight() {
        let bbr = BbrState::new();
        let tracker = SentTracker::new();

        bbr.on_sent(&tracker, 0, 1200);
        assert_eq!(bbr.inflight.load(Ordering::Relaxed), 1200);
        assert!(tracker.sent_bitmap.test(0));

        bbr.on_sent(&tracker, 1, 1200);
        assert_eq!(bbr.inflight.load(Ordering::Relaxed), 2400);
    }

    #[test]
    fn bbr_on_ack_reduces_inflight() {
        let bbr = BbrState::new();
        let tracker = SentTracker::new();

        bbr.on_sent(&tracker, 0, 1200);
        bbr.on_sent(&tracker, 1, 1200);

        let ack = AckFrame {
            largest_acked: 1,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..2],
        };

        let now = coarse_now_ns() + 10_000_000; // +10ms
        bbr.on_ack(&tracker, &ack, now);
        assert_eq!(bbr.inflight.load(Ordering::Relaxed), 0);
        assert_eq!(bbr.delivered.load(Ordering::Relaxed), 2400);
    }

    #[test]
    fn loss_detection() {
        let bbr = BbrState::new();
        let tracker = SentTracker::new();

        // Send packets 0-10
        for pn in 0..=10 {
            bbr.on_sent(&tracker, pn, 1200);
        }

        // ACK only packets 5-10 (0-4 should be detected as lost after threshold)
        let ack = AckFrame {
            largest_acked: 10,
            ack_delay: 0,
            ranges: smallvec::smallvec![5..11],
        };

        let now = coarse_now_ns() + 10_000_000;
        bbr.on_ack(&tracker, &ack, now);

        // Packets 0-7 should be marked lost (10 - 3 = 7)
        for pn in 0..=7 {
            assert!(
                tracker.lost_bitmap.test(pn) || tracker.acked_bitmap.test(pn),
                "pn {pn} should be lost or acked"
            );
        }
    }
}
