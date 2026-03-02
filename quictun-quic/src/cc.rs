//! AIMD (NewReno-style) congestion control for DATAGRAM-only tunnel traffic.
//!
//! Designed for concurrent TX/RX tasks sharing atomic state.
//! Uses `AtomicU16::swap(0)` on the sent-sizes ring as a "consumed" marker,
//! eliminating all AtomicBitmaps and their `advance_base()` calls.
//!
//! RFC 9002 allows custom CC algorithms; conforms to RFC 8085 §3.1 (TCP-fair).
//! DATAGRAMs (RFC 9221) require CC but no retransmission.

use std::sync::atomic::{AtomicU64, AtomicU16, Ordering};

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

/// MSS for congestion avoidance increment calculation.
const MSS: u64 = 1200;

/// AIMD congestion control state (all atomic for lock-free multi-core access).
///
/// Concurrency model:
/// - `bytes_in_flight`: TX adds (on_sent), RX subtracts (on_ack/detect_loss)
/// - `cwnd`, `ssthresh`, `recovery_pn`, `loss_scan_base`: RX only writes
/// - TX reads `bytes_in_flight` and `cwnd` for can_send()
pub struct CongestionControl {
    /// Congestion window (bytes).
    cwnd: AtomicU64,
    /// Slow start threshold. Init = u64::MAX (start in slow start).
    ssthresh: AtomicU64,
    /// Bytes currently in flight (sent but not acked/lost).
    bytes_in_flight: AtomicU64,
    /// Recovery dedup: no cwnd reduction while largest_acked <= this.
    recovery_pn: AtomicU64,
    /// Incremental loss scan cursor (avoids rescanning resolved PNs).
    loss_scan_base: AtomicU64,
    /// Smoothed RTT in nanoseconds (RFC 9002 §5.3 EWMA).
    smoothed_rtt_ns: AtomicU64,
    /// RTT variance in nanoseconds.
    rttvar_ns: AtomicU64,
    /// Minimum RTT observed (nanoseconds).
    min_rtt_ns: AtomicU64,
}

impl CongestionControl {
    pub fn new() -> Self {
        Self {
            cwnd: AtomicU64::new(INITIAL_CWND),
            ssthresh: AtomicU64::new(u64::MAX),
            bytes_in_flight: AtomicU64::new(0),
            recovery_pn: AtomicU64::new(0),
            loss_scan_base: AtomicU64::new(0),
            smoothed_rtt_ns: AtomicU64::new(0),
            rttvar_ns: AtomicU64::new(0),
            min_rtt_ns: AtomicU64::new(u64::MAX),
        }
    }

    /// Record a sent data packet (tracked for CC).
    pub fn on_sent(&self, ring: &SentPacketRing, pn: u64, size: u16) {
        let idx = (pn as usize) & RING_MASK;
        ring.sent_sizes[idx].store(size, Ordering::Relaxed);
        ring.sent_times[idx].store(coarse_now_ns(), Ordering::Relaxed);
        self.bytes_in_flight.fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Register an ACK-only packet (size=0, no inflight tracking).
    ///
    /// Clears the ring slot so on_ack correctly skips it (swap returns 0).
    pub fn register_ack_only(&self, ring: &SentPacketRing, pn: u64) {
        let idx = (pn as usize) & RING_MASK;
        ring.sent_sizes[idx].store(0, Ordering::Relaxed);
        ring.sent_times[idx].store(0, Ordering::Relaxed);
    }

    /// Process an ACK frame: consume acked packets, update RTT, detect losses, grow cwnd.
    pub fn on_ack(&self, ring: &SentPacketRing, ack: &AckFrame, now_ns: u64) {
        let mut newly_acked_bytes: u64 = 0;
        let mut min_rtt_sample: u64 = u64::MAX;
        let mut acked_count: u64 = 0;

        // Process each acknowledged range.
        for range in &ack.ranges {
            for pn in range.start..range.end {
                let idx = (pn as usize) & RING_MASK;
                // swap(0) = consume: returns size on first ACK, 0 on duplicate.
                let size = ring.sent_sizes[idx].swap(0, Ordering::Relaxed) as u64;
                if size == 0 {
                    continue; // ACK-only, duplicate ACK, or stale slot
                }

                acked_count += 1;
                newly_acked_bytes += size;

                // Subtract from inflight with saturating semantics.
                self.saturating_sub_inflight(size);

                // RTT sample from sent timestamp.
                let sent_time = ring.sent_times[idx].load(Ordering::Relaxed);
                if sent_time > 0 && now_ns > sent_time {
                    let rtt = now_ns - sent_time;
                    min_rtt_sample = min_rtt_sample.min(rtt);
                }
                // Clear timestamp to prevent stale RTT on ring wrap.
                ring.sent_times[idx].store(0, Ordering::Relaxed);
            }
        }

        tracing::debug!(
            acked_count,
            newly_acked_bytes,
            inflight = self.bytes_in_flight.load(Ordering::Relaxed),
            cwnd = self.cwnd.load(Ordering::Relaxed),
            largest_acked = ack.largest_acked,
            "CC on_ack"
        );

        // Update RTT estimates.
        if min_rtt_sample < u64::MAX {
            self.update_rtt(min_rtt_sample);
        }

        // Loss detection (RFC 9002 §6.1). Returns true if cwnd was reduced.
        let cwnd_reduced = self.detect_loss(ring, ack.largest_acked);

        // Grow cwnd if we acked new data and loss didn't just reduce cwnd.
        // During recovery (largest_acked <= recovery_pn), skip growth to let
        // the pipe drain before re-probing capacity.
        if newly_acked_bytes > 0 && !cwnd_reduced {
            let recovery = self.recovery_pn.load(Ordering::Relaxed);
            if recovery == 0 || ack.largest_acked > recovery {
                self.grow_cwnd(newly_acked_bytes);
            }
        }
    }

    /// Detect lost packets: scan [loss_scan_base, largest_acked - REORDER_THRESHOLD].
    ///
    /// Any ring slot with size > 0 in this range is considered lost.
    /// swap(0) consumes it (no double-counting).
    ///
    /// Returns `true` if cwnd was reduced (new loss event).
    fn detect_loss(&self, ring: &SentPacketRing, largest_acked: u64) -> bool {
        if largest_acked < REORDER_THRESHOLD {
            return false;
        }
        let loss_boundary = largest_acked - REORDER_THRESHOLD;
        let scan_base = self.loss_scan_base.load(Ordering::Relaxed);

        if scan_base > loss_boundary {
            return false;
        }

        let mut total_lost_bytes: u64 = 0;

        for pn in scan_base..=loss_boundary {
            let idx = (pn as usize) & RING_MASK;
            let size = ring.sent_sizes[idx].swap(0, Ordering::Relaxed) as u64;
            if size > 0 {
                total_lost_bytes += size;
                self.saturating_sub_inflight(size);
            }
        }

        // Advance scan cursor past the boundary.
        self.loss_scan_base.store(loss_boundary + 1, Ordering::Relaxed);

        // Halve cwnd on loss (once per loss event via recovery_pn dedup).
        if total_lost_bytes > 0 {
            let recovery = self.recovery_pn.load(Ordering::Relaxed);
            if largest_acked > recovery {
                // Enter recovery: set recovery_pn so subsequent losses in this
                // flight don't cause additional reductions.
                self.recovery_pn.store(largest_acked, Ordering::Relaxed);
                let cwnd = self.cwnd.load(Ordering::Relaxed);
                let new_cwnd = (cwnd / 2).max(MIN_CWND);
                self.cwnd.store(new_cwnd, Ordering::Relaxed);
                self.ssthresh.store(new_cwnd, Ordering::Relaxed);
                tracing::debug!(
                    lost_bytes = total_lost_bytes,
                    old_cwnd = cwnd,
                    new_cwnd,
                    recovery_pn = largest_acked,
                    "CC loss: cwnd halved"
                );
                return true;
            }
        }
        false
    }

    /// Grow cwnd: slow start or congestion avoidance.
    fn grow_cwnd(&self, acked_bytes: u64) {
        let cwnd = self.cwnd.load(Ordering::Relaxed);
        let ssthresh = self.ssthresh.load(Ordering::Relaxed);

        let new_cwnd = if cwnd < ssthresh {
            // Slow start: cwnd += acked_bytes (exponential growth).
            cwnd.saturating_add(acked_bytes)
        } else {
            // Congestion avoidance: cwnd += MSS * acked_bytes / cwnd (linear).
            let increment = (MSS * acked_bytes) / cwnd.max(1);
            cwnd.saturating_add(increment.max(1))
        };

        self.cwnd.store(new_cwnd, Ordering::Relaxed);
    }

    /// Update smoothed RTT per RFC 9002 §5.3.
    fn update_rtt(&self, rtt_ns: u64) {
        self.min_rtt_ns.fetch_min(rtt_ns, Ordering::Relaxed);

        let srtt = self.smoothed_rtt_ns.load(Ordering::Relaxed);
        if srtt == 0 {
            // First sample.
            self.smoothed_rtt_ns.store(rtt_ns, Ordering::Relaxed);
            self.rttvar_ns.store(rtt_ns / 2, Ordering::Relaxed);
        } else {
            // EWMA: rttvar = 3/4 * rttvar + 1/4 * |srtt - rtt|
            let rttvar = self.rttvar_ns.load(Ordering::Relaxed);
            let diff = if srtt > rtt_ns { srtt - rtt_ns } else { rtt_ns - srtt };
            let new_rttvar = (3 * rttvar / 4) + (diff / 4);
            self.rttvar_ns.store(new_rttvar, Ordering::Relaxed);
            // srtt = 7/8 * srtt + 1/8 * rtt
            let new_srtt = (7 * srtt / 8) + (rtt_ns / 8);
            self.smoothed_rtt_ns.store(new_srtt, Ordering::Relaxed);
        }
    }

    /// Subtract from bytes_in_flight with saturation (prevents underflow).
    fn saturating_sub_inflight(&self, size: u64) {
        self.bytes_in_flight
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                Some(current.saturating_sub(size))
            })
            .ok();
    }

    /// Check if congestion window allows sending.
    pub fn can_send(&self) -> bool {
        self.bytes_in_flight.load(Ordering::Relaxed) < self.cwnd.load(Ordering::Relaxed)
    }

    /// Get current bytes in flight.
    pub fn inflight(&self) -> u64 {
        self.bytes_in_flight.load(Ordering::Relaxed)
    }

    /// Get current congestion window.
    pub fn cwnd(&self) -> u64 {
        self.cwnd.load(Ordering::Relaxed)
    }

    /// Get smoothed RTT in nanoseconds.
    pub fn srtt_ns(&self) -> u64 {
        self.smoothed_rtt_ns.load(Ordering::Relaxed)
    }

    /// Get minimum RTT in nanoseconds.
    pub fn min_rtt_ns(&self) -> u64 {
        self.min_rtt_ns.load(Ordering::Relaxed)
    }
}

/// Per-packet send metadata ring, indexed by `pn % RING_SIZE`.
///
/// No bitmaps — swap(0) on sent_sizes serves as the "consumed" marker.
pub struct SentPacketRing {
    pub sent_sizes: Box<[AtomicU16]>,
    pub sent_times: Box<[AtomicU64]>,
}

impl SentPacketRing {
    pub fn new() -> Self {
        let mut sizes = Vec::with_capacity(RING_SIZE);
        sizes.resize_with(RING_SIZE, || AtomicU16::new(0));
        let mut times = Vec::with_capacity(RING_SIZE);
        times.resize_with(RING_SIZE, || AtomicU64::new(0));
        Self {
            sent_sizes: sizes.into_boxed_slice(),
            sent_times: times.into_boxed_slice(),
        }
    }
}

/// Coarse monotonic timestamp in nanoseconds.
///
/// Uses a global (not thread-local) epoch so that timestamps from on_sent()
/// (TX task) and on_ack() (RX task) share the same baseline.
pub fn coarse_now_ns() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static EPOCH: OnceLock<Instant> = OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initial_state() {
        let cc = CongestionControl::new();
        assert!(cc.can_send());
        assert_eq!(cc.cwnd(), INITIAL_CWND);
        assert_eq!(cc.inflight(), 0);
    }

    #[test]
    fn on_sent_tracks_inflight() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.on_sent(&ring, 0, 1200);
        assert_eq!(cc.inflight(), 1200);

        cc.on_sent(&ring, 1, 1200);
        assert_eq!(cc.inflight(), 2400);
    }

    #[test]
    fn on_ack_reduces_inflight() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.on_sent(&ring, 0, 1200);
        cc.on_sent(&ring, 1, 1200);

        let ack = AckFrame {
            largest_acked: 1,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..2],
        };

        let now = coarse_now_ns() + 10_000_000; // +10ms
        cc.on_ack(&ring, &ack, now);
        assert_eq!(cc.inflight(), 0);
    }

    #[test]
    fn duplicate_ack_no_double_subtract() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.on_sent(&ring, 0, 1200);

        let ack = AckFrame {
            largest_acked: 0,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..1],
        };

        let now = coarse_now_ns() + 10_000_000;
        cc.on_ack(&ring, &ack, now);
        assert_eq!(cc.inflight(), 0);

        // Second ACK for same PN — swap returns 0, inflight stays 0.
        cc.on_ack(&ring, &ack, now + 1_000_000);
        assert_eq!(cc.inflight(), 0);
    }

    #[test]
    fn ack_only_packets_skipped() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.on_sent(&ring, 0, 1200);
        cc.register_ack_only(&ring, 1);
        cc.on_sent(&ring, 2, 1200);
        assert_eq!(cc.inflight(), 2400);

        // ACK all three: PN 1 (ack-only) should be skipped.
        let ack = AckFrame {
            largest_acked: 2,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..3],
        };
        cc.on_ack(&ring, &ack, coarse_now_ns() + 10_000_000);
        assert_eq!(cc.inflight(), 0);
    }

    #[test]
    fn loss_detection() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        // Send packets 0-10.
        for pn in 0..=10 {
            cc.on_sent(&ring, pn, 1200);
        }
        let total_inflight = 11 * 1200u64;
        assert_eq!(cc.inflight(), total_inflight);

        // ACK only packets 5-10 (0-4 should be detected as lost via reorder threshold).
        // Loss boundary = 10 - 3 = 7, so PNs 0..=7 are scanned.
        // PNs 5-7 are acked (swap returns 0 in detect_loss), PNs 0-4 are lost.
        let ack = AckFrame {
            largest_acked: 10,
            ack_delay: 0,
            ranges: smallvec::smallvec![5..11],
        };
        cc.on_ack(&ring, &ack, coarse_now_ns() + 10_000_000);

        // Acked: 5,6,7,8,9,10 = 6 packets (7200 bytes)
        // Lost: 0,1,2,3,4 = 5 packets (6000 bytes) — detected because
        //   scan_base=0, loss_boundary=7, and PNs 5-7 were already consumed by on_ack.
        // Remaining inflight: 0
        assert_eq!(cc.inflight(), 0);
    }

    #[test]
    fn loss_halves_cwnd() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        // Artificially set cwnd high so we can observe the halving.
        cc.cwnd.store(100_000, Ordering::Relaxed);

        for pn in 0..=10 {
            cc.on_sent(&ring, pn, 1200);
        }

        // ACK only 5-10, causing loss of 0-4 (below boundary=7).
        let ack = AckFrame {
            largest_acked: 10,
            ack_delay: 0,
            ranges: smallvec::smallvec![5..11],
        };
        cc.on_ack(&ring, &ack, coarse_now_ns() + 10_000_000);

        // cwnd should be halved (100_000 / 2 = 50_000).
        assert_eq!(cc.cwnd(), 50_000);
    }

    #[test]
    fn recovery_dedup_no_double_halve() {
        // Test that swap(0) prevents double-counting: once a PN is consumed
        // by on_ack or detect_loss, it can't cause another cwnd reduction.
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.cwnd.store(100_000, Ordering::Relaxed);

        for pn in 0..=20 {
            cc.on_sent(&ring, pn, 1200);
        }

        // ACK 10-15 (largest=15): detect_loss scans [0..12].
        // PNs 0-9 are lost (10-12 consumed by ACK ranges). cwnd halved.
        let ack1 = AckFrame {
            largest_acked: 15,
            ack_delay: 0,
            ranges: smallvec::smallvec![10..16],
        };
        cc.on_ack(&ring, &ack1, coarse_now_ns() + 10_000_000);
        assert_eq!(cc.cwnd(), 50_000); // halved once

        // ACK 16-20 (largest=20): detect_loss scans [13..17].
        // PNs 13-15 were consumed by first ACK (ranges [10..16]).
        // PNs 16-17 consumed by this ACK. No lost bytes found → no second halving.
        let ack2 = AckFrame {
            largest_acked: 20,
            ack_delay: 0,
            ranges: smallvec::smallvec![16..21],
        };
        cc.on_ack(&ring, &ack2, coarse_now_ns() + 20_000_000);

        // cwnd should NOT be halved again (no lost packets found).
        // It grows slightly from congestion avoidance.
        assert!(cc.cwnd() >= 50_000, "cwnd should not decrease: {}", cc.cwnd());
    }

    #[test]
    fn slow_start_growth() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        // In slow start (cwnd < ssthresh=MAX), cwnd += acked_bytes.
        let initial_cwnd = cc.cwnd();

        cc.on_sent(&ring, 0, 1200);
        let ack = AckFrame {
            largest_acked: 0,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..1],
        };
        cc.on_ack(&ring, &ack, coarse_now_ns() + 10_000_000);

        // cwnd should grow by the full packet size in slow start.
        assert!(cc.cwnd() > initial_cwnd);
    }

    #[test]
    fn congestion_avoidance_growth() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        // Set ssthresh = cwnd to force congestion avoidance.
        cc.ssthresh.store(INITIAL_CWND, Ordering::Relaxed);

        let initial_cwnd = cc.cwnd();

        cc.on_sent(&ring, 0, 1200);
        let ack = AckFrame {
            largest_acked: 0,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..1],
        };
        cc.on_ack(&ring, &ack, coarse_now_ns() + 10_000_000);

        // Congestion avoidance: increment = MSS * acked / cwnd ≈ 1200*1200/14720 ≈ 97.
        // Much less than slow start's 1200.
        let growth = cc.cwnd() - initial_cwnd;
        assert!(growth > 0 && growth < 200, "CA growth={growth}, expected ~97");
    }

    #[test]
    fn rtt_estimation() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.on_sent(&ring, 0, 1200);
        let now = coarse_now_ns() + 50_000_000; // 50ms
        let ack = AckFrame {
            largest_acked: 0,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..1],
        };
        cc.on_ack(&ring, &ack, now);

        // First sample: srtt = rtt.
        let srtt = cc.srtt_ns();
        assert!(srtt > 0, "srtt should be set after first ACK");
        assert!(cc.min_rtt_ns() < u64::MAX, "min_rtt should be set");
    }

    #[test]
    fn can_send_blocks_when_window_full() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        // Fill the cwnd.
        let cwnd = cc.cwnd();
        let mut pn = 0u64;
        while cc.inflight() + 1200 <= cwnd {
            cc.on_sent(&ring, pn, 1200);
            pn += 1;
        }

        // Should be blocked (or very close to blocked).
        // Send one more to push over.
        cc.on_sent(&ring, pn, 1200);
        assert!(!cc.can_send(), "should be blocked when inflight >= cwnd");
    }

    #[test]
    fn min_cwnd_floor() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        // Set cwnd to minimum, then trigger loss.
        cc.cwnd.store(MIN_CWND, Ordering::Relaxed);

        for pn in 0..=10 {
            cc.on_sent(&ring, pn, 1200);
        }

        let ack = AckFrame {
            largest_acked: 10,
            ack_delay: 0,
            ranges: smallvec::smallvec![5..11],
        };
        cc.on_ack(&ring, &ack, coarse_now_ns() + 10_000_000);

        // cwnd should not go below MIN_CWND.
        assert!(cc.cwnd() >= MIN_CWND);
    }
}
