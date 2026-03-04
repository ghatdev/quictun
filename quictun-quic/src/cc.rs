//! Tunnel-native congestion control for DATAGRAM-only traffic.
//!
//! Designed for concurrent TX/RX tasks sharing atomic state.
//! Uses `AtomicU16::swap(0)` on the sent-sizes ring as a "consumed" marker.
//!
//! Key design decision: **no loss detection / cwnd reduction**. Inner TCP
//! handles its own congestion control and retransmission. The outer tunnel CC
//! only provides:
//! - Inflight tracking via on_sent/on_ack (with ring-wrap cleanup)
//! - RTT measurement for diagnostics
//! - Basic pacing via can_send() (inflight < cwnd)
//!
//! Aggressive loss detection (even with high thresholds) was found to cause
//! false positives because the tunnel ACK round-trip (TUN→kernel→TUN→encrypt→
//! network→decrypt→ACK) is 2-5ms — much longer than standard QUIC's sub-ms
//! turnaround. False loss detection consumes ring entries before on_ack can
//! process them, preventing RTT sampling and causing cascading failures.
//!
//! RFC 9002 allows custom CC; conforms to RFC 8085 §3.1 via cwnd pacing.

use std::sync::atomic::{AtomicU64, AtomicU16, Ordering};

use crate::frame::AckFrame;

/// Maximum RTT sample accepted (2 seconds in nanoseconds). Samples above this
/// are discarded — they come from delayed ACKs (keepalive piggybacking of
/// sporadic data packets), not from actual link RTT.
const MAX_RTT_SAMPLE_NS: u64 = 2_000_000_000;

/// Size of the sent-packet tracking ring (must be power of 2).
const RING_SIZE: usize = 65536;
const RING_MASK: usize = RING_SIZE - 1;

/// Initial and fixed cwnd. Tunnels are point-to-point links with known
/// capacity. 2MB ≈ BDP at ~10 Gbps with 1ms RTT.
const INITIAL_CWND: u64 = 2 * 1024 * 1024; // 2 MB

/// MSS for congestion avoidance increment calculation.
const MSS: u64 = 1200;

/// Tunnel congestion control state (all atomic for lock-free multi-core access).
///
/// Concurrency model:
/// - `bytes_in_flight`: TX adds (on_sent), RX subtracts (on_ack)
/// - `cwnd`, `ssthresh`: RX only writes
/// - TX reads `bytes_in_flight` and `cwnd` for can_send()
pub struct CongestionControl {
    /// Congestion window (bytes). Fixed at INITIAL_CWND (no reduction).
    cwnd: AtomicU64,
    /// Slow start threshold.
    ssthresh: AtomicU64,
    /// Bytes currently in flight (sent but not acked).
    /// Ring-wrap cleanup in on_sent prevents unbounded drift from lost packets.
    bytes_in_flight: AtomicU64,
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
            ssthresh: AtomicU64::new(INITIAL_CWND),
            bytes_in_flight: AtomicU64::new(0),
            smoothed_rtt_ns: AtomicU64::new(0),
            rttvar_ns: AtomicU64::new(0),
            min_rtt_ns: AtomicU64::new(u64::MAX),
        }
    }

    /// Record a sent data packet (tracked for CC).
    ///
    /// Uses swap() instead of store() to clean up leaked inflight from
    /// overwritten slots on ring wrap. If the previous occupant was a lost
    /// packet (never acked → size still non-zero), subtract its leaked bytes.
    pub fn on_sent(&self, ring: &SentPacketRing, pn: u64, size: u16) {
        let idx = (pn as usize) & RING_MASK;
        let old_size = ring.sent_sizes[idx].swap(size, Ordering::Relaxed) as u64;
        if old_size > 0 {
            self.saturating_sub_inflight(old_size);
        }
        ring.sent_times[idx].store(coarse_now_ns(), Ordering::Relaxed);
        self.bytes_in_flight.fetch_add(size as u64, Ordering::Relaxed);
    }

    /// Register an ACK-only packet (size=0, no inflight tracking).
    ///
    /// Uses swap to clean up leaked inflight from a previous ring occupant,
    /// then stores 0 so on_ack correctly skips this PN.
    pub fn register_ack_only(&self, ring: &SentPacketRing, pn: u64) {
        let idx = (pn as usize) & RING_MASK;
        let old_size = ring.sent_sizes[idx].swap(0, Ordering::Relaxed) as u64;
        if old_size > 0 {
            self.saturating_sub_inflight(old_size);
        }
        ring.sent_times[idx].store(0, Ordering::Relaxed);
    }

    /// Process an ACK frame: consume acked packets, update RTT, detect losses, grow cwnd.
    pub fn on_ack(&self, ring: &SentPacketRing, ack: &AckFrame, now_ns: u64) {
        let mut newly_acked_bytes: u64 = 0;
        let mut min_rtt_sample: u64 = u64::MAX;
        let mut acked_count: u64 = 0;
        let mut max_acked_sent_time: u64 = 0;

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
                if sent_time > 0 {
                    if sent_time > max_acked_sent_time {
                        max_acked_sent_time = sent_time;
                    }
                    if now_ns > sent_time {
                        let rtt = now_ns - sent_time;
                        min_rtt_sample = min_rtt_sample.min(rtt);
                    }
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

        // Loss detection disabled for tunnel use case: inner TCP handles its own
        // CC and retransmission. The outer tunnel should not declare in-transit
        // packets as "lost" — the ACK round-trip through the tunnel path
        // (TUN→kernel→TUN→encrypt→network→decrypt→ACK) takes 2-5ms, which is
        // much longer than standard QUIC's sub-ms ACK turnaround.
        //
        // Inflight tracking is maintained by on_sent (add) and on_ack (subtract).
        // Truly lost packets (never acked) are cleaned up when the ring wraps
        // and on_sent overwrites stale entries — the old inflight bytes remain
        // but are bounded by ring capacity (65536 × 1400 ≈ 90MB >> cwnd).
        //
        // TODO: Add periodic inflight cleanup for long-lived connections.

        // Always grow cwnd (no recovery gating since we don't reduce).
        if newly_acked_bytes > 0 {
            self.grow_cwnd(newly_acked_bytes);
        }
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
        // Discard absurd RTT samples from delayed ACKs (e.g., keepalive
        // piggybacking of sporadic ICMP/data packets).
        if rtt_ns > MAX_RTT_SAMPLE_NS {
            return;
        }

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
        set_times(&ring, 0..2, T);

        let ack = AckFrame {
            largest_acked: 1,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..2],
        };
        cc.on_ack(&ring, &ack, T + 10_000_000);
        assert_eq!(cc.inflight(), 0);
    }

    #[test]
    fn duplicate_ack_no_double_subtract() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.on_sent(&ring, 0, 1200);
        set_times(&ring, 0..1, T);

        let ack = AckFrame {
            largest_acked: 0,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..1],
        };

        let now = T + 10_000_000;
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
        set_times(&ring, 0..1, T);
        set_times(&ring, 2..3, T);

        // ACK all three: PN 1 (ack-only) should be skipped.
        let ack = AckFrame {
            largest_acked: 2,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..3],
        };
        cc.on_ack(&ring, &ack, T + 10_000_000);
        assert_eq!(cc.inflight(), 0);
    }

    /// Large base timestamp for tests. All test timestamps are relative to this
    /// to avoid dependency on the real `coarse_now_ns()` epoch.
    const T: u64 = 1_000_000_000; // 1 second

    /// Helper: set sent_times for a PN range to a given timestamp.
    fn set_times(ring: &SentPacketRing, pn_range: std::ops::Range<u64>, time: u64) {
        for pn in pn_range {
            let idx = (pn as usize) & RING_MASK;
            ring.sent_times[idx].store(time, Ordering::Relaxed);
        }
    }

    #[test]
    fn ring_wrap_cleans_leaked_inflight() {
        // When the ring wraps, on_sent cleans up leaked inflight from
        // overwritten slots (lost packets whose sizes were never acked).
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        // Send a packet at PN 0.
        cc.on_sent(&ring, 0, 1200);
        assert_eq!(cc.inflight(), 1200);

        // Simulate: PN 0 was lost (never acked). Ring wraps after 65536 PNs.
        // New on_sent at PN 65536 overwrites slot 0.
        cc.on_sent(&ring, RING_SIZE as u64, 1400);

        // Old leaked 1200 should be subtracted, new 1400 added.
        // Net: 0 + 1400 = 1400 (not 1200 + 1400 = 2600).
        assert_eq!(cc.inflight(), 1400);
    }

    #[test]
    fn ring_wrap_ack_only_cleans_leaked_inflight() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.on_sent(&ring, 0, 1200);
        assert_eq!(cc.inflight(), 1200);

        // ACK-only at PN 65536 overwrites slot 0 → cleans up leaked 1200.
        cc.register_ack_only(&ring, RING_SIZE as u64);
        assert_eq!(cc.inflight(), 0);
    }

    #[test]
    fn congestion_avoidance_growth() {
        // Tunnel CC starts in congestion avoidance (ssthresh = INITIAL_CWND).
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        let initial_cwnd = cc.cwnd();
        assert_eq!(initial_cwnd, INITIAL_CWND);

        // Use explicit timestamps to avoid coarse_now_ns() returning 0.
        cc.on_sent(&ring, 0, 1200);
        set_times(&ring, 0..1, T);
        let now = T + 10_000_000; // 10ms after send

        let ack = AckFrame {
            largest_acked: 0,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..1],
        };
        cc.on_ack(&ring, &ack, now);

        // Congestion avoidance: increment = MSS * acked / cwnd.
        // 1200 * 1200 / 2097152 ≈ 0 → clamped to min(1).
        let growth = cc.cwnd() - initial_cwnd;
        assert!(growth > 0, "CA should grow: growth={growth}");
    }

    #[test]
    fn slow_start_after_loss() {
        // After a loss event, ssthresh is set to new_cwnd. If cwnd is later
        // reset below ssthresh, slow start would apply. Test this path.
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        // Force slow start: set cwnd below ssthresh.
        cc.cwnd.store(10_000, Ordering::Relaxed);
        cc.ssthresh.store(100_000, Ordering::Relaxed);

        let initial_cwnd = cc.cwnd();

        cc.on_sent(&ring, 0, 1200);
        set_times(&ring, 0..1, T);
        let now = T + 10_000_000;

        let ack = AckFrame {
            largest_acked: 0,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..1],
        };
        cc.on_ack(&ring, &ack, now);

        // Slow start: cwnd += acked_bytes = 1200.
        assert_eq!(cc.cwnd(), initial_cwnd + 1200);
    }

    #[test]
    fn rtt_estimation() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.on_sent(&ring, 0, 1200);
        set_times(&ring, 0..1, T);
        let now = T + 50_000_000; // 50ms after send

        let ack = AckFrame {
            largest_acked: 0,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..1],
        };
        cc.on_ack(&ring, &ack, now);

        // First sample: srtt = rtt ≈ 50ms.
        let srtt = cc.srtt_ns();
        assert!(srtt > 0, "srtt should be set after first ACK");
        assert!(cc.min_rtt_ns() < u64::MAX, "min_rtt should be set");
    }

    #[test]
    fn can_send_blocks_when_window_full() {
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        // Use a smaller cwnd for this test (avoid sending thousands of packets).
        cc.cwnd.store(14720, Ordering::Relaxed);

        let cwnd = cc.cwnd();
        let mut pn = 0u64;
        while cc.inflight() + 1200 <= cwnd {
            cc.on_sent(&ring, pn, 1200);
            pn += 1;
        }

        // Send one more to push over.
        cc.on_sent(&ring, pn, 1200);
        assert!(!cc.can_send(), "should be blocked when inflight >= cwnd");
    }

    #[test]
    fn ring_wrap_no_false_cleanup_after_ack() {
        // If PN 0 is acked (swap→0), on_sent at PN 65536 should NOT subtract
        // anything extra from inflight.
        let cc = CongestionControl::new();
        let ring = SentPacketRing::new();

        cc.on_sent(&ring, 0, 1200);
        set_times(&ring, 0..1, T);

        // ACK PN 0: inflight goes to 0.
        let ack = AckFrame {
            largest_acked: 0,
            ack_delay: 0,
            ranges: smallvec::smallvec![0..1],
        };
        cc.on_ack(&ring, &ack, T + 10_000_000);
        assert_eq!(cc.inflight(), 0);

        // Now send at PN 65536 (same slot). Slot is already 0 from ACK.
        cc.on_sent(&ring, RING_SIZE as u64, 1400);
        assert_eq!(cc.inflight(), 1400); // Only the new packet, no false subtraction.
    }
}
