//! Delay-based rate controller for the quictun data plane.
//!
//! Reacts to queuing delay only (not loss), avoiding double-CC with inner TCP.
//! Rate-based with batch-level pacing — one comparison per TUN read iteration.

use std::time::{Duration, Instant};

/// Configuration for the delay-based rate controller.
#[derive(Debug, Clone, Copy)]
pub struct RateControlConfig {
    /// Target queuing delay tolerance. The controller backs off when
    /// `smoothed_rtt - min_rtt` exceeds this value.
    pub target_delay: Duration,
    /// Initial sending rate in bytes/sec.
    pub initial_rate: f64,
    /// Minimum sending rate floor in bytes/sec.
    pub min_rate: f64,
    /// Window for the windowed minimum RTT. After this duration without a
    /// new minimum, the stored `min_rtt` expires and resets to the next sample.
    pub rtt_window: Duration,
}

/// Delay-based rate controller state.
///
/// Embedded in `LocalConnectionState` as `Option<RateController>`.
/// When `None`, the connection operates without CC (zero overhead).
pub struct RateController {
    config: RateControlConfig,

    // ── RTT tracking ────────────────────────────────────────────────
    /// Windowed minimum RTT (base RTT estimate).
    min_rtt: Duration,
    /// When `min_rtt` was last updated.
    min_rtt_ts: Instant,
    /// Exponentially weighted moving average of RTT, in seconds.
    smoothed_rtt: f64,
    /// Whether we have received at least one RTT sample.
    rtt_initialized: bool,

    // ── RTT probe ───────────────────────────────────────────────────
    /// Outstanding RTT probe: (packet_number, send_time).
    /// Only one probe is active at a time. Cleared when ACK arrives.
    probe: Option<(u64, Instant)>,

    // ── Rate state ──────────────────────────────────────────────────
    /// Current sending rate in bytes/sec.
    rate: f64,

    // ── Interval tracking (batch-level pacing) ──────────────────────
    /// Bytes sent since the current pacing interval started.
    bytes_sent: u64,
    /// Start of the current pacing interval.
    interval_start: Instant,
}

/// EWMA smoothing factor (RFC 6298 style).
const EWMA_ALPHA: f64 = 0.125;

/// Maximum pacing interval before auto-reset (prevents stale budget after idle).
const MAX_INTERVAL: Duration = Duration::from_millis(100);

/// Rate increase factor per ACK round when below target delay.
const INCREASE_FACTOR: f64 = 1.05;

/// Maximum single-round rate decrease (50%).
const MAX_DECREASE: f64 = 0.5;

/// Proportional decrease gain.
const DECREASE_GAIN: f64 = 0.2;

impl RateController {
    /// Create a new rate controller with the given configuration.
    pub fn new(config: RateControlConfig) -> Self {
        let now = Instant::now();
        Self {
            rate: config.initial_rate,
            config,
            min_rtt: Duration::MAX,
            min_rtt_ts: now,
            smoothed_rtt: 0.0,
            rtt_initialized: false,
            probe: None,
            bytes_sent: 0,
            interval_start: now,
        }
    }

    /// Called after a data packet is encrypted and assigned a PN.
    /// Marks this packet as the RTT probe if no probe is outstanding.
    #[inline]
    pub fn on_packet_sent(&mut self, pn: u64) {
        if self.probe.is_none() {
            self.probe = Some((pn, Instant::now()));
        }
    }

    /// Called when an ACK is received. If the ACK covers the probe packet,
    /// computes an RTT sample and adjusts the sending rate.
    pub fn on_ack(&mut self, largest_acked: u64) {
        let (probe_pn, send_time) = match self.probe {
            Some((pn, ts)) if largest_acked >= pn => (pn, ts),
            _ => return,
        };
        // Clear the probe so the next encrypt_datagram will set a new one.
        self.probe = None;
        let _ = probe_pn; // used only for the guard above

        let rtt = send_time.elapsed();
        self.update_rtt(rtt);
        self.adjust_rate();
    }

    /// Returns `true` if the rate controller allows more data to be sent
    /// in the current pacing interval.
    ///
    /// Before the first RTT sample, always returns `true` (no data to pace with).
    #[inline]
    pub fn can_send(&self) -> bool {
        if !self.rtt_initialized {
            return true;
        }
        let elapsed = self.interval_start.elapsed();
        if elapsed >= MAX_INTERVAL {
            // Stale interval — will be reset on next on_bytes_sent().
            return true;
        }
        let allowed = self.rate * elapsed.as_secs_f64();
        (self.bytes_sent as f64) < allowed
    }

    /// Record that `bytes` were sent on the wire.
    #[inline]
    pub fn on_bytes_sent(&mut self, bytes: usize) {
        // Auto-reset interval if stale (after idle or long poll cycle).
        if self.interval_start.elapsed() >= MAX_INTERVAL {
            self.bytes_sent = 0;
            self.interval_start = Instant::now();
        }
        self.bytes_sent += bytes as u64;
    }

    /// Current sending rate in bits/sec (for logging/stats).
    #[inline]
    pub fn current_rate_bps(&self) -> f64 {
        self.rate * 8.0
    }

    // ── Internal ────────────────────────────────────────────────────

    fn update_rtt(&mut self, rtt: Duration) {
        let rtt_secs = rtt.as_secs_f64();

        // Windowed minimum RTT.
        if rtt < self.min_rtt || self.min_rtt_ts.elapsed() > self.config.rtt_window {
            self.min_rtt = rtt;
            self.min_rtt_ts = Instant::now();
        }

        // EWMA smoothed RTT.
        if !self.rtt_initialized {
            self.smoothed_rtt = rtt_secs;
            self.rtt_initialized = true;
        } else {
            self.smoothed_rtt =
                (1.0 - EWMA_ALPHA) * self.smoothed_rtt + EWMA_ALPHA * rtt_secs;
        }
    }

    fn adjust_rate(&mut self) {
        let min_rtt_secs = self.min_rtt.as_secs_f64();
        if min_rtt_secs <= 0.0 {
            return;
        }
        let queuing_delay = (self.smoothed_rtt - min_rtt_secs).max(0.0);
        let target = self.config.target_delay.as_secs_f64();

        if queuing_delay < target * 0.2 {
            // Well below target: increase rate.
            self.rate *= INCREASE_FACTOR;
        } else if queuing_delay > target {
            // Above target: proportional decrease, capped.
            let excess = queuing_delay / target;
            let factor = (1.0 - DECREASE_GAIN * excess).max(MAX_DECREASE);
            self.rate *= factor;
        }
        // else: near target, hold.

        self.rate = self.rate.max(self.config.min_rate);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RateControlConfig {
        RateControlConfig {
            target_delay: Duration::from_millis(5),
            initial_rate: 125_000_000.0, // 1 Gbps
            min_rate: 1_250_000.0,       // 10 Mbps
            rtt_window: Duration::from_secs(10),
        }
    }

    #[test]
    fn initial_state_allows_send() {
        let rc = RateController::new(test_config());
        assert!(rc.can_send());
        assert!(!rc.rtt_initialized);
    }

    #[test]
    fn can_send_before_rtt_always_true() {
        let mut rc = RateController::new(test_config());
        // Send a lot of bytes — should still allow because no RTT yet.
        rc.on_bytes_sent(1_000_000_000);
        assert!(rc.can_send());
    }

    #[test]
    fn budget_enforcement() {
        let mut rc = RateController::new(test_config());
        // Force RTT initialization with a fake sample.
        rc.update_rtt(Duration::from_millis(1));
        // Reset interval to now.
        rc.bytes_sent = 0;
        rc.interval_start = Instant::now();
        // At 1 Gbps = 125 MB/s, in 1ms we can send ~125 KB.
        // Sending 200 MB should exceed budget immediately.
        rc.on_bytes_sent(200_000_000);
        assert!(!rc.can_send());
    }

    #[test]
    fn rtt_probe_lifecycle() {
        let mut rc = RateController::new(test_config());

        // No probe initially.
        assert!(rc.probe.is_none());

        // First packet sets probe.
        rc.on_packet_sent(0);
        assert!(rc.probe.is_some());
        assert_eq!(rc.probe.unwrap().0, 0);

        // Second packet doesn't overwrite.
        rc.on_packet_sent(1);
        assert_eq!(rc.probe.unwrap().0, 0);

        // ACK for pn 0 computes RTT and clears probe.
        std::thread::sleep(Duration::from_millis(1));
        rc.on_ack(0);
        assert!(rc.probe.is_none());
        assert!(rc.rtt_initialized);

        // Next packet sets a new probe.
        rc.on_packet_sent(2);
        assert_eq!(rc.probe.unwrap().0, 2);
    }

    #[test]
    fn ack_below_probe_is_ignored() {
        let mut rc = RateController::new(test_config());
        rc.on_packet_sent(5);
        rc.on_ack(3); // below probe pn=5
        assert!(rc.probe.is_some()); // not cleared
        assert!(!rc.rtt_initialized);
    }

    #[test]
    fn rate_increases_on_low_delay() {
        let mut rc = RateController::new(test_config());
        let initial_rate = rc.rate;

        // Simulate: min_rtt = 1ms, smoothed_rtt = 1ms (zero queuing).
        rc.update_rtt(Duration::from_millis(1));
        rc.adjust_rate();

        assert!(rc.rate > initial_rate);
    }

    #[test]
    fn rate_decreases_on_high_delay() {
        let mut rc = RateController::new(test_config());

        // Establish min_rtt = 1ms.
        rc.update_rtt(Duration::from_millis(1));
        let rate_after_init = rc.rate;

        // Simulate high queuing: smoothed_rtt jumps to 20ms (19ms queuing >> 5ms target).
        for _ in 0..20 {
            rc.update_rtt(Duration::from_millis(20));
        }
        rc.adjust_rate();

        assert!(rc.rate < rate_after_init);
    }

    #[test]
    fn rate_never_below_min() {
        let mut rc = RateController::new(test_config());

        // Set very low rate, then force decrease.
        rc.rate = rc.config.min_rate;
        rc.update_rtt(Duration::from_millis(1));
        // Simulate massive queuing delay.
        rc.smoothed_rtt = 1.0; // 1 second
        rc.adjust_rate();

        assert_eq!(rc.rate, rc.config.min_rate);
    }

    #[test]
    fn min_rtt_window_expiry() {
        let config = RateControlConfig {
            rtt_window: Duration::from_millis(50), // short window for testing
            ..test_config()
        };
        let mut rc = RateController::new(config);

        // Set min_rtt = 1ms.
        rc.update_rtt(Duration::from_millis(1));
        assert_eq!(rc.min_rtt, Duration::from_millis(1));

        // Wait for window to expire.
        std::thread::sleep(Duration::from_millis(60));

        // New sample at 5ms should replace expired min_rtt.
        rc.update_rtt(Duration::from_millis(5));
        assert_eq!(rc.min_rtt, Duration::from_millis(5));
    }

    #[test]
    fn interval_auto_reset_after_idle() {
        let mut rc = RateController::new(test_config());
        rc.update_rtt(Duration::from_millis(1));

        // Send some bytes, exhaust budget.
        rc.on_bytes_sent(200_000_000);
        assert!(!rc.can_send());

        // Simulate idle period > MAX_INTERVAL.
        rc.interval_start = Instant::now() - Duration::from_millis(200);

        // can_send should return true (stale interval).
        assert!(rc.can_send());

        // on_bytes_sent should reset interval.
        rc.on_bytes_sent(100);
        assert_eq!(rc.bytes_sent, 100); // reset, not accumulated
    }

    #[test]
    fn current_rate_bps() {
        let rc = RateController::new(test_config());
        // 125 MB/s * 8 = 1 Gbps
        assert!((rc.current_rate_bps() - 1_000_000_000.0).abs() < 1.0);
    }

    #[test]
    fn rate_holds_near_target() {
        let mut rc = RateController::new(test_config());

        // min_rtt = 1ms, target = 5ms, so hold zone is 1ms..5ms queuing.
        rc.update_rtt(Duration::from_millis(1));
        let rate_before = rc.rate;

        // Set smoothed_rtt to 4ms (3ms queuing, within 1ms..5ms hold zone).
        rc.smoothed_rtt = 0.004;
        rc.adjust_rate();

        // Rate should not change (hold zone).
        assert_eq!(rc.rate, rate_before);
    }
}
