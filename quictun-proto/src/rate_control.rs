//! Delay-based rate controller for the quictun data plane.
//!
//! Uses one-way delay (OWD) measurement for queuing detection.
//! The peer computes OWD from embedded timestamps and reports queuing delay
//! in the ACK frame's ack_delay field. This avoids ACK timer jitter entirely.
//!
//! Rate-based with batch-level pacing — one comparison per TUN read iteration.

use std::time::{Duration, Instant};

/// Configuration for the delay-based rate controller.
#[derive(Debug, Clone, Copy)]
pub struct RateControlConfig {
    /// Target queuing delay tolerance. The controller backs off when
    /// the peer reports queuing delay exceeding this value.
    pub target_delay: Duration,
    /// Initial sending rate in bytes/sec.
    pub initial_rate: f64,
    /// Minimum sending rate floor in bytes/sec.
    pub min_rate: f64,
}

/// OWD tracking state (receiver side — tracks delay of packets we receive).
///
/// Embedded in `LocalConnectionState`. Computes queuing delay from sender
/// timestamps and reports it in ACK frames.
pub struct OwdTracker {
    /// Windowed minimum OWD (wrapping microseconds, includes clock offset).
    owd_min: i32,
    /// When `owd_min` was last updated (for windowed expiry).
    owd_min_ts: Instant,
    /// Whether we have received at least one OWD sample.
    initialized: bool,
    /// Latest computed queuing delay to report in the next ACK.
    pub queuing_delay_us: u64,
}

/// OWD minimum window — how long before owd_min expires and resets.
const OWD_MIN_WINDOW: Duration = Duration::from_secs(10);

impl Default for OwdTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl OwdTracker {
    pub fn new() -> Self {
        Self {
            owd_min: i32::MAX,
            owd_min_ts: Instant::now(),
            initialized: false,
            queuing_delay_us: 0,
        }
    }

    /// Process an incoming data packet's tx_timestamp.
    /// Computes OWD and updates the queuing delay for the next ACK.
    pub fn on_data_received(&mut self, tx_us: u32) {
        let rx_us = (crate::coarse_now_ns() / 1000) as u32;
        let owd = rx_us.wrapping_sub(tx_us) as i32;

        if !self.initialized || owd < self.owd_min || self.owd_min_ts.elapsed() > OWD_MIN_WINDOW {
            self.owd_min = owd;
            self.owd_min_ts = Instant::now();
            self.initialized = true;
        }

        let queuing = (owd - self.owd_min).max(0) as u64;
        self.queuing_delay_us = queuing;
    }
}

/// Delay-based rate controller state (sender side).
///
/// Embedded in `LocalConnectionState` as `Option<RateController>`.
/// When `None`, the connection operates without CC (zero overhead).
///
/// Receives queuing delay from the peer's ACK frame and adjusts sending rate.
pub struct RateController {
    config: RateControlConfig,

    // ── Rate state ──────────────────────────────────────────────────
    /// Current sending rate in bytes/sec.
    rate: f64,
    /// Whether we've received at least one queuing sample.
    active: bool,

    // ── Interval tracking (batch-level pacing) ──────────────────────
    /// Bytes sent since the current pacing interval started.
    bytes_sent: u64,
    /// Start of the current pacing interval.
    interval_start: Instant,
}

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
        Self {
            rate: config.initial_rate,
            config,
            active: false,
            bytes_sent: 0,
            interval_start: Instant::now(),
        }
    }

    /// Called when an ACK is received with the peer's reported queuing delay.
    ///
    /// `queuing_delay_us` is computed by the peer from OWD measurements
    /// and carried in the ACK frame's ack_delay field.
    pub fn on_ack(&mut self, queuing_delay_us: u64) {
        self.active = true;
        let rate_before = self.rate;

        let queuing = queuing_delay_us as f64 / 1_000_000.0;
        let target = self.config.target_delay.as_secs_f64();

        if queuing < target * 0.2 {
            // Well below target: increase rate.
            self.rate *= INCREASE_FACTOR;
        } else if queuing > target {
            // Above target: proportional decrease, capped.
            let excess = queuing / target;
            let factor = (1.0 - DECREASE_GAIN * excess).max(MAX_DECREASE);
            self.rate *= factor;
        }
        // else: near target, hold.

        self.rate = self.rate.max(self.config.min_rate);

        tracing::debug!(
            queuing_us = queuing_delay_us,
            rate_mbps = (self.rate * 8.0 / 1_000_000.0) as u64,
            rate_before_mbps = (rate_before * 8.0 / 1_000_000.0) as u64,
            "cc: rate adjustment"
        );
    }

    /// Returns `true` if the rate controller allows more data to be sent.
    #[inline]
    pub fn can_send(&self) -> bool {
        if !self.active {
            return true;
        }
        let elapsed = self.interval_start.elapsed();
        if elapsed >= MAX_INTERVAL {
            return true;
        }
        let allowed = self.rate * elapsed.as_secs_f64();
        (self.bytes_sent as f64) < allowed
    }

    /// Record that `bytes` were sent on the wire.
    #[inline]
    pub fn on_bytes_sent(&mut self, bytes: usize) {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> RateControlConfig {
        RateControlConfig {
            target_delay: Duration::from_millis(5),
            initial_rate: 125_000_000.0, // 1 Gbps
            min_rate: 1_250_000.0,       // 10 Mbps
        }
    }

    #[test]
    fn initial_state_allows_send() {
        let rc = RateController::new(test_config());
        assert!(rc.can_send());
        assert!(!rc.active);
    }

    #[test]
    fn can_send_before_active_always_true() {
        let mut rc = RateController::new(test_config());
        rc.on_bytes_sent(1_000_000_000);
        assert!(rc.can_send());
    }

    #[test]
    fn budget_enforcement() {
        let mut rc = RateController::new(test_config());
        rc.on_ack(0); // activate with zero queuing
        rc.bytes_sent = 0;
        rc.interval_start = Instant::now();
        rc.on_bytes_sent(200_000_000);
        assert!(!rc.can_send());
    }

    #[test]
    fn rate_increases_on_low_queuing() {
        let mut rc = RateController::new(test_config());
        let initial_rate = rc.rate;
        rc.on_ack(0); // zero queuing
        assert!(rc.rate > initial_rate);
    }

    #[test]
    fn rate_decreases_on_high_queuing() {
        let mut rc = RateController::new(test_config());
        let initial_rate = rc.rate;
        rc.on_ack(10_000); // 10ms queuing >> 5ms target
        assert!(rc.rate < initial_rate);
    }

    #[test]
    fn rate_holds_near_target() {
        let mut rc = RateController::new(test_config());
        rc.on_ack(0); // activate
        let rate_before = rc.rate;
        rc.on_ack(3000); // 3ms queuing, within 1ms..5ms hold zone
        assert_eq!(rc.rate, rate_before);
    }

    #[test]
    fn rate_never_below_min() {
        let mut rc = RateController::new(test_config());
        rc.rate = rc.config.min_rate;
        rc.on_ack(100_000); // 100ms queuing — massive
        assert_eq!(rc.rate, rc.config.min_rate);
    }

    #[test]
    fn interval_auto_reset_after_idle() {
        let mut rc = RateController::new(test_config());
        rc.on_ack(0); // activate
        rc.on_bytes_sent(200_000_000);
        assert!(!rc.can_send());
        rc.interval_start = Instant::now() - Duration::from_millis(200);
        assert!(rc.can_send());
        rc.on_bytes_sent(100);
        assert_eq!(rc.bytes_sent, 100);
    }

    #[test]
    fn current_rate_bps() {
        let rc = RateController::new(test_config());
        assert!((rc.current_rate_bps() - 1_000_000_000.0).abs() < 1.0);
    }

    #[test]
    fn owd_tracker_basic() {
        let mut tracker = OwdTracker::new();
        assert!(!tracker.initialized);
        assert_eq!(tracker.queuing_delay_us, 0);

        // First sample — becomes the baseline.
        let tx = (crate::coarse_now_ns() / 1000) as u32;
        tracker.on_data_received(tx);
        assert!(tracker.initialized);
        assert_eq!(tracker.queuing_delay_us, 0); // no queuing on first sample

        // Same-time sample — still zero queuing.
        let tx2 = (crate::coarse_now_ns() / 1000) as u32;
        tracker.on_data_received(tx2);
        // Queuing should be very small (just processing time).
        assert!(tracker.queuing_delay_us < 1000); // less than 1ms
    }

    #[test]
    fn owd_tracker_detects_queuing() {
        let mut tracker = OwdTracker::new();

        // Establish baseline: tx was 1000us ago, rx is now.
        let now_us = (crate::coarse_now_ns() / 1000) as u32;
        let tx_baseline = now_us.wrapping_sub(1000); // 1ms ago
        tracker.on_data_received(tx_baseline);
        assert_eq!(tracker.queuing_delay_us, 0);

        // Now a packet that experienced 5ms more delay:
        // tx was 6000us ago (1ms propagation + 5ms queuing), rx is now.
        let tx_delayed = now_us.wrapping_sub(6000);
        tracker.on_data_received(tx_delayed);
        // Should detect ~5000us of queuing.
        assert!(tracker.queuing_delay_us >= 4000);
        assert!(tracker.queuing_delay_us <= 6000);
    }
}
