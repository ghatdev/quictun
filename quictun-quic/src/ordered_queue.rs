//! Ordered send queue for multi-core packet number assignment (Phase 2).
//!
//! Phase 1: unused — single-threaded send uses atomic fetch_add directly.
//! Phase 2: AtomicPtr ring ensures strict wire-order PN compliance (RFC 9000 §17.1).

/// Placeholder for Phase 2 multi-core ordered send queue.
pub struct OrderedSendQueue {
    _private: (),
}

impl OrderedSendQueue {
    pub fn new() -> Self {
        Self { _private: () }
    }
}
