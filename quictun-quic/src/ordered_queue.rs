//! Ordered send queue for multi-core packet number assignment.
//!
//! Workers encrypt packets and place them into the queue indexed by PN.
//! A single TX drainer (core 0) pulls packets in strict PN order for
//! wire-order compliance (RFC 9000 §17.1).
//!
//! Uses `AtomicPtr<T>` ring — workers store pointers, drainer consumes them.
//! Capacity is a power-of-2 for fast modular indexing.

use std::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

/// Default capacity (must be power of 2).
const DEFAULT_CAPACITY: usize = 4096;

/// Ordered send queue: workers place items by PN, drainer reads in order.
///
/// Generic over `T` — in DPDK mode `T` is `*mut rte_mbuf` (wrapped as a
/// raw pointer stored via AtomicPtr), but for testing we use any `T`.
pub struct OrderedSendQueue<T> {
    /// Ring of atomic pointers. NULL means "slot empty".
    slots: Box<[AtomicPtr<T>]>,
    /// Bitmask for fast modular indexing (capacity - 1).
    mask: u64,
    /// Next PN the drainer expects to read (monotonically increasing).
    drain_head: AtomicU64,
}

impl<T> OrderedSendQueue<T> {
    /// Create a new ordered queue with default capacity (4096 slots).
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }

    /// Create with a specific capacity (must be power of 2).
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(capacity.is_power_of_two(), "capacity must be power of 2");
        let mut slots = Vec::with_capacity(capacity);
        for _ in 0..capacity {
            slots.push(AtomicPtr::new(std::ptr::null_mut()));
        }
        Self {
            slots: slots.into_boxed_slice(),
            mask: (capacity - 1) as u64,
            drain_head: AtomicU64::new(0),
        }
    }

    /// Place an item at the given packet number slot.
    ///
    /// Called by worker threads after encrypting a packet. The PN is assigned
    /// via `pn_counter.fetch_add(1)` before calling this.
    ///
    /// Returns `false` if the slot is already occupied (queue full / PN wraparound).
    #[inline]
    pub fn place(&self, pn: u64, item: *mut T) -> bool {
        let idx = (pn & self.mask) as usize;
        let prev = self.slots[idx].swap(item, Ordering::Release);
        prev.is_null() // true = success (slot was empty)
    }

    /// Drain consecutive items starting from the current head.
    ///
    /// Called by the single TX drainer (core 0). Collects up to `max` items
    /// that are ready in PN order. Returns the number of items drained.
    ///
    /// The drainer passes a callback that receives each `*mut T` in order.
    #[inline]
    pub fn drain<F>(&self, max: usize, mut f: F) -> usize
    where
        F: FnMut(*mut T),
    {
        let head = self.drain_head.load(Ordering::Relaxed);
        let mut count = 0;

        for i in 0..max {
            let pn = head + i as u64;
            let idx = (pn & self.mask) as usize;
            let ptr = self.slots[idx].swap(std::ptr::null_mut(), Ordering::Acquire);
            if ptr.is_null() {
                break;
            }
            f(ptr);
            count += 1;
        }

        if count > 0 {
            self.drain_head.fetch_add(count as u64, Ordering::Relaxed);
        }
        count
    }

    /// Get the current drain head (next PN expected).
    pub fn drain_head(&self) -> u64 {
        self.drain_head.load(Ordering::Relaxed)
    }

    /// Set the initial drain head (call before any place/drain).
    pub fn set_drain_head(&self, pn: u64) {
        self.drain_head.store(pn, Ordering::Relaxed);
    }

    /// Get the queue capacity.
    pub fn capacity(&self) -> usize {
        self.slots.len()
    }
}

// SAFETY: AtomicPtr<T> is Send+Sync, AtomicU64 is Send+Sync.
// The raw pointers stored in slots are managed by the caller.
unsafe impl<T> Send for OrderedSendQueue<T> {}
unsafe impl<T> Sync for OrderedSendQueue<T> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_place_and_drain() {
        let q: OrderedSendQueue<u8> = OrderedSendQueue::with_capacity(16);

        // Place items at PN 0, 1, 2
        let mut items: Vec<Box<u8>> = vec![Box::new(10), Box::new(20), Box::new(30)];
        for (i, item) in items.iter_mut().enumerate() {
            assert!(q.place(i as u64, &mut **item as *mut u8));
        }

        // Drain should yield 3 items in order
        let mut drained = Vec::new();
        let count = q.drain(10, |ptr| {
            drained.push(unsafe { *ptr });
        });
        assert_eq!(count, 3);
        assert_eq!(drained, vec![10, 20, 30]);
        assert_eq!(q.drain_head(), 3);
    }

    #[test]
    fn drain_stops_at_gap() {
        let q: OrderedSendQueue<u8> = OrderedSendQueue::with_capacity(16);

        let mut a = Box::new(1u8);
        let mut c = Box::new(3u8);
        // Place PN 0 and 2 (skip 1)
        assert!(q.place(0, &mut *a as *mut u8));
        assert!(q.place(2, &mut *c as *mut u8));

        // Drain should only get PN 0 (stops at gap at PN 1)
        let mut drained = Vec::new();
        let count = q.drain(10, |ptr| {
            drained.push(unsafe { *ptr });
        });
        assert_eq!(count, 1);
        assert_eq!(drained, vec![1]);
        assert_eq!(q.drain_head(), 1);

        // Now fill the gap
        let mut b = Box::new(2u8);
        assert!(q.place(1, &mut *b as *mut u8));

        // Drain should get PN 1 and 2
        drained.clear();
        let count = q.drain(10, |ptr| {
            drained.push(unsafe { *ptr });
        });
        assert_eq!(count, 2);
        assert_eq!(drained, vec![2, 3]);
        assert_eq!(q.drain_head(), 3);
    }

    #[test]
    fn wraparound() {
        let q: OrderedSendQueue<u8> = OrderedSendQueue::with_capacity(4);

        // Fill all 4 slots
        let mut items: Vec<Box<u8>> = (0..4).map(|i| Box::new(i as u8)).collect();
        for (i, item) in items.iter_mut().enumerate() {
            assert!(q.place(i as u64, &mut **item as *mut u8));
        }

        // Drain all
        let count = q.drain(4, |_| {});
        assert_eq!(count, 4);
        assert_eq!(q.drain_head(), 4);

        // Place at PN 4, 5 (wraps around to slots 0, 1)
        let mut e = Box::new(40u8);
        let mut f = Box::new(50u8);
        assert!(q.place(4, &mut *e as *mut u8));
        assert!(q.place(5, &mut *f as *mut u8));

        let mut drained = Vec::new();
        let count = q.drain(4, |ptr| {
            drained.push(unsafe { *ptr });
        });
        assert_eq!(count, 2);
        assert_eq!(drained, vec![40, 50]);
    }

    #[test]
    fn empty_drain() {
        let q: OrderedSendQueue<u8> = OrderedSendQueue::new();
        let count = q.drain(10, |_| panic!("should not be called"));
        assert_eq!(count, 0);
    }
}
