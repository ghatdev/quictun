//! Lock-free bitmap for tracking received/sent/acked packet numbers,
//! and ACK range generation from the bitmap.

use std::ops::Range;
use std::sync::atomic::{AtomicU64, Ordering};

use smallvec::SmallVec;

/// Number of AtomicU64 words in the bitmap (65536 PNs = 8KB).
const BITMAP_WORDS: usize = 1024;
/// Total number of packet numbers tracked by the bitmap.
const BITMAP_CAPACITY: u64 = (BITMAP_WORDS * 64) as u64;

/// Lock-free sliding-window bitmap for tracking packet numbers.
///
/// Thread-safe: all operations use atomic instructions (CAS for test_and_set,
/// store/load for set/test). Designed for concurrent access from multiple cores.
pub struct AtomicBitmap {
    words: Box<[AtomicU64]>,
    /// Base packet number (sliding window). PNs below this are implicitly "set".
    base_pn: AtomicU64,
}

impl AtomicBitmap {
    pub fn new() -> Self {
        // Allocate directly on heap via Vec to avoid stack overflow
        let mut words = Vec::with_capacity(BITMAP_WORDS);
        words.resize_with(BITMAP_WORDS, || AtomicU64::new(0));
        Self {
            words: words.into_boxed_slice(),
            base_pn: AtomicU64::new(0),
        }
    }

    /// Set the bit for `pn`. Returns false if out of window.
    pub fn set(&self, pn: u64) -> bool {
        let base = self.base_pn.load(Ordering::Relaxed);
        if pn < base {
            return false; // below window
        }
        let offset = pn - base;
        if offset >= BITMAP_CAPACITY {
            return false; // above window
        }
        let word_idx = (offset >> 6) as usize & (BITMAP_WORDS - 1);
        let bit_idx = offset & 63;
        self.words[word_idx].fetch_or(1u64 << bit_idx, Ordering::Relaxed);
        true
    }

    /// Test if the bit for `pn` is set.
    pub fn test(&self, pn: u64) -> bool {
        let base = self.base_pn.load(Ordering::Relaxed);
        if pn < base {
            return true; // below window, considered "received" (old)
        }
        let offset = pn - base;
        if offset >= BITMAP_CAPACITY {
            return false; // above window
        }
        let word_idx = (offset >> 6) as usize & (BITMAP_WORDS - 1);
        let bit_idx = offset & 63;
        (self.words[word_idx].load(Ordering::Relaxed) >> bit_idx) & 1 == 1
    }

    /// Atomically test and set. Returns the previous value.
    pub fn test_and_set(&self, pn: u64) -> bool {
        let base = self.base_pn.load(Ordering::Relaxed);
        if pn < base {
            return true; // below window, was already "set"
        }
        let offset = pn - base;
        if offset >= BITMAP_CAPACITY {
            return false;
        }
        let word_idx = (offset >> 6) as usize & (BITMAP_WORDS - 1);
        let bit_idx = offset & 63;
        let mask = 1u64 << bit_idx;
        let prev = self.words[word_idx].fetch_or(mask, Ordering::Relaxed);
        (prev & mask) != 0
    }

    /// Advance the sliding window base. Clears bits that fall below the new base.
    pub fn advance_base(&self, new_base: u64) {
        let old_base = self.base_pn.load(Ordering::Relaxed);
        if new_base <= old_base {
            return;
        }
        // Clear words that are now below the window.
        let advance = new_base - old_base;
        if advance >= BITMAP_CAPACITY {
            // Full reset
            for word in self.words.iter() {
                word.store(0, Ordering::Relaxed);
            }
        } else {
            // Clear only the words that rotated out
            let old_word_start = (old_base >> 6) as usize & (BITMAP_WORDS - 1);
            let new_word_start = (new_base >> 6) as usize & (BITMAP_WORDS - 1);
            let words_to_clear = ((advance + 63) >> 6) as usize;
            for i in 0..words_to_clear.min(BITMAP_WORDS) {
                let idx = (old_word_start + i) % BITMAP_WORDS;
                if idx != new_word_start || words_to_clear > BITMAP_WORDS {
                    self.words[idx].store(0, Ordering::Relaxed);
                }
            }
        }
        self.base_pn.store(new_base, Ordering::Relaxed);
    }

    /// Get the current base PN.
    pub fn base(&self) -> u64 {
        self.base_pn.load(Ordering::Relaxed)
    }
}

/// Generate ACK ranges from a received bitmap.
///
/// Scans from `largest_pn` downward, emitting contiguous ranges.
/// Returns ranges sorted descending (largest first), each as `start..end` (exclusive end).
pub fn generate_ack_ranges(
    bitmap: &AtomicBitmap,
    largest_pn: u64,
    max_ranges: usize,
) -> SmallVec<[Range<u64>; 8]> {
    let mut ranges: SmallVec<[Range<u64>; 8]> = SmallVec::new();
    let base = bitmap.base();
    if largest_pn < base {
        return ranges;
    }

    let mut pn = largest_pn;
    let mut in_range = false;
    let mut range_end = 0u64;

    loop {
        if bitmap.test(pn) {
            if !in_range {
                range_end = pn + 1;
                in_range = true;
            }
        } else if in_range {
            ranges.push(pn + 1..range_end);
            in_range = false;
            if ranges.len() >= max_ranges {
                break;
            }
        }

        if pn == base {
            if in_range {
                ranges.push(pn..range_end);
            }
            break;
        }
        pn -= 1;
    }

    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_set_test() {
        let bm = AtomicBitmap::new();
        assert!(!bm.test(0));
        bm.set(0);
        assert!(bm.test(0));
        assert!(!bm.test(1));
        bm.set(100);
        assert!(bm.test(100));
    }

    #[test]
    fn bitmap_test_and_set() {
        let bm = AtomicBitmap::new();
        assert!(!bm.test_and_set(42));
        assert!(bm.test_and_set(42)); // already set
        assert!(bm.test(42));
    }

    #[test]
    fn bitmap_sliding_window() {
        let bm = AtomicBitmap::new();
        bm.set(0);
        bm.set(1);
        bm.set(2);
        assert!(bm.test(0));

        // Advance past 0
        bm.advance_base(2);
        assert!(bm.test(0)); // below base → treated as "set"
        assert!(bm.test(2));

        // New PNs in the window
        bm.set(BITMAP_CAPACITY + 1);
        assert!(!bm.test(BITMAP_CAPACITY + 2));
    }

    #[test]
    fn generate_ranges_contiguous() {
        let bm = AtomicBitmap::new();
        for pn in 0..10 {
            bm.set(pn);
        }
        let ranges = generate_ack_ranges(&bm, 9, 8);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 0..10);
    }

    #[test]
    fn generate_ranges_with_gap() {
        let bm = AtomicBitmap::new();
        // Set 0-4 and 7-9, gap at 5,6
        for pn in 0..5 {
            bm.set(pn);
        }
        for pn in 7..10 {
            bm.set(pn);
        }
        let ranges = generate_ack_ranges(&bm, 9, 8);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 7..10);
        assert_eq!(ranges[1], 0..5);
    }

    #[test]
    fn generate_ranges_max_limit() {
        let bm = AtomicBitmap::new();
        // Create many gaps: set even numbers only
        for pn in (0..20).step_by(2) {
            bm.set(pn);
        }
        let ranges = generate_ack_ranges(&bm, 18, 3);
        assert_eq!(ranges.len(), 3);
    }
}
