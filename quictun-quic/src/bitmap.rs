//! Non-atomic sliding-window bitmap for tracking packet numbers.
//!
//! Single-owner variant of [`AtomicBitmap`](crate::ack::AtomicBitmap).
//! Same API, plain `u64` instead of `AtomicU64`. For use in
//! [`LocalConnectionState`](crate::local::LocalConnectionState) (single-task loop).

/// Number of u64 words in the bitmap (65536 PNs = 8KB).
const BITMAP_WORDS: usize = 1024;
/// Total number of packet numbers tracked by the bitmap.
const BITMAP_CAPACITY: u64 = (BITMAP_WORDS * 64) as u64;

/// Sliding-window bitmap for tracking packet numbers (single-owner).
pub struct Bitmap {
    words: Box<[u64]>,
    /// Base packet number (sliding window). PNs below this are implicitly "set".
    base_pn: u64,
}

impl Bitmap {
    pub fn new() -> Self {
        Self {
            words: vec![0u64; BITMAP_WORDS].into_boxed_slice(),
            base_pn: 0,
        }
    }

    /// Set the bit for `pn`. Returns false if out of window.
    pub fn set(&mut self, pn: u64) -> bool {
        if pn < self.base_pn {
            return false;
        }
        let offset = pn - self.base_pn;
        if offset >= BITMAP_CAPACITY {
            return false;
        }
        let word_idx = (offset >> 6) as usize & (BITMAP_WORDS - 1);
        let bit_idx = offset & 63;
        self.words[word_idx] |= 1u64 << bit_idx;
        true
    }

    /// Test if the bit for `pn` is set.
    pub fn test(&self, pn: u64) -> bool {
        if pn < self.base_pn {
            return true; // below window, considered "received"
        }
        let offset = pn - self.base_pn;
        if offset >= BITMAP_CAPACITY {
            return false;
        }
        let word_idx = (offset >> 6) as usize & (BITMAP_WORDS - 1);
        let bit_idx = offset & 63;
        (self.words[word_idx] >> bit_idx) & 1 == 1
    }

    /// Advance the sliding window base. Clears bits that fall below the new base.
    pub fn advance_base(&mut self, new_base: u64) {
        if new_base <= self.base_pn {
            return;
        }
        let advance = new_base - self.base_pn;
        if advance >= BITMAP_CAPACITY {
            for word in self.words.iter_mut() {
                *word = 0;
            }
        } else {
            let old_word_start = (self.base_pn >> 6) as usize & (BITMAP_WORDS - 1);
            let new_word_start = (new_base >> 6) as usize & (BITMAP_WORDS - 1);
            let words_to_clear = ((advance + 63) >> 6) as usize;
            for i in 0..words_to_clear.min(BITMAP_WORDS) {
                let idx = (old_word_start + i) % BITMAP_WORDS;
                if idx != new_word_start || words_to_clear > BITMAP_WORDS {
                    self.words[idx] = 0;
                }
            }
        }
        self.base_pn = new_base;
    }

    /// Get the current base PN.
    pub fn base(&self) -> u64 {
        self.base_pn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bitmap_set_test() {
        let mut bm = Bitmap::new();
        assert!(!bm.test(0));
        bm.set(0);
        assert!(bm.test(0));
        assert!(!bm.test(1));
        bm.set(100);
        assert!(bm.test(100));
    }

    #[test]
    fn bitmap_sliding_window() {
        let mut bm = Bitmap::new();
        bm.set(0);
        bm.set(1);
        bm.set(2);
        assert!(bm.test(0));

        bm.advance_base(2);
        assert!(bm.test(0)); // below base → treated as "set"
        assert!(bm.test(2));

        bm.set(BITMAP_CAPACITY + 1);
        assert!(!bm.test(BITMAP_CAPACITY + 2));
    }

    #[test]
    fn bitmap_large_advance() {
        let mut bm = Bitmap::new();
        for pn in 0..100 {
            bm.set(pn);
        }
        // Advance past entire window.
        bm.advance_base(BITMAP_CAPACITY + 100);
        // Everything below base is "set".
        assert!(bm.test(0));
        // New PNs above base should not be set.
        assert!(!bm.test(BITMAP_CAPACITY + 200));
    }
}
