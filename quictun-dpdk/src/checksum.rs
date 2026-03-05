//! Optimized Internet checksum computation with architecture-tiered dispatch.
//!
//! Dispatch order:
//! 1. x86_64 + AVX2 (runtime detect) → 32 bytes/iteration
//! 2. aarch64 NEON (always available) → 16 bytes/iteration
//! 3. Scalar fast path (all arches)   → 8 bytes/iteration

use std::net::Ipv4Addr;

// ── Public API ──────────────────────────────────────────────────────

/// Compute the RFC 1071 Internet checksum over `data`.
#[inline]
pub fn internet_checksum(data: &[u8]) -> u16 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 detected at runtime.
            return unsafe { checksum_avx2(data) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON is always available on aarch64.
        return unsafe { checksum_neon(data) };
    }
    #[allow(unreachable_code)]
    checksum_scalar_fast(data)
}

/// Compute the full UDP checksum (pseudo-header + UDP segment).
///
/// `udp_segment` must include the UDP header (8 bytes) + payload, with the
/// checksum field set to 0x0000. Returns 0xFFFF if the computed value is zero
/// (RFC 768: zero means "no checksum").
pub fn udp_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    // Accumulate the 12-byte pseudo-header inline (no separate allocation).
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    let mut sum: u64 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u64;
    sum += u16::from_be_bytes([src[2], src[3]]) as u64;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u64;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u64;
    sum += 17u64; // protocol = UDP
    sum += udp_segment.len() as u64;

    // Add the UDP segment checksum (using the fast path).
    let segment_sum = internet_checksum_partial(udp_segment);
    sum += segment_sum;

    // Fold 64 → 16 and complement.
    let cksum = fold_and_complement(sum);
    if cksum == 0 { 0xFFFF } else { cksum }
}

/// Compute only the pseudo-header partial sum for HW offload mode.
///
/// The NIC will add the UDP segment checksum on top of this seed value.
/// Returns the one's complement of the pseudo-header sum (ready to write
/// into the UDP checksum field for the NIC to finish).
pub fn udp_pseudo_header_checksum(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_len: u16) -> u16 {
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    let mut sum: u64 = 0;
    sum += u16::from_be_bytes([src[0], src[1]]) as u64;
    sum += u16::from_be_bytes([src[2], src[3]]) as u64;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u64;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u64;
    sum += 17u64; // protocol = UDP
    sum += udp_len as u64;

    fold_and_complement(sum)
}

// ── Internal helpers ────────────────────────────────────────────────

/// Partial checksum: returns the raw (unfolded) sum as u64.
/// Caller must fold and complement.
fn internet_checksum_partial(data: &[u8]) -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        if is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 detected at runtime.
            return unsafe { checksum_avx2_partial(data) };
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        // SAFETY: NEON always available.
        return unsafe { checksum_neon_partial(data) };
    }
    #[allow(unreachable_code)]
    checksum_scalar_fast_partial(data)
}

/// Fold a u64 accumulator down to u16 and one's-complement.
#[inline(always)]
fn fold_and_complement(mut sum: u64) -> u16 {
    // 64 → 32
    sum = (sum & 0xffff_ffff) + (sum >> 32);
    // 32 → 16 (may need two folds if carry)
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    !(sum as u16)
}

// ── Scalar fast path (8 bytes/iteration via u64 accumulator) ────────

/// Scalar fast partial sum (returns raw u64 accumulator).
fn checksum_scalar_fast_partial(data: &[u8]) -> u64 {
    let mut sum: u64 = 0;

    // Process aligned u64 chunks (8 bytes = 4 u16 words per iteration).
    // SAFETY: align_to is safe; prefix/suffix are the unaligned remainders.
    let (prefix, aligned, suffix) = unsafe { data.align_to::<u64>() };

    // Handle unaligned prefix bytes.
    for chunk in prefix.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u64;
    }

    // Main loop: accumulate 8 bytes at a time.
    // We interpret each u64 as four big-endian u16 words.
    for &qword in aligned {
        let be = qword.to_be();
        sum += (be >> 48) & 0xffff;
        sum += (be >> 32) & 0xffff;
        sum += (be >> 16) & 0xffff;
        sum += be & 0xffff;
    }

    // Handle unaligned suffix bytes.
    for chunk in suffix.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u64;
    }

    sum
}

/// Scalar fast path: full checksum with fold + complement.
fn checksum_scalar_fast(data: &[u8]) -> u16 {
    fold_and_complement(checksum_scalar_fast_partial(data))
}

// ── x86_64 AVX2 (32 bytes/iteration) ───────────────────────────────

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn checksum_avx2_partial(data: &[u8]) -> u64 {
    #[cfg(target_arch = "x86_64")]
    use std::arch::x86_64::*;

    let mut sum: u64 = 0;
    let len = data.len();
    let mut offset = 0;
    let ptr = data.as_ptr();

    // Accumulate in 4 × u64 lanes to avoid overflow.
    // Each iteration: load 32 bytes, zero-extend u16→u32, horizontal pair-add to u64.
    let mut acc = _mm256_setzero_si256();

    // We can safely do ~2048 iterations before u32 lanes overflow (65535 * 2048 < u32::MAX).
    // For simplicity, fold every 256 iterations.
    let mut iters_since_fold: usize = 0;

    while offset + 32 <= len {
        let chunk = _mm256_loadu_si256(ptr.add(offset) as *const __m256i);

        // Zero-extend low 16 u8→u16 then u16→u32 by interleaving with zero.
        // Actually, we want to sum as u16 words in network byte order.
        // Approach: unpack bytes to u16, then accumulate in u32 lanes.

        // Split 32 bytes into two 128-bit halves.
        let lo128 = _mm256_castsi256_si128(chunk);
        let hi128 = _mm256_extracti128_si256(chunk, 1);

        // Byte-swap within each 16-bit word: _mm_shuffle_epi8 for BE→LE u16.
        let swap_mask = _mm_set_epi8(14, 15, 12, 13, 10, 11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1);
        let lo_swapped = _mm_shuffle_epi8(lo128, swap_mask);
        let hi_swapped = _mm_shuffle_epi8(hi128, swap_mask);

        // Unsigned u16 → u32 widening add (NOT _mm_madd_epi16 which treats as signed i16).
        let zero128 = _mm_setzero_si128();
        let lo_lo = _mm_unpacklo_epi16(lo_swapped, zero128); // words 0-3 zero-extended to u32
        let lo_hi = _mm_unpackhi_epi16(lo_swapped, zero128); // words 4-7 zero-extended to u32
        let lo_sum = _mm_add_epi32(lo_lo, lo_hi); // 4 × u32 partial sums
        let lo_u64 = _mm256_cvtepu32_epi64(lo_sum);

        let hi_lo = _mm_unpacklo_epi16(hi_swapped, zero128);
        let hi_hi = _mm_unpackhi_epi16(hi_swapped, zero128);
        let hi_sum = _mm_add_epi32(hi_lo, hi_hi);
        let hi_u64 = _mm256_cvtepu32_epi64(hi_sum);

        acc = _mm256_add_epi64(acc, lo_u64);
        acc = _mm256_add_epi64(acc, hi_u64);

        offset += 32;
        iters_since_fold += 1;

        if iters_since_fold >= 256 {
            // Horizontal reduce acc into sum.
            let mut tmp = [0u64; 4];
            _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, acc);
            sum += tmp[0] + tmp[1] + tmp[2] + tmp[3];
            acc = _mm256_setzero_si256();
            iters_since_fold = 0;
        }
    }

    // Final horizontal reduce.
    {
        let mut tmp = [0u64; 4];
        _mm256_storeu_si256(tmp.as_mut_ptr() as *mut __m256i, acc);
        sum += tmp[0] + tmp[1] + tmp[2] + tmp[3];
    }

    // Handle remaining bytes with scalar.
    let tail = &data[offset..];
    for chunk in tail.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u64;
    }

    sum
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn checksum_avx2(data: &[u8]) -> u16 {
    fold_and_complement(checksum_avx2_partial(data))
}

// ── aarch64 NEON (16 bytes/iteration) ──────────────────────────────

#[cfg(target_arch = "aarch64")]
unsafe fn checksum_neon_partial(data: &[u8]) -> u64 {
    use std::arch::aarch64::*;

    let mut sum: u64 = 0;
    let len = data.len();
    let mut offset = 0;
    let ptr = data.as_ptr();

    // Accumulate in u64x2 to prevent overflow.
    let mut acc = unsafe { vdupq_n_u64(0) };

    while offset + 16 <= len {
        // Load 16 bytes as 8 big-endian u16 words.
        let chunk = unsafe { vld1q_u8(ptr.add(offset)) };

        // Byte-swap within u16 lanes: big-endian → native (little-endian).
        let swapped = unsafe { vrev16q_u8(chunk) };

        // Reinterpret as u16 vector, then widen: u16→u32→u64.
        let u16s = unsafe { vreinterpretq_u16_u8(swapped) }; // 8 × u16 (native endian)
        let u32s = unsafe { vpaddlq_u16(u16s) }; // 4 × u32 (pairwise sum of u16→u32)
        let u64s = unsafe { vpaddlq_u32(u32s) }; // 2 × u64

        acc = unsafe { vaddq_u64(acc, u64s) };

        offset += 16;
    }

    // Horizontal reduce: 2 × u64 → scalar.
    sum += unsafe { vgetq_lane_u64(acc, 0) + vgetq_lane_u64(acc, 1) };

    // Handle remaining bytes with scalar.
    let tail = &data[offset..];
    for chunk in tail.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u64;
    }

    sum
}

#[cfg(target_arch = "aarch64")]
unsafe fn checksum_neon(data: &[u8]) -> u16 {
    fold_and_complement(unsafe { checksum_neon_partial(data) })
}

// ── Naive reference implementation (for tests) ─────────────────────

#[cfg(test)]
fn checksum_naive(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
fn udp_checksum_naive(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, udp_segment: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    sum += u16::from_be_bytes([src[0], src[1]]) as u32;
    sum += u16::from_be_bytes([src[2], src[3]]) as u32;
    sum += u16::from_be_bytes([dst[0], dst[1]]) as u32;
    sum += u16::from_be_bytes([dst[2], dst[3]]) as u32;
    sum += 17u32;
    sum += udp_segment.len() as u32;
    for chunk in udp_segment.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from_be_bytes([chunk[0], 0])
        };
        sum += word as u32;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let cksum = !(sum as u16);
    if cksum == 0 { 0xFFFF } else { cksum }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scalar_vs_naive() {
        // Test various sizes including edge cases.
        for size in [
            0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 33, 63, 64, 100, 1400, 1500,
        ] {
            let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let naive = checksum_naive(&data);
            let scalar = checksum_scalar_fast(&data);
            assert_eq!(
                naive, scalar,
                "scalar mismatch at size {size}: naive=0x{naive:04x}, scalar=0x{scalar:04x}"
            );
        }
    }

    #[test]
    fn test_dispatch_vs_naive() {
        // Tests the public dispatch function against naive.
        for size in [0, 1, 3, 7, 15, 31, 33, 100, 1400] {
            let data: Vec<u8> = (0..size).map(|i| (i * 7 % 256) as u8).collect();
            let naive = checksum_naive(&data);
            let dispatched = internet_checksum(&data);
            assert_eq!(
                naive, dispatched,
                "dispatch mismatch at size {size}: naive=0x{naive:04x}, dispatched=0x{dispatched:04x}"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_avx2_vs_scalar() {
        if !is_x86_feature_detected!("avx2") {
            return; // Skip on machines without AVX2
        }
        for size in [0, 1, 3, 7, 15, 31, 32, 33, 63, 64, 100, 1400, 1500] {
            let data: Vec<u8> = (0..size).map(|i| (i * 13 % 256) as u8).collect();
            let scalar = checksum_scalar_fast(&data);
            let avx2 = unsafe { checksum_avx2(&data) };
            assert_eq!(
                scalar, avx2,
                "AVX2 mismatch at size {size}: scalar=0x{scalar:04x}, avx2=0x{avx2:04x}"
            );
        }
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_neon_vs_scalar() {
        for size in [0, 1, 3, 7, 15, 16, 31, 32, 33, 63, 64, 100, 1400, 1500] {
            let data: Vec<u8> = (0..size).map(|i| (i * 13 % 256) as u8).collect();
            let scalar = checksum_scalar_fast(&data);
            let neon = unsafe { checksum_neon(&data) };
            assert_eq!(
                scalar, neon,
                "NEON mismatch at size {size}: scalar=0x{scalar:04x}, neon=0x{neon:04x}"
            );
        }
    }

    #[test]
    fn test_odd_lengths() {
        for size in [0, 1, 3, 7, 15, 31, 33] {
            let data: Vec<u8> = (0..size).map(|i| (i + 0x42) as u8).collect();
            let naive = checksum_naive(&data);
            let fast = internet_checksum(&data);
            assert_eq!(naive, fast, "odd-length mismatch at size {size}");
        }
    }

    #[test]
    fn test_udp_checksum() {
        let src_ip = Ipv4Addr::new(192, 168, 100, 10);
        let dst_ip = Ipv4Addr::new(192, 168, 100, 11);

        // Build a fake UDP segment: header (8 bytes) + payload.
        let payload = b"hello checksum test";
        let udp_len = 8 + payload.len();
        let mut segment = vec![0u8; udp_len];
        // src_port, dst_port, length, checksum=0
        segment[0..2].copy_from_slice(&4433u16.to_be_bytes());
        segment[2..4].copy_from_slice(&5000u16.to_be_bytes());
        segment[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        segment[6..8].copy_from_slice(&[0x00, 0x00]);
        segment[8..].copy_from_slice(payload);

        let naive = udp_checksum_naive(src_ip, dst_ip, &segment);
        let fast = udp_checksum(src_ip, dst_ip, &segment);
        assert_eq!(
            naive, fast,
            "UDP checksum mismatch: naive=0x{naive:04x}, fast=0x{fast:04x}"
        );
        assert_ne!(fast, 0, "UDP checksum should be non-zero");
    }

    #[test]
    fn test_pseudo_header_checksum() {
        let src_ip = Ipv4Addr::new(10, 0, 0, 1);
        let dst_ip = Ipv4Addr::new(10, 0, 0, 2);
        let udp_len = 28u16;

        let phdr_cksum = udp_pseudo_header_checksum(src_ip, dst_ip, udp_len);
        // Just verify it's non-zero and deterministic.
        assert_ne!(phdr_cksum, 0);
        assert_eq!(
            phdr_cksum,
            udp_pseudo_header_checksum(src_ip, dst_ip, udp_len)
        );
    }

    #[test]
    fn test_ipv4_header_checksum() {
        // Build a minimal IPv4 header and verify checksum validates.
        let mut hdr = [0u8; 20];
        hdr[0] = 0x45;
        hdr[8] = 64; // TTL
        hdr[9] = 17; // UDP
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        hdr[12..16].copy_from_slice(&src.octets());
        hdr[16..20].copy_from_slice(&dst.octets());
        let total_len: u16 = 20 + 8 + 10;
        hdr[2..4].copy_from_slice(&total_len.to_be_bytes());

        let cksum = internet_checksum(&hdr);
        hdr[10..12].copy_from_slice(&cksum.to_be_bytes());
        // Recomputing over header-with-checksum should yield 0.
        assert_eq!(internet_checksum(&hdr), 0);
    }
}
