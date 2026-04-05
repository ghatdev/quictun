//! Single-owner connection state for the tokio single-task data plane.
//!
//! [`LocalConnectionState`] provides the same encrypt/decrypt/ACK API as
//! [`ConnectionState`](crate::ConnectionState) but uses plain fields instead
//! of atomics/locks. Designed for `&mut self` access from a single tokio task.

use std::collections::VecDeque;
use std::ops::Range;

use bytes::BytesMut;
use quinn_proto::ConnectionId;
use quinn_proto::crypto::{self, HeaderKey, PacketKey};
use smallvec::SmallVec;
use tracing::warn;

use crate::bitmap::Bitmap;
use crate::frame::AckFrame;
use crate::{
    DecryptedInPlace, DecryptedPacket, EncryptResult, KEY_UPDATE_THRESHOLD,
    MAX_ACK_RANGES, ParseError, decrypt_payload, decrypt_payload_in_place, encrypt_packet,
    encrypt_packet_in_place, prepare_key_generations, unprotect_header,
};

/// Pre-assigned metadata for one packet in a batch (parallel encrypt).
pub struct PreparedPacket {
    pub pn: u64,
    pub largest_acked: u64,
    pub key_phase: bool,
}

/// Immutable key snapshot for parallel sealing.
///
/// Holds references to the TX keys. `PacketKey` and `HeaderKey` are `Send + Sync`,
/// so this can be shared across threads for parallel encrypt.
pub struct SealKeys<'a> {
    pub remote_cid: &'a ConnectionId,
    pub tx_packet_key: &'a dyn PacketKey,
    pub tx_header_key: &'a dyn HeaderKey,
    pub tag_len: usize,
}

// SAFETY: PacketKey and HeaderKey are Send + Sync (confirmed in quinn-proto).
// SealKeys only holds immutable references to them.
unsafe impl Send for SealKeys<'_> {}
unsafe impl Sync for SealKeys<'_> {}

/// Non-atomic QUIC 1-RTT connection state for single-task use.
///
/// All methods take `&mut self`. No locks, no atomics, no Arc.
pub struct LocalConnectionState {
    // Keys — plain, no locks.
    pub(crate) rx_packet_key: Box<dyn PacketKey>,
    pub(crate) tx_packet_key: Box<dyn PacketKey>,
    pub(crate) rx_header_key: Box<dyn HeaderKey>,
    pub(crate) tx_header_key: Box<dyn HeaderKey>,
    pub(crate) tag_len: usize,

    // Key update — plain structs.
    pub(crate) next_keys: VecDeque<(Box<dyn PacketKey>, Box<dyn PacketKey>)>,
    pub(crate) pending_rx_key: Option<Box<dyn PacketKey>>,
    pub(crate) key_phase: bool,
    pub(crate) peer_key_phase: bool,
    pub(crate) packets_since_key_update: u64,

    // Identity.
    pub(crate) local_cid: ConnectionId,
    pub(crate) remote_cid: ConnectionId,
    pub(crate) local_cid_len: usize,

    // Key exhaustion flag.
    pub(crate) key_exhausted: bool,

    // TX state.
    pub(crate) pn_counter: u64,
    pub(crate) largest_acked: u64,

    // RX state.
    pub(crate) largest_rx_pn: u64,
    pub(crate) received: Bitmap,
    /// Largest RX PN at the time of the last ACK send (for timer-driven ACKs).
    pub(crate) last_acked_pn: u64,

    // OWD tracking (receiver side — for packets we receive from peer).
    pub(crate) owd_tracker: crate::rate_control::OwdTracker,

    // Rate control (sender side, optional, None = no CC).
    pub(crate) rate_controller: Option<crate::rate_control::RateController>,
}

impl LocalConnectionState {
    /// Create from quinn-proto keys after handshake.
    pub fn new(
        keys: crypto::Keys,
        key_generations: VecDeque<crypto::KeyPair<Box<dyn PacketKey>>>,
        local_cid: ConnectionId,
        remote_cid: ConnectionId,
        is_server: bool,
    ) -> Self {
        let tag_len = keys.packet.local.tag_len();
        let (tx_packet_key, rx_packet_key) = (keys.packet.local, keys.packet.remote);
        let (tx_header_key, rx_header_key) = (keys.header.local, keys.header.remote);
        let next_keys = prepare_key_generations(key_generations);
        let _ = is_server;

        Self {
            rx_packet_key,
            tx_packet_key,
            rx_header_key,
            tx_header_key,
            tag_len,
            next_keys,
            pending_rx_key: None,
            key_phase: false,
            peer_key_phase: false,
            packets_since_key_update: 0,
            key_exhausted: false,
            local_cid,
            remote_cid,
            local_cid_len: local_cid.len(),
            pn_counter: 0,
            largest_acked: 0,
            largest_rx_pn: 0,
            received: Bitmap::new(),
            last_acked_pn: 0,
            owd_tracker: crate::rate_control::OwdTracker::new(),
            rate_controller: None,
        }
    }

    /// Create with a custom ACK interval (kept for API compat, interval is ignored).
    pub fn with_ack_interval(
        keys: crypto::Keys,
        key_generations: VecDeque<crypto::KeyPair<Box<dyn PacketKey>>>,
        local_cid: ConnectionId,
        remote_cid: ConnectionId,
        is_server: bool,
        _ack_interval: u32,
    ) -> Self {
        Self::new(keys, key_generations, local_cid, remote_cid, is_server)
    }

    /// Decrypt an incoming 1-RTT packet, reusing a caller-provided BytesMut.
    pub fn decrypt_packet_with_buf(
        &mut self,
        packet: &mut [u8],
        scratch: &mut BytesMut,
    ) -> Result<DecryptedPacket, ParseError> {
        let hdr = unprotect_header(
            packet,
            self.local_cid_len,
            self.tag_len,
            &*self.rx_header_key,
            self.largest_rx_pn,
        )?;

        // Key phase rotation (single-owner, no CAS needed).
        if hdr.key_phase != self.peer_key_phase {
            self.peer_key_phase = hdr.key_phase;
            self.handle_key_update_rx(hdr.key_phase);
        }

        // Reject duplicate packet numbers.
        if self.received.test(hdr.pn) {
            return Err(ParseError::DuplicatePacket);
        }

        let result = decrypt_payload(packet, &hdr, &*self.rx_packet_key, scratch)?;

        // Update RX state.
        self.received.set(hdr.pn);
        if hdr.pn > self.largest_rx_pn {
            self.largest_rx_pn = hdr.pn;
        }

        // OWD tracking: compute queuing delay from sender's timestamp.
        if let Some(tx_us) = result.tx_timestamp {
            self.owd_tracker.on_data_received(tx_us);
        }

        Ok(result)
    }

    /// Decrypt an incoming 1-RTT packet fully in-place (zero heap allocation).
    ///
    /// Returns byte ranges into `packet` for each DATAGRAM payload.
    /// Used by the DPDK data plane where mbufs are decrypted in-place.
    pub fn decrypt_packet_in_place(
        &mut self,
        packet: &mut [u8],
    ) -> Result<DecryptedInPlace, ParseError> {
        let hdr = unprotect_header(
            packet,
            self.local_cid_len,
            self.tag_len,
            &*self.rx_header_key,
            self.largest_rx_pn,
        )?;

        // Key phase rotation (single-owner, no CAS needed).
        if hdr.key_phase != self.peer_key_phase {
            self.peer_key_phase = hdr.key_phase;
            self.handle_key_update_rx(hdr.key_phase);
        }

        // Reject duplicate packet numbers.
        if self.received.test(hdr.pn) {
            return Err(ParseError::DuplicatePacket);
        }

        let result = decrypt_payload_in_place(packet, &hdr, &*self.rx_packet_key)?;

        // Update RX state.
        self.received.set(hdr.pn);
        if hdr.pn > self.largest_rx_pn {
            self.largest_rx_pn = hdr.pn;
        }

        // OWD tracking: compute queuing delay from sender's timestamp.
        if let Some(tx_us) = result.tx_timestamp {
            self.owd_tracker.on_data_received(tx_us);
        }

        Ok(result)
    }

    /// Encrypt a datagram payload into a complete 1-RTT QUIC packet.
    pub fn encrypt_datagram(
        &mut self,
        payload: &[u8],
        buf: &mut [u8],
    ) -> Result<EncryptResult, ParseError> {
        self.packets_since_key_update += 1;
        if self.packets_since_key_update == KEY_UPDATE_THRESHOLD {
            self.initiate_key_update();
        }

        let pn = self.pn_counter;
        self.pn_counter += 1;

        // Include OWD timestamp if CC is enabled (5 extra bytes per packet).
        let tx_timestamp = if self.rate_controller.is_some() {
            Some((crate::coarse_now_ns() / 1000) as u32)
        } else {
            None
        };

        encrypt_packet(
            payload,
            &self.remote_cid,
            pn,
            self.largest_acked,
            self.key_phase,
            &*self.tx_packet_key,
            &*self.tx_header_key,
            self.tag_len,
            buf,
            tx_timestamp,
        )
    }

    /// Encrypt a datagram in-place where the payload is already positioned in `buf`.
    ///
    /// The payload must start at offset `1 + remote_cid.len() + 4 + 1` (= 14 for 8-byte CID).
    /// Writes the QUIC short header and DATAGRAM frame type over the first bytes,
    /// then encrypts in-place — **no payload copy**.
    pub fn encrypt_datagram_in_place(
        &mut self,
        payload_len: usize,
        buf: &mut [u8],
    ) -> Result<EncryptResult, ParseError> {
        self.packets_since_key_update += 1;
        if self.packets_since_key_update == KEY_UPDATE_THRESHOLD {
            self.initiate_key_update();
        }

        let pn = self.pn_counter;
        self.pn_counter += 1;

        encrypt_packet_in_place(
            payload_len,
            &self.remote_cid,
            pn,
            self.largest_acked,
            self.key_phase,
            &*self.tx_packet_key,
            &*self.tx_header_key,
            self.tag_len,
            buf,
        )
    }

    /// Encrypt a standalone ACK packet.
    ///
    /// Generates ACK ranges from the received bitmap and encrypts an ACK-only
    /// 1-RTT packet. Used by the timer-driven ACK path.
    pub fn encrypt_ack(
        &mut self,
        buf: &mut [u8],
    ) -> Result<EncryptResult, ParseError> {
        let ack_ranges = self.generate_ack_ranges();

        // Carry OWD-computed queuing delay in the ack_delay field.
        let ack_delay_us = self.owd_tracker.queuing_delay_us;

        self.packets_since_key_update += 1;
        if self.packets_since_key_update == KEY_UPDATE_THRESHOLD {
            self.initiate_key_update();
        }

        let pn = self.pn_counter;
        self.pn_counter += 1;

        crate::encrypt_ack_packet(
            &ack_ranges,
            ack_delay_us,
            &self.remote_cid,
            pn,
            self.largest_acked,
            self.key_phase,
            &*self.tx_packet_key,
            &*self.tx_header_key,
            self.tag_len,
            buf,
        )
    }

    /// Encrypt a CONNECTION_CLOSE frame (error code 0x00 = No Error) into a 1-RTT packet.
    ///
    /// Used during graceful shutdown. Does not increment the key update counter.
    pub fn encrypt_connection_close(
        &mut self,
        buf: &mut [u8],
    ) -> Result<EncryptResult, ParseError> {
        let pn = self.pn_counter;
        self.pn_counter += 1;

        let (header_len, _pn_len) = crate::packet::build_short_header(
            &self.remote_cid,
            pn,
            self.largest_acked,
            self.key_phase,
            false,
            buf,
        );

        let mut frame_pos = header_len;
        frame_pos += crate::frame::build_connection_close(0x00, &mut buf[frame_pos..]);

        // Ensure minimum packet size for header protection sample.
        let pn_offset = 1 + self.remote_cid.len();
        let min_total = pn_offset + 4 + self.tx_header_key.sample_size();
        let total_with_tag = frame_pos + self.tag_len;
        if total_with_tag < min_total {
            let pad_needed = min_total - total_with_tag;
            buf[frame_pos..frame_pos + pad_needed].fill(0x00);
            frame_pos += pad_needed;
        }

        let total_with_tag = frame_pos + self.tag_len;
        if buf.len() < total_with_tag {
            return Err(ParseError::BufferTooShort);
        }

        self.tx_packet_key
            .encrypt(pn, &mut buf[..total_with_tag], header_len);
        self.tx_header_key
            .encrypt(pn_offset, &mut buf[..total_with_tag]);

        Ok(EncryptResult {
            len: total_with_tag,
            pn,
        })
    }

    /// Check if an ACK should be sent (timer-driven).
    ///
    /// Returns true if any packets have been received since the last ACK.
    /// Called by the engine's ACK timer (~20ms), not per-packet.
    pub fn needs_ack(&self) -> bool {
        self.largest_rx_pn > self.last_acked_pn
    }

    /// Generate ACK ranges from the received bitmap.
    pub fn generate_ack_ranges(&mut self) -> SmallVec<[Range<u64>; 8]> {
        let ranges = generate_ack_ranges_from_bitmap(&self.received, self.largest_rx_pn);
        self.last_acked_pn = self.largest_rx_pn;
        // Advance base past fully-ACKed regions to keep the scan window small.
        // With contiguous delivery (common in VPN), a single range [base..largest+1]
        // means base never advances. Use the first (largest) range's start instead,
        // keeping a margin of 256 PNs for late reorderings.
        if let Some(first_range) = ranges.first() {
            let new_base = first_range.start.saturating_sub(256);
            if new_base > self.received.base() {
                self.received.advance_base(new_base);
            }
        }
        ranges
    }

    /// Process an ACK frame received from the peer.
    pub fn process_ack(&mut self, ack: &AckFrame) {
        if ack.largest_acked > self.largest_acked {
            self.largest_acked = ack.largest_acked;
        }
        if let Some(ref mut rc) = self.rate_controller {
            // ack_delay carries the peer's OWD-computed queuing delay (microseconds).
            rc.on_ack(ack.ack_delay);
        }
    }

    /// Configure the delay-based rate controller.
    pub fn set_rate_control(&mut self, config: crate::rate_control::RateControlConfig) {
        self.rate_controller = Some(crate::rate_control::RateController::new(config));
    }

    /// Returns `true` if the rate controller allows more data to be sent.
    /// Always returns `true` if no rate controller is configured.
    #[inline]
    pub fn can_send(&self) -> bool {
        match &self.rate_controller {
            Some(rc) => rc.can_send(),
            None => true,
        }
    }

    /// Notify the rate controller that bytes were sent on the wire.
    #[inline]
    pub fn on_bytes_sent(&mut self, bytes: usize) {
        if let Some(ref mut rc) = self.rate_controller {
            rc.on_bytes_sent(bytes);
        }
    }

    pub fn local_cid(&self) -> &ConnectionId {
        &self.local_cid
    }

    pub fn remote_cid(&self) -> &ConnectionId {
        &self.remote_cid
    }

    pub fn local_cid_len(&self) -> usize {
        self.local_cid_len
    }

    pub fn tag_len(&self) -> usize {
        self.tag_len
    }

    /// Returns `true` if keys are exhausted and the connection must be closed.
    pub fn is_key_exhausted(&self) -> bool {
        self.key_exhausted
    }

    /// Assign packet numbers for a batch of `count` packets.
    ///
    /// Handles the key update boundary: if the batch would cross the 7M threshold,
    /// it truncates at the boundary. The caller should re-call for the remainder.
    pub fn prepare_batch(&mut self, count: usize) -> SmallVec<[PreparedPacket; 64]> {
        let mut prepared = SmallVec::with_capacity(count);

        for _ in 0..count {
            // Check key update threshold before assigning PN.
            self.packets_since_key_update += 1;
            if self.packets_since_key_update == KEY_UPDATE_THRESHOLD {
                self.initiate_key_update();
                // Truncate batch here — caller will re-call for remainder with new keys.
                if prepared.is_empty() {
                    // At least emit one packet with the new keys.
                } else {
                    break;
                }
            }

            let pn = self.pn_counter;
            self.pn_counter += 1;

            prepared.push(PreparedPacket {
                pn,
                largest_acked: self.largest_acked,
                key_phase: self.key_phase,
            });
        }

        prepared
    }

    /// Return immutable references to the current TX keys for parallel encryption.
    ///
    /// Call after `prepare_batch`. The returned references are valid until the next
    /// mutable operation on this connection.
    pub fn seal_keys(&self) -> SealKeys<'_> {
        SealKeys {
            remote_cid: &self.remote_cid,
            tx_packet_key: &*self.tx_packet_key,
            tx_header_key: &*self.tx_header_key,
            tag_len: self.tag_len,
        }
    }

    fn handle_key_update_rx(&mut self, new_phase: bool) {
        if let Some(new_rx) = self.pending_rx_key.take() {
            self.rx_packet_key = new_rx;
            tracing::debug!("key update: RX rotated (peer responded to our initiation)");
        } else if let Some((new_rx, new_tx)) = self.next_keys.pop_front() {
            self.rx_packet_key = new_rx;
            self.tx_packet_key = new_tx;
            tracing::debug!("key update: rotated to new keys (peer-initiated)");
        } else {
            self.key_exhausted = true;
            warn!("key update: no pre-computed keys available, connection must be closed");
            return;
        }
        self.key_phase = new_phase;
        self.packets_since_key_update = 0;
    }

    fn initiate_key_update(&mut self) {
        if let Some((new_rx, new_tx)) = self.next_keys.pop_front() {
            self.pending_rx_key = Some(new_rx);
            self.tx_packet_key = new_tx;
            self.key_phase = !self.key_phase;
            self.packets_since_key_update = 0;
            tracing::debug!("key update: TX rotated, awaiting peer response");
        } else {
            self.key_exhausted = true;
            warn!("key update: no pre-computed keys available, connection must be closed");
        }
    }
}

/// Generate ACK ranges from a non-atomic Bitmap using word-level scanning.
///
/// Scans 64 bits at a time instead of bit-by-bit. For nearly-contiguous bitmaps
/// (common in VPN tunnels with in-order delivery), most words are 0xFFFF...
/// and are skipped in one comparison.
pub(crate) fn generate_ack_ranges_from_bitmap(bitmap: &Bitmap, largest_pn: u64) -> SmallVec<[Range<u64>; 8]> {
    let mut ranges: SmallVec<[Range<u64>; 8]> = SmallVec::new();
    let base = bitmap.base();
    if largest_pn < base {
        return ranges;
    }

    // Use absolute PN indexing (consistent with Bitmap::set/test/advance_base).
    let largest_word = (largest_pn >> 6) as usize;
    let base_word = (base >> 6) as usize;
    // Mask: only bits <= largest_pn's bit position in the top word.
    let top_bit = (largest_pn & 63) as u32;
    let top_mask = if top_bit == 63 {
        u64::MAX
    } else {
        (1u64 << (top_bit + 1)) - 1
    };

    let bitmap_word_count = bitmap.word_count();

    let mut in_range = false;
    let mut range_end = 0u64;
    let mut first_word = true;

    let mut word_idx = largest_word;

    loop {
        let actual_word_idx = word_idx & (bitmap_word_count - 1);
        let mut word = bitmap.word_at(actual_word_idx);

        // Mask the top word to only include bits up to largest_pn.
        if first_word {
            word &= top_mask;
            first_word = false;
        }

        // With absolute indexing, word_base_pn = word_idx * 64.
        let word_base_pn = (word_idx as u64) * 64;

        if word == u64::MAX {
            // All 64 bits set — extend or start range.
            let block_end = word_base_pn + 64;
            if !in_range {
                range_end = block_end.min(largest_pn + 1);
                in_range = true;
            }
            // Range continues.
        } else if word == 0 {
            // No bits set — close range if open.
            if in_range {
                let block_end = word_base_pn + 64;
                ranges.push(block_end..range_end);
                in_range = false;
                if ranges.len() >= MAX_ACK_RANGES {
                    break;
                }
            }
        } else {
            // Partial word — scan bits from high to low.
            for bit in (0..64).rev() {
                let pn = word_base_pn + bit;
                if pn > largest_pn || pn < base {
                    continue;
                }
                if (word >> bit) & 1 == 1 {
                    if !in_range {
                        range_end = pn + 1;
                        in_range = true;
                    }
                } else if in_range {
                    ranges.push(pn + 1..range_end);
                    in_range = false;
                    if ranges.len() >= MAX_ACK_RANGES {
                        break;
                    }
                }
            }
            if ranges.len() >= MAX_ACK_RANGES {
                break;
            }
        }

        if word_idx <= base_word {
            break;
        }
        word_idx -= 1;
    }

    // Close final range.
    if in_range && ranges.len() < MAX_ACK_RANGES {
        ranges.push(base..range_end);
    }

    ranges
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ranges_contiguous() {
        let mut bm = Bitmap::new();
        for pn in 0..10 {
            bm.set(pn);
        }
        let ranges = generate_ack_ranges_from_bitmap(&bm, 9);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 0..10);
    }

    #[test]
    fn generate_ranges_with_gap() {
        let mut bm = Bitmap::new();
        for pn in 0..5 {
            bm.set(pn);
        }
        for pn in 7..10 {
            bm.set(pn);
        }
        let ranges = generate_ack_ranges_from_bitmap(&bm, 9);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 7..10);
        assert_eq!(ranges[1], 0..5);
    }

    #[test]
    fn generate_ranges_large_contiguous() {
        // Simulate VPN scenario: 1000 contiguous packets.
        let mut bm = Bitmap::new();
        for pn in 0..1000 {
            bm.set(pn);
        }
        let ranges = generate_ack_ranges_from_bitmap(&bm, 999);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 0..1000);
    }

    #[test]
    fn generate_ranges_cross_word_boundary() {
        // Gap right at a word boundary (64).
        let mut bm = Bitmap::new();
        for pn in 0..63 {
            bm.set(pn);
        }
        // Skip 63
        for pn in 64..128 {
            bm.set(pn);
        }
        let ranges = generate_ack_ranges_from_bitmap(&bm, 127);
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0], 64..128);
        assert_eq!(ranges[1], 0..63);
    }

    #[test]
    fn generate_ranges_after_advance() {
        // Test with advanced base.
        let mut bm = Bitmap::new();
        for pn in 0..200 {
            bm.set(pn);
        }
        bm.advance_base(100);
        for pn in 100..300 {
            bm.set(pn);
        }
        let ranges = generate_ack_ranges_from_bitmap(&bm, 299);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0], 100..300);
    }

    /// Compare word-level scan against bit-by-bit reference implementation.
    #[test]
    fn generate_ranges_matches_reference() {
        fn reference_scan(bitmap: &Bitmap, largest_pn: u64) -> SmallVec<[Range<u64>; 8]> {
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
                    if ranges.len() >= MAX_ACK_RANGES {
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

        // Test 1: Large contiguous block.
        let mut bm = Bitmap::new();
        for pn in 0..5000 {
            bm.set(pn);
        }
        assert_eq!(
            generate_ack_ranges_from_bitmap(&bm, 4999),
            reference_scan(&bm, 4999),
            "test 1: large contiguous"
        );

        // Test 2: Periodic gaps (every 100th packet missing).
        let mut bm = Bitmap::new();
        for pn in 0..2000 {
            if pn % 100 != 50 {
                bm.set(pn);
            }
        }
        assert_eq!(
            generate_ack_ranges_from_bitmap(&bm, 1999),
            reference_scan(&bm, 1999),
            "test 2: periodic gaps"
        );

        // Test 3: Gap at word boundary.
        let mut bm = Bitmap::new();
        for pn in 0..500 {
            if pn != 64 && pn != 128 && pn != 192 {
                bm.set(pn);
            }
        }
        assert_eq!(
            generate_ack_ranges_from_bitmap(&bm, 499),
            reference_scan(&bm, 499),
            "test 3: gaps at word boundaries"
        );

        // Test 4: Only every other packet.
        let mut bm = Bitmap::new();
        for pn in (0..200).step_by(2) {
            bm.set(pn);
        }
        assert_eq!(
            generate_ack_ranges_from_bitmap(&bm, 199),
            reference_scan(&bm, 199),
            "test 4: every other packet (largest not set)"
        );
        assert_eq!(
            generate_ack_ranges_from_bitmap(&bm, 198),
            reference_scan(&bm, 198),
            "test 4b: every other packet (largest set)"
        );

        // Test 5: Single packet.
        let mut bm = Bitmap::new();
        bm.set(42);
        assert_eq!(
            generate_ack_ranges_from_bitmap(&bm, 42),
            reference_scan(&bm, 42),
            "test 5: single packet"
        );

        // Test 6: Empty range at start, packets at end.
        let mut bm = Bitmap::new();
        for pn in 900..1000 {
            bm.set(pn);
        }
        assert_eq!(
            generate_ack_ranges_from_bitmap(&bm, 999),
            reference_scan(&bm, 999),
            "test 6: gap at start"
        );
    }
}
