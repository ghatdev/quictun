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
    DecryptedPacket, EncryptResult, ParseError,
    decrypt_payload, encrypt_packet, prepare_key_generations, unprotect_header,
    KEY_UPDATE_THRESHOLD, MAX_ACK_RANGES, DEFAULT_ACK_INTERVAL,
};

/// Non-atomic QUIC 1-RTT connection state for single-task use.
///
/// All methods take `&mut self`. No locks, no atomics, no Arc.
pub struct LocalConnectionState {
    // Keys — plain, no locks.
    rx_packet_key: Box<dyn PacketKey>,
    tx_packet_key: Box<dyn PacketKey>,
    rx_header_key: Box<dyn HeaderKey>,
    tx_header_key: Box<dyn HeaderKey>,
    tag_len: usize,

    // Key update — plain structs.
    next_keys: VecDeque<(Box<dyn PacketKey>, Box<dyn PacketKey>)>,
    pending_rx_key: Option<Box<dyn PacketKey>>,
    key_phase: bool,
    peer_key_phase: bool,
    packets_since_key_update: u64,

    // Identity.
    local_cid: ConnectionId,
    remote_cid: ConnectionId,
    local_cid_len: usize,

    // TX state.
    pn_counter: u64,
    largest_acked: u64,

    // RX state.
    largest_rx_pn: u64,
    received: Bitmap,
    rx_since_last_ack: u32,
    ack_interval: u32,
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
            local_cid,
            remote_cid,
            local_cid_len: local_cid.len(),
            pn_counter: 0,
            largest_acked: 0,
            largest_rx_pn: 0,
            received: Bitmap::new(),
            rx_since_last_ack: 0,
            ack_interval: DEFAULT_ACK_INTERVAL,
        }
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

        let result = decrypt_payload(packet, &hdr, &*self.rx_packet_key, scratch)?;

        // Update RX state.
        self.received.set(hdr.pn);
        if hdr.pn > self.largest_rx_pn {
            self.largest_rx_pn = hdr.pn;
        }
        self.rx_since_last_ack += 1;

        Ok(result)
    }

    /// Encrypt a datagram payload into a complete 1-RTT QUIC packet.
    pub fn encrypt_datagram(
        &mut self,
        payload: &[u8],
        ack_ranges: Option<&[Range<u64>]>,
        buf: &mut [u8],
    ) -> Result<EncryptResult, ParseError> {
        self.packets_since_key_update += 1;
        if self.packets_since_key_update == KEY_UPDATE_THRESHOLD {
            self.initiate_key_update();
        }

        let pn = self.pn_counter;
        self.pn_counter += 1;

        encrypt_packet(
            payload,
            ack_ranges,
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

    /// Check if an ACK should be sent.
    pub fn needs_ack(&self) -> bool {
        self.rx_since_last_ack >= self.ack_interval
    }

    /// Generate ACK ranges from the received bitmap.
    pub fn generate_ack_ranges(&mut self) -> SmallVec<[Range<u64>; 8]> {
        let ranges = generate_ack_ranges_from_bitmap(&self.received, self.largest_rx_pn);
        self.rx_since_last_ack = 0;
        if let Some(last_range) = ranges.last() {
            if last_range.start > 0 {
                self.received.advance_base(last_range.start);
            }
        }
        ranges
    }

    /// Process an ACK frame received from the peer.
    pub fn process_ack(&mut self, ack: &AckFrame) {
        if ack.largest_acked > self.largest_acked {
            self.largest_acked = ack.largest_acked;
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

    fn handle_key_update_rx(&mut self, new_phase: bool) {
        if let Some(new_rx) = self.pending_rx_key.take() {
            self.rx_packet_key = new_rx;
            tracing::debug!("key update: RX rotated (peer responded to our initiation)");
        } else if let Some((new_rx, new_tx)) = self.next_keys.pop_front() {
            self.rx_packet_key = new_rx;
            self.tx_packet_key = new_tx;
            tracing::debug!("key update: rotated to new keys (peer-initiated)");
        } else {
            warn!("key update requested but no pre-computed keys available");
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
            warn!("key update: no pre-computed keys available, cannot rotate");
        }
    }
}

/// Generate ACK ranges from a non-atomic Bitmap.
fn generate_ack_ranges_from_bitmap(
    bitmap: &Bitmap,
    largest_pn: u64,
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
}
