use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::BytesMut;
use rustc_hash::FxHashMap;

use crate::dispatch::{ConnectionEntry, PipelineRings};
use crate::event_loop::{DpdkConfig, SendPtr};
use crate::ffi;
use crate::mbuf::Mbuf;
use crate::net::{self, ArpTable, ChecksumMode, NetIdentity, ParsedPacket};
use crate::port;
use crate::shared::{self, BUF_SIZE, DriveResult, MultiQuicState, QuicState};
use quictun_core::manager::{ConnEntry, ConnectionManager, ManagerAction, PromoteResult};
use quictun_core::peer::{self, PeerConfig};
use quictun_core::routing::RouteAction;
use quictun_proto::cid_to_u64;
use quictun_proto::local::LocalConnectionState;

/// Maximum burst size for rx/tx.
pub(crate) const BURST_SIZE: usize = 32;

/// Smaller burst size for inner→outer pipeline in quictun-proto mode.
/// Pending mbuf retry + back-pressure handle TX ring overflow; safe to raise.
const INNER_BURST_SIZE: u16 = 24;

/// Maximum number of GSO segments per poll_transmit call.
/// quinn-proto will pack up to this many QUIC packets into one transmit buffer.
const MAX_GSO_SEGMENTS: usize = 10;

/// Ethernet header size (dst MAC + src MAC + EtherType).
const ETH_HLEN: usize = 14;

/// Pre-computed Ethernet header for the DPDK inner interface.
///
/// Packets between the engine and the inner port always use the same
/// src/dst MACs, so we compute the header once and reuse it.
pub struct InnerEthHeader {
    /// Header bytes: [dst_mac(6)][src_mac(6)][0x08, 0x00] (IPv4).
    pub bytes: [u8; ETH_HLEN],
}

impl InnerEthHeader {
    /// Build the Ethernet header for engine → app direction.
    ///
    /// - `src_mac`: MAC of the DPDK inner port
    /// - `dst_mac`: MAC of the kernel-facing TAP interface
    pub fn new(src_mac: [u8; 6], dst_mac: [u8; 6]) -> Self {
        let mut bytes = [0u8; ETH_HLEN];
        bytes[0..6].copy_from_slice(&dst_mac);
        bytes[6..12].copy_from_slice(&src_mac);
        bytes[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
        Self { bytes }
    }
}

/// Inner interface configuration for the L2 DPDK inner port.
///
/// Used by both TAP PMD and virtio-user modes.
pub struct InnerPort {
    pub port_id: u16,
    pub eth_hdr: InnerEthHeader,
}

/// Number of consecutive empty polls before entering backoff sleep.
pub(crate) const EMPTY_POLL_THRESHOLD: u32 = 1024;
/// Minimum sleep duration in microseconds during adaptive backoff.
pub(crate) const MIN_DELAY_US: u32 = 1;
/// Maximum sleep duration in microseconds during adaptive backoff.
pub(crate) const MAX_DELAY_US: u32 = 100;

/// Result of resolving a completed handshake into connection metadata.
pub struct ResolvedHandshake {
    pub conn: LocalConnectionState,
    pub tunnel_ip: Ipv4Addr,
    pub remote_addr: SocketAddr,
    pub remote_mac: [u8; 6],
    pub cid: u64,
    /// Raw CID bytes for logging.
    pub cid_bytes: Vec<u8>,
    /// Peer's allowed IP networks (for router-mode routing table).
    pub allowed_ips: Vec<ipnet::Ipv4Net>,
}

/// Extract shared handshake completion logic: identify peer, resolve MAC, build CID.
///
/// Returns `None` if the peer cannot be identified (rejects the connection).
pub(crate) fn resolve_completed_handshake(
    hs: &shared::HandshakeState,
    conn_state: LocalConnectionState,
    peers: &[PeerConfig],
    identity: &NetIdentity,
    arp_table: &ArpTable,
) -> Option<ResolvedHandshake> {
    // Identify peer to get tunnel IP and allowed IPs.
    let identified = peer::identify_peer(&hs.connection, peers)
        .or_else(|| {
            // Single-peer fallback: skip identification.
            if peers.len() == 1 {
                Some(&peers[0])
            } else {
                None
            }
        });

    let identified = identified.or_else(|| {
        tracing::warn!(
            remote = %hs.remote_addr,
            "could not identify peer, rejecting"
        );
        None
    })?;

    let tunnel_ip = identified.tunnel_ip;
    let allowed_ips = identified.allowed_ips.clone();

    // Resolve remote MAC from ARP table.
    let remote_ip = match hs.remote_addr.ip() {
        std::net::IpAddr::V4(ip) => ip,
        _ => Ipv4Addr::UNSPECIFIED,
    };
    let remote_mac = arp_table.lookup(remote_ip).unwrap_or([0xff; 6]);

    let cid_bytes = conn_state.local_cid().to_vec();
    let cid = cid_to_u64(&cid_bytes);

    Some(ResolvedHandshake {
        conn: conn_state,
        tunnel_ip,
        remote_addr: hs.remote_addr,
        remote_mac,
        cid,
        cid_bytes,
        allowed_ips,
    })
}

/// Run the DPDK polling engine.
///
/// This is the hot loop: RX burst → QUIC → inner write → drain transmits → TX burst.
/// No syscalls for network I/O (pure DPDK PMD polling).
///
/// Handles 1..N connections on a single core via a connection table.
/// Single peer = 1-entry table. Multi-peer listeners work without multi-core.
#[allow(clippy::too_many_arguments)]
pub fn run(
    outer_port_id: u16,
    queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    multi_state: &mut MultiQuicState,
    identity: &NetIdentity,
    arp_table: &mut ArpTable,
    inner: InnerPort,
    shutdown: Arc<AtomicBool>,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    peers: &[PeerConfig],
    tunnel_ip: Ipv4Addr,
    max_peers: usize,
    idle_timeout: Duration,
    rate_control_config: Option<quictun_proto::rate_control::RateControlConfig>,
) -> Result<()> {
    const CID_LEN: usize = 8;

    let mut response_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut pkt_buf = [0u8; 2048];
    let mut ip_id: u16 = 0;
    // Reusable BytesMut for feeding quinn-proto long header RX (handshake path).
    let mut rx_buf = BytesMut::with_capacity(2048);

    // Pending packets to transmit (raw Ethernet frames for ARP replies, etc.).
    let mut pending_frames: Vec<Vec<u8>> = Vec::new();

    // Monotonic epoch for CC timestamps (wrapping u32 microseconds).
    let cc_epoch = Instant::now();
    let cc_enabled = rate_control_config.is_some();

    // Connection lifecycle manager: connection table + routing table + sweep.
    let mut manager = ConnectionManager::<LocalConnectionState>::new(
        tunnel_ip,
        false, // default_external
        max_peers,
        idle_timeout,
    );

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut quic_rx: u64 = 0;
    let mut inner_rx: u64 = 0;
    let mut inner_tx: u64 = 0;
    let mut inner_tx_drop: u64 = 0;
    let mut outer_tx_drop: u64 = 0;
    let mut decrypt_fail: u64 = 0;
    let mut last_stats = Instant::now();

    // Adaptive polling state.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    // Rate-limited stats timer: only call Instant::now() every 32768 busy iterations.
    // clock_gettime + duration_since was ~12% CPU at 13 Gbps for a 2-second stats timer.
    let mut stats_poll_counter: u32 = 0;

    // ACK timer: generate explicit ACK frames with queuing delay for CC feedback.
    // Check every 1024 busy iterations (~25ms at high rates).
    let mut ack_poll_counter: u32 = 0;
    let mut last_ack = Instant::now();
    let mut ack_buf = [0u8; 256];

    // Pre-allocated mbuf vectors for batched TX (reused across loop iterations).
    let mut inner_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);
    let mut outer_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);

    // Pending mbufs from a failed outer tx_burst (retry next iteration instead of dropping).
    let mut pending_outer_tx: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);

    // If connector, drain initial handshake transmits (Client Hello).
    for hs in multi_state.handshakes.values_mut() {
        drain_handshake_transmits(
            &mut hs.connection,
            Instant::now(),
            outer_port_id,
            queue_id,
            mempool,
            identity,
            arp_table,
            &mut transmit_buf,
            &mut tx_pkts,
            &mut ip_id,
            checksum_mode,
        );
    }

    tracing::info!("DPDK engine started (polling loop)");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("shutdown signal received");
            break;
        }

        // During handshake, quinn-proto needs accurate time every iteration.
        // After all handshakes complete, `now` is only used for stats — sample less.
        if !multi_state.handshakes.is_empty() {
            now = Instant::now();
        }

        // ── Phase 1a: RX burst from outer port → parse → decrypt/handshake ──

        inner_tx_mbufs.clear();

        let mut rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];

        let nb_rx = port::rx_burst(outer_port_id, queue_id, &mut rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_rx as usize {
            // SAFETY: rx_burst wrote a valid mbuf pointer into rx_mbufs[i]; we take
            // exclusive ownership. The mbuf is freed on drop at end of this iteration.
            let mut mbuf = unsafe { Mbuf::from_raw(rx_mbufs[i]) };
            rx_pkts += 1;

            enum RxAction {
                ShortHeader {
                    src_mac: [u8; 6],
                    src_ip: Ipv4Addr,
                    src_port: u16,
                    payload_offset: usize,
                    payload_len: usize,
                },
                LongHeader {
                    src_mac: [u8; 6],
                    src_ip: Ipv4Addr,
                    src_port: u16,
                    ecn: Option<quinn_proto::EcnCodepoint>,
                    payload_offset: usize,
                    payload_len: usize,
                },
                Arp(net::ParsedArp),
                Skip,
            }

            let data = mbuf.data_mut();

            let action = {
                match net::parse_packet(data) {
                    Some(ParsedPacket::Udp(udp)) => {
                        if udp.dst_ip != identity.local_ip
                            || udp.dst_port != identity.local_port
                            || udp.payload.is_empty()
                        {
                            RxAction::Skip
                        } else {
                            let payload_offset =
                                unsafe { udp.payload.as_ptr().offset_from(data.as_ptr()) as usize };
                            let payload_len = udp.payload.len();
                            let first_byte = udp.payload[0];
                            if first_byte & 0x80 == 0 {
                                // Short header → fast path (decrypt via connection table).
                                RxAction::ShortHeader {
                                    src_mac: udp.src_mac,
                                    src_ip: udp.src_ip,
                                    src_port: udp.src_port,
                                    payload_offset,
                                    payload_len,
                                }
                            } else {
                                // Long header → handshake via MultiQuicState.
                                RxAction::LongHeader {
                                    src_mac: udp.src_mac,
                                    src_ip: udp.src_ip,
                                    src_port: udp.src_port,
                                    ecn: udp.ecn,
                                    payload_offset,
                                    payload_len,
                                }
                            }
                        }
                    }
                    Some(ParsedPacket::Arp(arp)) => RxAction::Arp(arp),
                    Some(ParsedPacket::Ipv4Raw(_)) => RxAction::Skip,
                    None => RxAction::Skip,
                }
            };

            match action {
                RxAction::ShortHeader {
                    src_mac,
                    src_ip,
                    src_port,
                    payload_offset,
                    payload_len,
                } => {
                    arp_table.learn(src_ip, src_mac);
                    quic_rx += 1;

                    // Extract CID and look up connection.
                    if payload_len < 1 + CID_LEN {
                        continue;
                    }
                    let cid_key = cid_to_u64(&data[payload_offset + 1..payload_offset + 1 + CID_LEN]);

                    let Some(entry) = manager.get_mut(&cid_key) else {
                        decrypt_fail += 1;
                        continue;
                    };

                    // Decrypt and extract datagram info while data borrow is active.
                    let decrypt_result = {
                        match entry.conn.decrypt_packet_in_place(
                            &mut data[payload_offset..payload_offset + payload_len],
                        ) {
                            Ok(decrypted) => {
                                entry.remote_addr = SocketAddr::new(src_ip.into(), src_port);
                                entry.last_rx = now;

                                if let Some(ref ack) = decrypted.ack {
                                    entry.conn.process_ack(ack);
                                    entry.on_ack(ack);
                                }
                                // OWD sample from sender's timestamp.
                                if let Some(tx_us) = decrypted.tx_timestamp {
                                    let rx_us = (cc_epoch.elapsed().as_micros() & 0xFFFF_FFFF) as u32;
                                    entry.on_owd_sample(tx_us, rx_us);
                                }

                                if decrypted.datagrams.len() == 1 {
                                    // Single datagram: prepare for zero-copy.
                                    let range = &decrypted.datagrams[0];
                                    let abs_start = payload_offset + range.start;
                                    let datagram_len = range.end - range.start;
                                    Some((abs_start, datagram_len))
                                } else {
                                    // Multiple datagrams (rare): alloc+copy each.
                                    for range in &decrypted.datagrams {
                                        let abs_start = payload_offset + range.start;
                                        let abs_end = payload_offset + range.end;
                                        let datagram_len = abs_end - abs_start;
                                        let frame_len = ETH_HLEN + datagram_len;
                                        if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
                                            if let Ok(buf) = out_mbuf.alloc_space(frame_len as u16) {
                                                buf[..ETH_HLEN].copy_from_slice(&inner.eth_hdr.bytes);
                                                buf[ETH_HLEN..frame_len]
                                                    .copy_from_slice(&data[abs_start..abs_end]);
                                                inner_tx_mbufs.push(out_mbuf.into_raw());
                                                inner_tx += 1;
                                            }
                                        }
                                    }
                                    None
                                }
                            }
                            Err(_e) => {
                                decrypt_fail += 1;
                                None
                            }
                        }
                    };
                    // data borrow ends here — mbuf can be reused.

                    if let Some((abs_start, datagram_len)) = decrypt_result {
                        // Zero-copy: adjust original mbuf to inner frame layout.
                        // Strip outer headers (ETH+IP+UDP+QUIC) before datagram,
                        // keep room for 14-byte inner ETH header, trim AEAD tag.
                        let adj_len = (abs_start - ETH_HLEN) as u16;
                        let new_total = (ETH_HLEN + datagram_len) as u16;
                        if mbuf.adj(adj_len).is_some() {
                            mbuf.data_mut()[..ETH_HLEN]
                                .copy_from_slice(&inner.eth_hdr.bytes);
                            mbuf.truncate(new_total);
                            inner_tx_mbufs.push(mbuf.into_raw());
                            inner_tx += 1;
                        }
                    }
                }
                RxAction::LongHeader {
                    src_mac,
                    src_ip,
                    src_port,
                    ecn,
                    payload_offset,
                    payload_len,
                } => {
                    arp_table.learn(src_ip, src_mac);
                    quic_rx += 1;

                    // Long header → quinn-proto (handshake, cold path — copy is fine).
                    rx_buf.clear();
                    rx_buf.extend_from_slice(&data[payload_offset..payload_offset + payload_len]);
                    let quic_data = rx_buf.split();

                    let remote_addr = SocketAddr::new(src_ip.into(), src_port);
                    let responses = multi_state.handle_incoming(
                        now,
                        remote_addr,
                        ecn,
                        quic_data,
                        &mut response_buf,
                    );

                    // Send responses back to the sender.
                    for buf in responses {
                        let dst_mac = arp_table.lookup(src_ip).unwrap_or([0xff; 6]);
                        ip_id = ip_id.wrapping_add(1);
                        let frame_len = net::build_udp_packet(
                            &identity.local_mac,
                            &dst_mac,
                            identity.local_ip,
                            src_ip,
                            identity.local_port,
                            src_port,
                            &buf,
                            &mut pkt_buf,
                            0,
                            ip_id,
                            checksum_mode,
                        );
                        pending_frames.push(pkt_buf[..frame_len].to_vec());
                    }
                }
                RxAction::Arp(arp) => {
                    arp_table.learn(arp.sender_ip, arp.sender_mac);

                    // Reply to ARP requests for our IP.
                    if arp.is_request && arp.target_ip == identity.local_ip {
                        let reply =
                            net::build_arp_reply(&arp, identity.local_mac, identity.local_ip);
                        pending_frames.push(reply);
                    }
                }
                RxAction::Skip => {}
            }
            // mbuf freed on drop
        }

        // Batch send decrypted datagrams to inner port (retry once on partial send).
        if !inner_tx_mbufs.is_empty() {
            let nb = inner_tx_mbufs.len() as u16;
            let mut sent = port::tx_burst(inner.port_id, 0, &mut inner_tx_mbufs, nb);
            if sent < nb {
                let remaining = &mut inner_tx_mbufs[sent as usize..];
                let nb_remain = remaining.len() as u16;
                sent += port::tx_burst(inner.port_id, 0, remaining, nb_remain);
            }
            if sent < nb {
                inner_tx_drop += (nb - sent) as u64;
                for raw in &inner_tx_mbufs[sent as usize..] {
                    unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
                }
            }
        }

        // ── Phase 1b: Read from inner port → encrypt → outer TX ──
        //
        // Back-pressure: if the outer TX ring was full last iteration,
        // skip inner RX to let the TX queue drain.

        let mut inner_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] =
            [std::ptr::null_mut(); BURST_SIZE];
        let inner_burst = if !manager.is_empty() {
            INNER_BURST_SIZE
        } else {
            BURST_SIZE as u16
        };
        // Rate-limit backpressure: skip inner RX when CC says stop.
        let cc_blocked = cc_enabled
            && manager.values().next().map_or(false, |e| !e.can_send());
        let nb = if !pending_outer_tx.is_empty() || cc_blocked {
            0 // back-pressure: drain pending mbufs / wait for CC budget
        } else {
            port::rx_burst(inner.port_id, 0, &mut inner_rx_mbufs, inner_burst)
        };

        outer_tx_mbufs.clear();

        for i in 0..nb as usize {
            // SAFETY: inner rx_burst wrote a valid mbuf pointer; exclusive ownership taken.
            let mut mbuf = unsafe { Mbuf::from_raw(inner_rx_mbufs[i]) };

            // Extract fields from immutable data borrow, then drop the borrow.
            let (ethertype, ip_payload_len, dst_ip) = {
                let data = mbuf.data();
                if data.len() < ETH_HLEN + 20 {
                    let et = if data.len() >= ETH_HLEN {
                        u16::from_be_bytes([data[12], data[13]])
                    } else {
                        0
                    };
                    (et, 0, Ipv4Addr::UNSPECIFIED)
                } else {
                    let et = u16::from_be_bytes([data[12], data[13]]);
                    let ip_len = data.len() - ETH_HLEN;
                    let dst = Ipv4Addr::new(
                        data[ETH_HLEN + 16],
                        data[ETH_HLEN + 17],
                        data[ETH_HLEN + 18],
                        data[ETH_HLEN + 19],
                    );
                    (et, ip_len, dst)
                }
            };

            match ethertype {
                0x0800 => {
                    if ip_payload_len == 0 {
                        continue;
                    }
                    inner_rx += 1;

                    // Look up connection by dest IP, with single-connection default route.
                    let entry = match manager.lookup_route(dst_ip) {
                        RouteAction::ForwardToPeer(cid) => manager.get_mut(&cid),
                        _ if manager.len() == 1 => manager.values_mut().next(),
                        _ => None,
                    };

                    let Some(entry) = entry else {
                        continue;
                    };

                    // CC: check rate controller before sending.
                    // Break (not continue) to stop processing more inner
                    // packets — leaving them in the kernel TUN buffer is
                    // better than dropping them one by one.
                    if !entry.can_send() {
                        // Free remaining mbufs from this burst.
                        for j in (i + 1)..nb as usize {
                            unsafe { ffi::shim_rte_pktmbuf_free(inner_rx_mbufs[j]) };
                        }
                        break;
                    }

                    // Zero-copy encrypt: reuse the inner RX mbuf.
                    //
                    // Inner mbuf layout: [inner ETH(14)][IP payload(N)]
                    // QUIC short header(13) + DATAGRAM type(1) = 14 bytes = ETH_HLEN.
                    // So the QUIC overhead exactly replaces the inner ETH header.
                    //
                    // Steps:
                    // 1. Prepend 42 bytes for outer ETH(14)+IP(20)+UDP(8) using headroom
                    // 2. Append tag_len bytes for AEAD tag
                    // 3. Write QUIC header + DG type over old inner ETH position
                    // 4. Encrypt QUIC payload in-place (no copy!)
                    // 5. Write outer headers
                    let tag_len = entry.conn.tag_len();

                    if mbuf.prepend(net::HEADER_SIZE as u16).is_none() {
                        continue;
                    }
                    if mbuf.append(tag_len as u16).is_none() {
                        continue;
                    }

                    let buf = mbuf.data_mut();
                    // buf layout: [42 bytes for outer hdrs][old inner ETH(14)][IP payload(N)][tag space]
                    let quic_buf = &mut buf[net::HEADER_SIZE..];

                    let tx_ts = if cc_enabled {
                        Some((cc_epoch.elapsed().as_micros() & 0xFFFF_FFFF) as u32)
                    } else {
                        None
                    };
                    match entry.conn.encrypt_datagram_in_place(ip_payload_len, quic_buf, tx_ts) {
                        Ok(result) => {
                            let remote_ip = match entry.remote_addr.ip() {
                                std::net::IpAddr::V4(ip) => ip,
                                _ => Ipv4Addr::UNSPECIFIED,
                            };
                            let remote_mac = arp_table.lookup(remote_ip)
                                .unwrap_or([0xff; 6]);
                            ip_id = ip_id.wrapping_add(1);
                            net::build_udp_packet_inplace(
                                &identity.local_mac,
                                &remote_mac,
                                identity.local_ip,
                                remote_ip,
                                identity.local_port,
                                entry.remote_addr.port(),
                                result.len,
                                buf,
                                0,
                                ip_id,
                                checksum_mode,
                            );
                            // No truncate needed: prepend(42) + original(14+N) + append(tag)
                            // = 42 + 14 + N + tag = HEADER_SIZE + result.len exactly.
                            match checksum_mode {
                                ChecksumMode::HardwareUdpOnly => {
                                    mbuf.set_tx_udp_checksum_offload()
                                }
                                ChecksumMode::HardwareFull => {
                                    mbuf.set_tx_full_checksum_offload()
                                }
                                _ => {}
                            }
                            entry.on_bytes_sent(result.len);
                            entry.last_tx = now;
                            outer_tx_mbufs.push(mbuf.into_raw());
                        }
                        Err(e) => {
                            tracing::trace!(error = %e, "quictun-proto encrypt failed");
                        }
                    }
                }
                0x0806 => {
                    // ARP: reply to requests with our inner port MAC.
                    if let Some(ParsedPacket::Arp(arp)) = net::parse_packet(mbuf.data()) {
                        if arp.is_request {
                            let inner_mac: [u8; 6] = inner.eth_hdr.bytes[6..12]
                                .try_into()
                                .expect("eth_hdr always 14 bytes");
                            let reply = net::build_arp_reply(&arp, inner_mac, arp.target_ip);
                            if let Ok(mut reply_mbuf) = Mbuf::alloc(mempool) {
                                if reply_mbuf.write_packet(&reply).is_ok() {
                                    let raw = reply_mbuf.into_raw();
                                    let mut tx = [raw];
                                    let sent = port::tx_burst(inner.port_id, 0, &mut tx, 1);
                                    if sent == 0 {
                                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
            // mbuf freed on drop
        }

        // Drain pending mbufs from previous iteration first.
        if !pending_outer_tx.is_empty() {
            let nb_pend = pending_outer_tx.len() as u16;
            let sent = port::tx_burst(outer_port_id, queue_id, &mut pending_outer_tx, nb_pend);
            tx_pkts += sent as u64;
            if sent < nb_pend {
                if pending_outer_tx.len() > 64 {
                    outer_tx_drop += (pending_outer_tx.len() - 64) as u64;
                    for raw in &pending_outer_tx[64..] {
                        unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
                    }
                    pending_outer_tx.truncate(64);
                }
                pending_outer_tx.drain(..sent as usize);
            } else {
                pending_outer_tx.clear();
            }
        }

        // Batch TX for quictun-proto encrypted packets.
        if !outer_tx_mbufs.is_empty() {
            let nb_tx = outer_tx_mbufs.len() as u16;
            let sent = port::tx_burst(outer_port_id, queue_id, &mut outer_tx_mbufs, nb_tx);
            tx_pkts += sent as u64;
            if sent < nb_tx {
                pending_outer_tx.extend_from_slice(&outer_tx_mbufs[sent as usize..]);
            }
            outer_tx_mbufs.clear();
        }

        // ── Phase 2: Drive handshakes ────────────────────────────────

        if !multi_state.handshakes.is_empty() {
            // Handle timeouts.
            for hs in multi_state.handshakes.values_mut() {
                if let Some(timeout) = hs.connection.poll_timeout() {
                    if now >= timeout {
                        hs.connection.handle_timeout(now);
                    }
                }
            }

            // Poll for completed handshakes.
            let drive_result = multi_state.poll_handshakes();

            for ch in drive_result.completed {
                if let Some((mut hs, conn_state)) = multi_state.extract_connection(ch) {
                    // Drain final handshake transmits.
                    drain_handshake_transmits(
                        &mut hs.connection,
                        now,
                        outer_port_id,
                        queue_id,
                        mempool,
                        identity,
                        arp_table,
                        &mut transmit_buf,
                        &mut tx_pkts,
                        &mut ip_id,
                        checksum_mode,
                    );

                    match manager.promote_handshake(&hs, conn_state, peers) {
                        PromoteResult::Accepted {
                            cid_key, cid_bytes, tunnel_ip: peer_ip,
                            allowed_ips, remote_addr, keepalive_interval,
                            conn_state, evicted,
                        } => {
                            if let Some(evicted) = evicted {
                                tracing::info!(
                                    tunnel_ip = %evicted.tunnel_ip,
                                    "evicted stale connection"
                                );
                            }
                            manager.insert_connection(cid_key, ConnEntry {
                                conn: conn_state,
                                tunnel_ip: peer_ip,
                                allowed_ips,
                                remote_addr,
                                keepalive_interval,
                                last_tx: now,
                                last_rx: now,
                                owd_tracker: quictun_proto::rate_control::OwdTracker::new(),
                                rate_controller: rate_control_config.map(
                                    quictun_proto::rate_control::RateController::new,
                                ),
                            });

                            tracing::info!(
                                tunnel_ip = %peer_ip,
                                remote = %remote_addr,
                                cid = %hex::encode(&cid_bytes),
                                cc = if rate_control_config.is_some() { "delay" } else { "none" },
                                "connection established"
                            );
                        }
                        PromoteResult::Rejected { remote_addr, reason, .. } => {
                            tracing::warn!(
                                remote = %remote_addr,
                                reason = ?reason,
                                "handshake rejected"
                            );
                        }
                    }
                }
            }

            // Drain handshake transmits for in-progress connections.
            for hs in multi_state.handshakes.values_mut() {
                drain_handshake_transmits(
                    &mut hs.connection,
                    now,
                    outer_port_id,
                    queue_id,
                    mempool,
                    identity,
                    arp_table,
                    &mut transmit_buf,
                    &mut tx_pkts,
                    &mut ip_id,
                    checksum_mode,
                );
            }
        }

        // Send pending raw frames (ARP replies, stateless QUIC responses).
        send_raw_frames(
            outer_port_id,
            queue_id,
            mempool,
            &mut pending_frames,
            &mut tx_pkts,
            checksum_mode,
        )?;

        // ── Periodic stats (rate-limited clock) ─────────────────────
        // During handshake: `now` refreshed at loop top (quinn-proto needs it every iteration).
        // After handshake: only call Instant::now() every 32768 busy iterations to avoid
        // wasting ~12% CPU on clock_gettime + duration_since for a 2-second timer.
        if !multi_state.handshakes.is_empty() || (nb_rx > 0 || nb > 0) {
            stats_poll_counter = stats_poll_counter.wrapping_add(1);
            if !multi_state.handshakes.is_empty() || stats_poll_counter & 0x7FFF == 0 {
                if multi_state.handshakes.is_empty() {
                    now = Instant::now();
                }
                // Sweep idle/exhausted connections (piggyback on clock refresh).
                if !manager.is_empty() {
                    let actions = manager.sweep_timeouts();
                    for action in actions {
                        match action {
                            ManagerAction::SendKeepalive { cid_key } => {
                                if let Some(entry) = manager.get_mut(&cid_key) {
                                    let mut ka_buf = [0u8; 256];
                                    if let Ok(result) = entry.conn.encrypt_datagram(&[], &mut ka_buf, None) {
                                        let remote_ip = match entry.remote_addr.ip() {
                                            std::net::IpAddr::V4(ip) => ip,
                                            _ => Ipv4Addr::UNSPECIFIED,
                                        };
                                        let ka_mac = arp_table.lookup(remote_ip)
                                            .unwrap_or([0xff; 6]);
                                        ip_id = ip_id.wrapping_add(1);
                                        let frame_len = net::HEADER_SIZE + result.len;
                                        if let Ok(mut mbuf) = Mbuf::alloc(mempool) {
                                            if let Ok(buf) = mbuf.alloc_space(frame_len as u16) {
                                                net::build_udp_packet(
                                                    &identity.local_mac,
                                                    &ka_mac,
                                                    identity.local_ip,
                                                    remote_ip,
                                                    identity.local_port,
                                                    entry.remote_addr.port(),
                                                    &ka_buf[..result.len],
                                                    buf,
                                                    0,
                                                    ip_id,
                                                    checksum_mode,
                                                );
                                                match checksum_mode {
                                                    ChecksumMode::HardwareUdpOnly => {
                                                        mbuf.set_tx_udp_checksum_offload()
                                                    }
                                                    ChecksumMode::HardwareFull => {
                                                        mbuf.set_tx_full_checksum_offload()
                                                    }
                                                    _ => {}
                                                }
                                                let raw = mbuf.into_raw();
                                                let mut burst = [raw];
                                                let sent = port::tx_burst(outer_port_id, queue_id, &mut burst, 1);
                                                if sent == 0 {
                                                    unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                                }
                                            }
                                        }
                                        entry.last_tx = now;
                                    }
                                }
                            }
                            ManagerAction::ConnectionRemoved { tunnel_ip: tip, reason, .. } => {
                                tracing::info!(
                                    tunnel_ip = %tip,
                                    reason = ?reason,
                                    "connection removed by sweep"
                                );
                            }
                        }
                    }
                }

                if now.duration_since(last_stats).as_secs() >= 2 {
                    tracing::info!(
                        rx_pkts,
                        tx_pkts,
                        quic_rx,
                        inner_rx,
                        inner_tx,
                        inner_tx_drop,
                        outer_tx_drop,
                        decrypt_fail,
                        connections = manager.len(),
                        handshakes = multi_state.handshakes.len(),
                        "dpdk engine stats"
                    );
                    last_stats = now;
                }
            }
        }

        // ── Timer-driven ACK generation ─────────────────────────────
        // Rate-limited to avoid calling Instant::now() on every iteration.
        if nb_rx > 0 || nb > 0 {
            ack_poll_counter = ack_poll_counter.wrapping_add(1);
            if ack_poll_counter & 0x3FF == 0 {
                let ack_now = Instant::now();
                if ack_now.duration_since(last_ack) >= ACK_INTERVAL {
                    for entry in manager.values_mut() {
                        if entry.conn.needs_ack() {
                            let ack_delay = entry.queuing_delay_us();
                            if let Ok(result) = entry.conn.encrypt_ack(ack_delay, &mut ack_buf) {
                                let remote_ip = match entry.remote_addr.ip() {
                                    std::net::IpAddr::V4(ip) => ip,
                                    _ => Ipv4Addr::UNSPECIFIED,
                                };
                                let remote_mac = arp_table.lookup(remote_ip).unwrap_or([0xff; 6]);
                                ip_id = ip_id.wrapping_add(1);
                                let frame_len = net::HEADER_SIZE + result.len;
                                if let Ok(mut mbuf) = Mbuf::alloc(mempool) {
                                    if let Ok(buf) = mbuf.alloc_space(frame_len as u16) {
                                        net::build_udp_packet(
                                            &identity.local_mac,
                                            &remote_mac,
                                            identity.local_ip,
                                            remote_ip,
                                            identity.local_port,
                                            entry.remote_addr.port(),
                                            &ack_buf[..result.len],
                                            buf,
                                            0,
                                            ip_id,
                                            checksum_mode,
                                        );
                                        match checksum_mode {
                                            ChecksumMode::HardwareUdpOnly => {
                                                mbuf.set_tx_udp_checksum_offload()
                                            }
                                            ChecksumMode::HardwareFull => {
                                                mbuf.set_tx_full_checksum_offload()
                                            }
                                            _ => {}
                                        }
                                        outer_tx_mbufs.push(mbuf.into_raw());
                                    }
                                }
                            }
                        }
                    }
                    // Flush ACK mbufs.
                    if !outer_tx_mbufs.is_empty() {
                        let nb = outer_tx_mbufs.len() as u16;
                        let sent = port::tx_burst(
                            outer_port_id, queue_id, &mut outer_tx_mbufs, nb,
                        );
                        for &ptr in &outer_tx_mbufs[sent as usize..] {
                            unsafe { ffi::shim_rte_pktmbuf_free(ptr) };
                        }
                        tx_pkts += sent as u64;
                        outer_tx_mbufs.clear();
                    }
                    last_ack = ack_now;
                }
            }
        }

        // ── Adaptive polling: backoff on empty polls ──────────────────
        if adaptive_poll {
            if nb_rx == 0 && nb == 0 {
                empty_polls += 1;
                if empty_polls > EMPTY_POLL_THRESHOLD {
                    std::thread::sleep(Duration::from_micros(delay_us as u64));
                    delay_us = delay_us.saturating_mul(2).min(MAX_DELAY_US);
                }
            } else {
                empty_polls = 0;
                delay_us = MIN_DELAY_US;
            }
        }
    }

    Ok(())
}

/// Drain quinn-proto transmits and send them as Ethernet frames via DPDK.
#[allow(clippy::too_many_arguments)]
fn drain_and_send(
    state: &mut QuicState,
    now: Instant,
    outer_port_id: u16,
    outer_queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    identity: &NetIdentity,
    arp_table: &ArpTable,
    transmit_buf: &mut Vec<u8>,
    tx_count: &mut u64,
    ip_id: &mut u16,
    checksum_mode: ChecksumMode,
) -> Result<()> {
    let Some(conn) = state.connection.as_mut() else {
        return Ok(());
    };

    // Default MAC for handshake transmits — resolved per-transmit below via ARP.
    let dst_mac = [0xff; 6];

    let mut tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::new();

    loop {
        transmit_buf.clear();
        let Some(transmit) = conn.poll_transmit(now, MAX_GSO_SEGMENTS, transmit_buf) else {
            break;
        };

        let data = &transmit_buf[..transmit.size];

        // Determine destination from transmit (uses state remote_addr by default).
        let dst_ip = match transmit.destination {
            SocketAddr::V4(v4) => *v4.ip(),
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let dst_port = transmit.destination.port();
        let actual_dst_mac = arp_table.lookup(dst_ip).unwrap_or(dst_mac);

        // Map quinn ECN codepoint to raw TOS bits.
        let ecn_bits = transmit.ecn.map_or(0u8, |e| e as u8);

        // GSO: when segment_size is set, quinn packed multiple QUIC packets into
        // one transmit buffer. Split them into individual Eth/IP/UDP frames.
        let seg_size = transmit.segment_size.unwrap_or(data.len());

        for chunk in data.chunks(seg_size) {
            *ip_id = ip_id.wrapping_add(1);

            let frame_len = net::HEADER_SIZE + chunk.len();

            // Allocate mbuf and build frame directly into it (zero-copy).
            let mut mbuf = Mbuf::alloc(mempool)?;
            let buf = mbuf.alloc_space(frame_len as u16)?;
            net::build_udp_packet(
                &identity.local_mac,
                &actual_dst_mac,
                identity.local_ip,
                dst_ip,
                identity.local_port,
                dst_port,
                chunk,
                buf,
                ecn_bits,
                *ip_id,
                checksum_mode,
            );
            match checksum_mode {
                ChecksumMode::HardwareUdpOnly => mbuf.set_tx_udp_checksum_offload(),
                ChecksumMode::HardwareFull => mbuf.set_tx_full_checksum_offload(),
                _ => {}
            }
            tx_mbufs.push(mbuf.into_raw());
        }
    }

    if !tx_mbufs.is_empty() {
        let nb = tx_mbufs.len() as u16;
        let sent = port::tx_burst(outer_port_id, outer_queue_id, &mut tx_mbufs, nb);
        *tx_count += sent as u64;

        // Free any mbufs that tx_burst didn't consume.
        for raw in &tx_mbufs[sent as usize..] {
            // SAFETY: tx_burst returned `sent`; mbufs at indices [sent..] were not consumed.
            unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
        }
    }

    Ok(())
}

/// Send pre-built raw Ethernet frames (ARP replies, stateless QUIC responses).
fn send_raw_frames(
    outer_port_id: u16,
    outer_queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    frames: &mut Vec<Vec<u8>>,
    tx_count: &mut u64,
    checksum_mode: ChecksumMode,
) -> Result<()> {
    if frames.is_empty() {
        return Ok(());
    }

    let mut tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(frames.len());

    for frame in frames.iter() {
        let mut mbuf = Mbuf::alloc(mempool)?;
        mbuf.write_packet(frame)?;
        match checksum_mode {
            ChecksumMode::HardwareUdpOnly => mbuf.set_tx_udp_checksum_offload(),
            ChecksumMode::HardwareFull => mbuf.set_tx_full_checksum_offload(),
            _ => {}
        }
        tx_mbufs.push(mbuf.into_raw());
    }

    let nb = tx_mbufs.len() as u16;
    let sent = port::tx_burst(outer_port_id, outer_queue_id, &mut tx_mbufs, nb);
    *tx_count += sent as u64;

    for raw in &tx_mbufs[sent as usize..] {
        // SAFETY: unsent mbufs are still owned by us.
        unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
    }

    frames.clear();
    Ok(())
}

/// Result from handshake-only phase.
pub struct HandshakeResult {
    /// quictun-proto connection state for the data plane.
    pub conn_state: LocalConnectionState,
    /// Learned network identity (peer MAC, ports, etc.).
    pub identity: NetIdentity,
    /// Learned ARP entries.
    pub arp_table: ArpTable,
}

/// Run only the QUIC handshake on core 0, then return.
///
/// Handles ARP resolution, quinn-proto state machine, and key extraction.
/// Returns `HandshakeResult` on success — caller spawns worker threads.
#[allow(clippy::too_many_arguments)]
pub fn run_handshake_only(
    outer_port_id: u16,
    queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    state: &mut QuicState,
    identity: &NetIdentity,
    arp_table: &mut ArpTable,
    inner: &InnerPort,
    shutdown: &AtomicBool,
    checksum_mode: ChecksumMode,
) -> Result<HandshakeResult> {
    let mut response_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut drive_result = DriveResult::new();
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut pkt_buf = [0u8; 2048];
    let mut deadline = Instant::now() + Duration::from_secs(1);
    let mut ip_id: u16 = 0;
    let mut rx_buf = BytesMut::with_capacity(2048);
    let mut pending_frames: Vec<Vec<u8>> = Vec::new();
    let mut tx_pkts: u64 = 0;

    // If connector, drain initial handshake transmits.
    drain_and_send(
        state,
        Instant::now(),
        outer_port_id,
        queue_id,
        mempool,
        identity,
        arp_table,
        &mut transmit_buf,
        &mut tx_pkts,
        &mut ip_id,
        checksum_mode,
    )?;

    tracing::info!("handshake phase started (core 0)");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            anyhow::bail!("shutdown during handshake");
        }

        let now = Instant::now();

        // RX burst: process ARP + QUIC long headers
        let mut rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
        let nb_rx = port::rx_burst(outer_port_id, queue_id, &mut rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_rx as usize {
            let mbuf = unsafe { Mbuf::from_raw(rx_mbufs[i]) };
            let data = mbuf.data();

            match net::parse_packet(data) {
                Some(ParsedPacket::Udp(udp)) => {
                    if udp.dst_ip != identity.local_ip || udp.dst_port != identity.local_port {
                        continue;
                    }
                    arp_table.learn(udp.src_ip, udp.src_mac);
                    state.remote_addr = SocketAddr::new(udp.src_ip.into(), udp.src_port);

                    if udp.payload.is_empty() {
                        continue;
                    }
                    let first_byte = udp.payload[0];
                    if first_byte & 0x80 != 0 {
                        // Long header → quinn-proto
                        rx_buf.clear();
                        rx_buf.extend_from_slice(udp.payload);
                        let quic_data = rx_buf.split();
                        let remote_addr = SocketAddr::new(udp.src_ip.into(), udp.src_port);
                        if let Some(event) = state.endpoint.handle(
                            now,
                            remote_addr,
                            None,
                            udp.ecn,
                            quic_data,
                            &mut response_buf,
                        ) {
                            let responses =
                                shared::handle_datagram_event(state, event, &mut response_buf);
                            for buf in responses {
                                let dst_mac = arp_table
                                    .lookup(udp.src_ip)
                                    .unwrap_or(udp.src_mac);
                                ip_id = ip_id.wrapping_add(1);
                                let frame_len = net::build_udp_packet(
                                    &identity.local_mac,
                                    &dst_mac,
                                    identity.local_ip,
                                    udp.src_ip,
                                    identity.local_port,
                                    udp.src_port,
                                    &buf,
                                    &mut pkt_buf,
                                    0,
                                    ip_id,
                                    checksum_mode,
                                );
                                pending_frames.push(pkt_buf[..frame_len].to_vec());
                            }
                        }
                    }
                }
                Some(ParsedPacket::Arp(arp)) => {
                    arp_table.learn(arp.sender_ip, arp.sender_mac);
                    if arp.is_request && arp.target_ip == identity.local_ip {
                        let reply =
                            net::build_arp_reply(&arp, identity.local_mac, identity.local_ip);
                        pending_frames.push(reply);
                    }
                }
                Some(ParsedPacket::Ipv4Raw(_)) | None => {}
            }
        }

        // Handle inner ARP during handshake
        let mut inner_rx_mbufs: [*mut ffi::rte_mbuf; 8] = [std::ptr::null_mut(); 8];
        let nb_inner = port::rx_burst(inner.port_id, 0, &mut inner_rx_mbufs, 8);
        for i in 0..nb_inner as usize {
            let mbuf = unsafe { Mbuf::from_raw(inner_rx_mbufs[i]) };
            let data = mbuf.data();
            if data.len() >= ETH_HLEN {
                let ethertype = u16::from_be_bytes([data[12], data[13]]);
                if ethertype == 0x0806 {
                    if let Some(ParsedPacket::Arp(arp)) = net::parse_packet(data) {
                        if arp.is_request {
                            let inner_mac: [u8; 6] = inner.eth_hdr.bytes[6..12]
                                .try_into()
                                .expect("eth_hdr always 14 bytes");
                            let reply = net::build_arp_reply(&arp, inner_mac, arp.target_ip);
                            if let Ok(mut reply_mbuf) = Mbuf::alloc(mempool) {
                                if reply_mbuf.write_packet(&reply).is_ok() {
                                    let raw = reply_mbuf.into_raw();
                                    let mut tx = [raw];
                                    let sent = port::tx_burst(inner.port_id, 0, &mut tx, 1);
                                    if sent == 0 {
                                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // quinn-proto state machine
        if now >= deadline {
            if let Some(conn) = state.connection.as_mut() {
                conn.handle_timeout(now);
            }
        }

        shared::process_events(state, &mut drive_result);

        // Check for connected
        if drive_result.connected {
            if let Some(cs) = drive_result.connection_state.take() {
                tracing::info!("handshake complete (quictun-proto data plane ready)");
                // Drain any remaining handshake transmits
                drain_and_send(
                    state,
                    now,
                    outer_port_id,
                    queue_id,
                    mempool,
                    identity,
                    arp_table,
                    &mut transmit_buf,
                    &mut tx_pkts,
                    &mut ip_id,
                    checksum_mode,
                )?;
                send_raw_frames(
                    outer_port_id,
                    queue_id,
                    mempool,
                    &mut pending_frames,
                    &mut tx_pkts,
                    checksum_mode,
                )?;
                return Ok(HandshakeResult {
                    conn_state: cs,
                    identity: identity.clone(),
                    arp_table: arp_table.clone(),
                });
            }
            tracing::info!("tunnel established but no quictun-proto keys — cannot use multi-core");
            anyhow::bail!("multi-core requires quictun-proto keys");
        }
        if drive_result.connection_lost {
            anyhow::bail!("connection lost during handshake");
        }

        drain_and_send(
            state,
            now,
            outer_port_id,
            queue_id,
            mempool,
            identity,
            arp_table,
            &mut transmit_buf,
            &mut tx_pkts,
            &mut ip_id,
            checksum_mode,
        )?;

        send_raw_frames(
            outer_port_id,
            queue_id,
            mempool,
            &mut pending_frames,
            &mut tx_pkts,
            checksum_mode,
        )?;

        deadline = if let Some(conn) = state.connection.as_mut() {
            conn.poll_timeout().unwrap_or(now + Duration::from_secs(1))
        } else {
            now + Duration::from_secs(1)
        };
    }
}

// ── Multi-client dispatcher + worker loops ──────────────────────────────

use crate::dispatch::{ControlMessage, DpdkDispatchTable, WorkerRings};

/// Run the multi-client dispatcher on core 0.
///
/// Core 0 reads all outer and inner RX, dispatches to workers via SPSC rings,
/// collects inner TX from workers for inner port, and drives handshakes.
#[allow(clippy::too_many_arguments)]
pub fn run_dispatcher(
    outer_port_id: u16,
    mempool: *mut ffi::rte_mempool,
    multi_state: &mut MultiQuicState,
    dispatch_table: &mut DpdkDispatchTable,
    workers: &[WorkerRings],
    identity: &NetIdentity,
    arp_table: &mut ArpTable,
    inner: &InnerPort,
    peers: &[PeerConfig],
    shutdown: &AtomicBool,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
) -> Result<()> {
    let mut response_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut pkt_buf = [0u8; 2048];
    let mut ip_id: u16 = 0;
    let mut rx_buf = BytesMut::with_capacity(2048);
    let mut pending_frames: Vec<Vec<u8>> = Vec::new();

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut dispatch_miss: u64 = 0;
    let mut last_stats = Instant::now();

    // Adaptive polling state.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    // Reusable mbuf array for collecting inner TX from workers.
    let mut inner_tx_collect: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];

    tracing::info!(n_workers = workers.len(), "dispatcher started on core 0");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("dispatcher: shutdown signal received");
            break;
        }

        if !multi_state.handshakes.is_empty() {
            now = Instant::now();
        }
        let mut had_work = false;

        // ── 1. Outer RX burst → dispatch by CID or feed handshake ──

        let mut rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
        let nb_rx = port::rx_burst(outer_port_id, 0, &mut rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_rx as usize {
            let mbuf = unsafe { Mbuf::from_raw(rx_mbufs[i]) };
            rx_pkts += 1;
            let data = mbuf.data();

            match net::parse_packet(data) {
                Some(ParsedPacket::Udp(udp)) => {
                    if udp.payload.is_empty() {
                        continue;
                    }

                    arp_table.learn(udp.src_ip, udp.src_mac);

                    let first_byte = udp.payload[0];
                    if first_byte & 0x80 == 0 {
                        // Short header → dispatch by CID.
                        let cid_offset = 1; // first byte of CID after header byte
                        // CID length: use endpoint's expected CID length (default 8).
                        let cid_len = 8usize; // TODO: make configurable
                        if udp.payload.len() >= 1 + cid_len {
                            let cid_bytes = &udp.payload[cid_offset..cid_offset + cid_len];
                            if let Some(worker_id) = dispatch_table.lookup_cid(cid_bytes) {
                                // Enqueue raw mbuf to worker. Worker decrypts in-place.
                                let raw = mbuf.into_raw();
                                if !workers[worker_id].outer_rx.enqueue(raw) {
                                    // Ring full — drop packet.
                                    unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                }
                            } else {
                                dispatch_miss += 1;
                            }
                        }
                    } else {
                        // Long header → handshake via quinn-proto.
                        rx_buf.clear();
                        rx_buf.extend_from_slice(udp.payload);
                        let quic_data = rx_buf.split();
                        let remote_addr = SocketAddr::new(udp.src_ip.into(), udp.src_port);

                        let responses = multi_state.handle_incoming(
                            now,
                            remote_addr,
                            udp.ecn,
                            quic_data,
                            &mut response_buf,
                        );

                        for buf in responses {
                            let dst_mac = arp_table
                                .lookup(udp.src_ip)
                                .unwrap_or(udp.src_mac);
                            ip_id = ip_id.wrapping_add(1);
                            let frame_len = net::build_udp_packet(
                                &identity.local_mac,
                                &dst_mac,
                                identity.local_ip,
                                udp.src_ip,
                                identity.local_port,
                                udp.src_port,
                                &buf,
                                &mut pkt_buf,
                                0,
                                ip_id,
                                checksum_mode,
                            );
                            pending_frames.push(pkt_buf[..frame_len].to_vec());
                        }
                    }
                }
                Some(ParsedPacket::Arp(arp)) => {
                    arp_table.learn(arp.sender_ip, arp.sender_mac);
                    if arp.is_request && arp.target_ip == identity.local_ip {
                        let reply =
                            net::build_arp_reply(&arp, identity.local_mac, identity.local_ip);
                        pending_frames.push(reply);
                    }
                }
                Some(ParsedPacket::Ipv4Raw(_)) | None => {}
            }
        }

        if nb_rx > 0 {
            had_work = true;
        }

        // ── 2. Inner RX burst → dispatch by dest IP ──

        let mut inner_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] =
            [std::ptr::null_mut(); BURST_SIZE];
        let nb_inner = port::rx_burst(inner.port_id, 0, &mut inner_rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_inner as usize {
            let mbuf = unsafe { Mbuf::from_raw(inner_rx_mbufs[i]) };
            let data = mbuf.data();

            if data.len() < ETH_HLEN {
                continue;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            match ethertype {
                0x0800 => {
                    // IPv4: extract dest IP, dispatch to worker.
                    if data.len() >= ETH_HLEN + 20 {
                        let dst_ip = Ipv4Addr::new(
                            data[ETH_HLEN + 16],
                            data[ETH_HLEN + 17],
                            data[ETH_HLEN + 18],
                            data[ETH_HLEN + 19],
                        );
                        if let Some(worker_id) = dispatch_table.lookup_ip(dst_ip) {
                            let raw = mbuf.into_raw();
                            if !workers[worker_id].inner_rx.enqueue(raw) {
                                unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                            }
                        }
                        // No route = drop (unknown dest IP).
                    }
                }
                0x0806 => {
                    // Inner ARP reply.
                    if let Some(ParsedPacket::Arp(arp)) = net::parse_packet(data) {
                        if arp.is_request {
                            let inner_mac: [u8; 6] = inner.eth_hdr.bytes[6..12]
                                .try_into()
                                .expect("eth_hdr always 14 bytes");
                            let reply = net::build_arp_reply(&arp, inner_mac, arp.target_ip);
                            if let Ok(mut reply_mbuf) = Mbuf::alloc(mempool) {
                                if reply_mbuf.write_packet(&reply).is_ok() {
                                    let raw = reply_mbuf.into_raw();
                                    let mut tx = [raw];
                                    let sent = port::tx_burst(inner.port_id, 0, &mut tx, 1);
                                    if sent == 0 {
                                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if nb_inner > 0 {
            had_work = true;
        }

        // ── 3. Drain worker inner_tx rings → inner port TX ──

        for worker in workers {
            let nb = worker.inner_tx.dequeue_burst(&mut inner_tx_collect);
            if nb > 0 {
                had_work = true;
                let sent = port::tx_burst(
                    inner.port_id,
                    0,
                    &mut inner_tx_collect[..nb as usize],
                    nb as u16,
                );
                for j in sent as usize..nb as usize {
                    unsafe { ffi::shim_rte_pktmbuf_free(inner_tx_collect[j]) };
                }
            }
        }

        // Refresh `now` only when there was actual work (skip clock_gettime on idle polls).
        if multi_state.handshakes.is_empty() && had_work {
            now = Instant::now();
        }

        // ── 4. Drive handshakes (skip entirely when no handshakes in progress) ──

        if !multi_state.handshakes.is_empty() {
            let drive_result = multi_state.poll_handshakes();

            for ch in drive_result.completed {
                if let Some((mut hs, conn_state)) = multi_state.extract_connection(ch) {
                    let Some(resolved) =
                        resolve_completed_handshake(&hs, conn_state, peers, identity, arp_table)
                    else {
                        continue;
                    };

                    // Assign to least-loaded worker.
                    let worker_id = dispatch_table.least_loaded_worker();
                    dispatch_table.register_cid_raw(&resolved.cid_bytes, worker_id);
                    dispatch_table.add_route(resolved.tunnel_ip, worker_id);

                    // Drain final handshake transmits.
                    drain_handshake_transmits(
                        &mut hs.connection,
                        now,
                        outer_port_id,
                        0,
                        mempool,
                        identity,
                        arp_table,
                        &mut transmit_buf,
                        &mut tx_pkts,
                        &mut ip_id,
                        checksum_mode,
                    );

                    // Send control message to worker.
                    if let Ok(mut ctrl) = workers[worker_id].control.lock() {
                        ctrl.push(ControlMessage::AddConnection {
                            conn: resolved.conn,
                            tunnel_ip: resolved.tunnel_ip,
                            remote_addr: resolved.remote_addr,
                            remote_mac: resolved.remote_mac,
                        });
                    }

                    tracing::info!(
                        tunnel_ip = %resolved.tunnel_ip,
                        worker = worker_id,
                        cid = %hex::encode(&resolved.cid_bytes),
                        "connection assigned to worker"
                    );
                }
            }

            // Drain handshake transmits for in-progress connections.
            for hs in multi_state.handshakes.values_mut() {
                drain_handshake_transmits(
                    &mut hs.connection,
                    now,
                    outer_port_id,
                    0,
                    mempool,
                    identity,
                    arp_table,
                    &mut transmit_buf,
                    &mut tx_pkts,
                    &mut ip_id,
                    checksum_mode,
                );
            }

            // Handle timeouts.
            for hs in multi_state.handshakes.values_mut() {
                let timeout = hs.connection.poll_timeout();
                if let Some(t) = timeout {
                    if now >= t {
                        hs.connection.handle_timeout(now);
                    }
                }
            }
        }

        // ── 5. Send pending raw frames ──
        send_raw_frames(outer_port_id, 0, mempool, &mut pending_frames, &mut tx_pkts, checksum_mode)?;

        // ── Stats ──
        if now.duration_since(last_stats).as_secs() >= 2 {
            tracing::info!(
                rx_pkts,
                tx_pkts,
                dispatch_miss,
                handshakes = multi_state.handshakes.len(),
                "dispatcher stats"
            );
            last_stats = now;
        }

        // ── Adaptive polling ──
        if adaptive_poll {
            if !had_work {
                empty_polls += 1;
                if empty_polls > EMPTY_POLL_THRESHOLD {
                    std::thread::sleep(Duration::from_micros(delay_us as u64));
                    delay_us = delay_us.saturating_mul(2).min(MAX_DELAY_US);
                }
            } else {
                empty_polls = 0;
                delay_us = MIN_DELAY_US;
            }
        }
    }

    Ok(())
}

/// Drain transmits from a quinn-proto connection during handshake.
#[allow(clippy::too_many_arguments)]
fn drain_handshake_transmits(
    conn: &mut quinn_proto::Connection,
    now: Instant,
    outer_port_id: u16,
    queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    identity: &NetIdentity,
    arp_table: &ArpTable,
    transmit_buf: &mut Vec<u8>,
    tx_count: &mut u64,
    ip_id: &mut u16,
    checksum_mode: ChecksumMode,
) {
    loop {
        transmit_buf.clear();
        let Some(transmit) = conn.poll_transmit(now, MAX_GSO_SEGMENTS, transmit_buf) else {
            break;
        };
        let data = &transmit_buf[..transmit.size];

        // Use transmit.destination for per-connection addressing (multi-client safe).
        let dst_ip = match transmit.destination {
            SocketAddr::V4(v4) => *v4.ip(),
            _ => Ipv4Addr::UNSPECIFIED,
        };
        let dst_port = transmit.destination.port();
        let dst_mac = arp_table.lookup(dst_ip).unwrap_or([0xff; 6]);

        let seg_size = transmit.segment_size.unwrap_or(data.len());

        for chunk in data.chunks(seg_size) {
            *ip_id = ip_id.wrapping_add(1);
            let frame_len = net::HEADER_SIZE + chunk.len();
            if let Ok(mut mbuf) = Mbuf::alloc(mempool) {
                if let Ok(buf) = mbuf.alloc_space(frame_len as u16) {
                    net::build_udp_packet(
                        &identity.local_mac,
                        &dst_mac,
                        identity.local_ip,
                        dst_ip,
                        identity.local_port,
                        dst_port,
                        chunk,
                        buf,
                        0,
                        *ip_id,
                        checksum_mode,
                    );
                    match checksum_mode {
                        ChecksumMode::HardwareUdpOnly => mbuf.set_tx_udp_checksum_offload(),
                        ChecksumMode::HardwareFull => mbuf.set_tx_full_checksum_offload(),
                        _ => {}
                    }
                    let raw = mbuf.into_raw();
                    let mut tx = [raw];
                    let sent = port::tx_burst(outer_port_id, queue_id, &mut tx, 1);
                    *tx_count += sent as u64;
                    if sent == 0 {
                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                    }
                }
            }
        }
    }
}

/// Run a multi-client worker on a dedicated core.
///
/// Each worker owns per-connection `LocalConnectionState` (no sharing).
/// Receives mbufs from dispatcher via SPSC rings, encrypts/decrypts, and
/// TX directly to outer port on its own TX queue.
#[allow(clippy::too_many_arguments)]
pub fn run_worker(
    outer_port_id: u16,
    tx_queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    rings: &WorkerRings,
    inner_eth_hdr: &InnerEthHeader,
    identity: &NetIdentity,
    shutdown: &AtomicBool,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    core_id: usize,
) -> Result<()> {
    // Per-connection state: CID (as u64) → connection entry.
    let mut connections: FxHashMap<u64, ConnectionEntry> = FxHashMap::default();
    // IP → CID (as u64) lookup for inner RX routing.
    let mut ip_to_cid: FxHashMap<Ipv4Addr, u64> = FxHashMap::default();

    let mut ip_id: u16 = (core_id as u16).wrapping_mul(10000);

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut inner_rx: u64 = 0;
    let mut decrypt_fail: u64 = 0;
    let mut last_stats = Instant::now();

    // Adaptive polling.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    // Reusable mbuf arrays.
    let mut outer_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
    let mut inner_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
    let mut outer_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);
    let mut inner_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);

    tracing::info!(core = core_id, tx_queue = tx_queue_id, "worker started");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!(core = core_id, "worker: shutdown signal received");
            break;
        }

        let mut had_work = false;

        // ── 0. Check control channel ──
        if let Ok(mut ctrl) = rings.control.try_lock() {
            for msg in ctrl.drain(..) {
                match msg {
                    ControlMessage::AddConnection {
                        conn,
                        tunnel_ip,
                        remote_addr,
                        remote_mac,
                    } => {
                        let cid_bytes = conn.local_cid().to_vec();
                        let cid = cid_to_u64(&cid_bytes);
                        tracing::info!(
                            core = core_id,
                            tunnel_ip = %tunnel_ip,
                            cid = %hex::encode(&cid_bytes),
                            "worker: added connection"
                        );
                        ip_to_cid.insert(tunnel_ip, cid);
                        connections.insert(
                            cid,
                            ConnectionEntry {
                                conn,
                                tunnel_ip,
                                remote_addr,
                                remote_mac,
                            },
                        );
                    }
                    ControlMessage::RemoveConnection { cid } => {
                        let key = cid_to_u64(cid.as_ref());
                        if let Some(entry) = connections.remove(&key) {
                            ip_to_cid.remove(&entry.tunnel_ip);
                            tracing::info!(
                                core = core_id,
                                tunnel_ip = %entry.tunnel_ip,
                                "worker: removed connection"
                            );
                        }
                    }
                    ControlMessage::AddRouterConnection { .. }
                    | ControlMessage::PeerAssignment { .. } => {
                        // Not used in engine mode.
                    }
                }
            }
        }

        // ── 1. Outer RX: dequeue from ring → decrypt → enqueue inner TX ──

        let nb_rx = rings.outer_rx.dequeue_burst(&mut outer_rx_mbufs);
        inner_tx_mbufs.clear();

        for i in 0..nb_rx as usize {
            let mut mbuf = unsafe { Mbuf::from_raw(outer_rx_mbufs[i]) };
            rx_pkts += 1;
            let data = mbuf.data_mut();

            // Parse to get UDP payload.
            let Some(ParsedPacket::Udp(udp)) = net::parse_packet(data) else {
                continue;
            };
            if udp.payload.is_empty() || udp.payload[0] & 0x80 != 0 {
                continue;
            }
            let src_mac = udp.src_mac;
            let src_ip = udp.src_ip;
            let src_port = udp.src_port;

            let payload_offset =
                unsafe { udp.payload.as_ptr().offset_from(data.as_ptr()) as usize };
            let payload_len = udp.payload.len();

            // Extract CID to find connection.
            let cid_len = 8usize; // TODO: make configurable
            if payload_len < 1 + cid_len {
                continue;
            }
            let cid_key = cid_to_u64(&data[payload_offset + 1..payload_offset + 1 + cid_len]);

            let Some(entry) = connections.get_mut(&cid_key) else {
                decrypt_fail += 1;
                continue;
            };

            match entry
                .conn
                .decrypt_packet_in_place(&mut data[payload_offset..payload_offset + payload_len])
            {
                Ok(decrypted) => {
                    // Update peer address on every authenticated packet.
                    entry.remote_addr = SocketAddr::new(src_ip.into(), src_port);
                    entry.remote_mac = src_mac;

                    if let Some(ref ack) = decrypted.ack {
                        entry.conn.process_ack(ack);
                        // Note: ConnectionEntry doesn't have CC state — on_ack is
                        // on ConnEntry in the pipeline I/O thread's manager instead.
                    }
                    for range in &decrypted.datagrams {
                        let abs_start = payload_offset + range.start;
                        let abs_end = payload_offset + range.end;
                        let datagram_len = abs_end - abs_start;
                        let frame_len = ETH_HLEN + datagram_len;
                        if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
                            if let Ok(buf) = out_mbuf.alloc_space(frame_len as u16) {
                                buf[..ETH_HLEN].copy_from_slice(&inner_eth_hdr.bytes);
                                buf[ETH_HLEN..frame_len].copy_from_slice(&data[abs_start..abs_end]);
                                inner_tx_mbufs.push(out_mbuf.into_raw());
                            }
                        }
                    }
                }
                Err(_) => {
                    decrypt_fail += 1;
                }
            }
        }

        if nb_rx > 0 {
            had_work = true;
        }

        // Enqueue inner TX mbufs back to dispatcher via ring.
        if !inner_tx_mbufs.is_empty() {
            let enqueued = rings.inner_tx.enqueue_burst(&inner_tx_mbufs);
            // Free any that didn't fit.
            for j in enqueued as usize..inner_tx_mbufs.len() {
                unsafe { ffi::shim_rte_pktmbuf_free(inner_tx_mbufs[j]) };
            }
        }

        // ── 2. Inner RX: dequeue from ring → encrypt → TX directly to outer port ──

        let nb_inner = rings.inner_rx.dequeue_burst(&mut inner_rx_mbufs);
        outer_tx_mbufs.clear();

        for i in 0..nb_inner as usize {
            let mbuf = unsafe { Mbuf::from_raw(inner_rx_mbufs[i]) };
            let data = mbuf.data();
            if data.len() < ETH_HLEN + 20 {
                continue;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            if ethertype != 0x0800 {
                continue;
            }

            inner_rx += 1;
            let ip_payload = &data[ETH_HLEN..];

            // Find connection by dest IP.
            let dst_ip = Ipv4Addr::new(
                data[ETH_HLEN + 16],
                data[ETH_HLEN + 17],
                data[ETH_HLEN + 18],
                data[ETH_HLEN + 19],
            );
            let Some(&cid) = ip_to_cid.get(&dst_ip) else {
                continue;
            };
            let Some(entry) = connections.get_mut(&cid) else {
                continue;
            };

            let max_quic_len =
                1 + entry.conn.remote_cid().len() + 4 + 1 + ip_payload.len() + entry.conn.tag_len();
            let max_frame_len = net::HEADER_SIZE + max_quic_len;
            let Ok(max_frame_len_u16) = u16::try_from(max_frame_len) else {
                continue;
            };

            if let Ok(mut tx_mbuf) = Mbuf::alloc(mempool) {
                if let Ok(buf) = tx_mbuf.alloc_space(max_frame_len_u16) {
                    match entry.conn.encrypt_datagram(
                        ip_payload,
                        &mut buf[net::HEADER_SIZE..],
                        None,
                    ) {
                        Ok(result) => {
                            let remote_ip = match entry.remote_addr.ip() {
                                std::net::IpAddr::V4(ip) => ip,
                                _ => Ipv4Addr::UNSPECIFIED,
                            };
                            ip_id = ip_id.wrapping_add(1);
                            let actual_len = net::build_udp_packet_inplace(
                                &identity.local_mac,
                                &entry.remote_mac,
                                identity.local_ip,
                                remote_ip,
                                identity.local_port,
                                entry.remote_addr.port(),
                                result.len,
                                buf,
                                0,
                                ip_id,
                                checksum_mode,
                            );
                            tx_mbuf.truncate(actual_len as u16);
                            match checksum_mode {
                                ChecksumMode::HardwareUdpOnly => {
                                    tx_mbuf.set_tx_udp_checksum_offload()
                                }
                                ChecksumMode::HardwareFull => {
                                    tx_mbuf.set_tx_full_checksum_offload()
                                }
                                _ => {}
                            }
                            outer_tx_mbufs.push(tx_mbuf.into_raw());
                        }
                        Err(e) => {
                            tracing::trace!(core = core_id, error = %e, "encrypt failed");
                        }
                    }
                }
            }
        }

        if nb_inner > 0 {
            had_work = true;
        }

        // TX directly to outer port on this worker's queue.
        if !outer_tx_mbufs.is_empty() {
            let nb_tx = outer_tx_mbufs.len() as u16;
            let sent = port::tx_burst(outer_port_id, tx_queue_id, &mut outer_tx_mbufs, nb_tx);
            tx_pkts += sent as u64;
            for j in sent as usize..outer_tx_mbufs.len() {
                unsafe { ffi::shim_rte_pktmbuf_free(outer_tx_mbufs[j]) };
            }
        }

        // ── Stats ──
        if had_work {
            now = Instant::now();
        }
        if now.duration_since(last_stats).as_secs() >= 2 {
            tracing::info!(
                core = core_id,
                rx_pkts,
                tx_pkts,
                inner_rx,
                decrypt_fail,
                connections = connections.len(),
                "worker stats"
            );
            last_stats = now;
        }

        // ── Adaptive polling ──
        if adaptive_poll {
            if !had_work {
                empty_polls += 1;
                if empty_polls > EMPTY_POLL_THRESHOLD {
                    std::thread::sleep(Duration::from_micros(delay_us as u64));
                    delay_us = delay_us.saturating_mul(2).min(MAX_DELAY_US);
                }
            } else {
                empty_polls = 0;
                delay_us = MIN_DELAY_US;
            }
        }
    }

    Ok(())
}

// ── Pipeline architecture (SharedConnectionState) ──────────────────────
//
// Core 0 = I/O thread (RX/TX, handshake, ACK, keepalive, key rotation).
// Workers 1..N = crypto workers (decrypt/encrypt via SharedConnectionState).
// Packets are round-robin distributed — any worker processes any connection.

use crate::dispatch::{PipelineConnection, PipelineControlMessage};
use quictun_proto::shared::SharedConnectionState;

/// ACK generation interval.
const ACK_INTERVAL: Duration = Duration::from_millis(25);

/// Run the pipeline I/O thread on core 0.
///
/// Core 0 responsibilities:
/// - Outer RX: parse packets, send handshakes to quinn-proto, round-robin
///   short header packets to workers via `decrypt_rx` rings.
/// - Inner RX: read from TAP, round-robin to workers via `encrypt_rx` rings.
/// - Inner TX: drain `inner_tx` rings from workers → TX to TAP.
/// - Handshake: drive MultiQuicState for new connections.
/// - ACK: periodically generate and send ACKs for each connection.
/// - Keepalive: send empty datagrams periodically.
/// - Key rotation: call `maybe_initiate_key_update` based on dispatch count.
#[allow(clippy::too_many_arguments)]
pub fn run_pipeline_io(
    outer_port_id: u16,
    mempool: *mut ffi::rte_mempool,
    multi_state: &mut MultiQuicState,
    workers: &[PipelineRings],
    identity: &NetIdentity,
    arp_table: &mut ArpTable,
    inner: &InnerPort,
    peers: &[PeerConfig],
    shutdown: &AtomicBool,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    tunnel_ip: Ipv4Addr,
    max_peers: usize,
    idle_timeout: Duration,
    rate_control_config: Option<quictun_proto::rate_control::RateControlConfig>,
) -> Result<()> {
    let n_workers = workers.len();

    let mut response_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut pkt_buf = [0u8; 2048];
    let mut ack_buf = [0u8; 256];
    let mut ip_id: u16 = 0;
    let mut rx_buf = BytesMut::with_capacity(2048);
    let mut pending_frames: Vec<Vec<u8>> = Vec::new();

    // Connection table on core 0 (for ACK/keepalive/key rotation).
    let mut manager = ConnectionManager::<Arc<SharedConnectionState>>::new(
        tunnel_ip,
        false,
        max_peers,
        idle_timeout,
    );

    // Round-robin counter for worker dispatch.
    let mut rr_decrypt: usize = 0;
    let mut rr_encrypt: usize = 0;

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut inner_rx_pkts: u64 = 0;
    let mut inner_tx_pkts: u64 = 0;
    let mut dispatch_drop: u64 = 0;
    let mut last_stats = Instant::now();

    // Timer state.
    let mut last_ack = Instant::now();

    // Adaptive polling state.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    // Reusable mbuf arrays for collecting TX from workers.
    let mut inner_tx_collect: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
    let mut outer_tx_collect: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];

    tracing::info!(n_workers, "pipeline I/O started on core 0");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("pipeline I/O: shutdown signal received");
            break;
        }

        // During handshake, quinn-proto needs accurate time every iteration.
        // After all handshakes complete, skip clock_gettime (saves ~4% CPU).
        if !multi_state.handshakes.is_empty() {
            now = Instant::now();
        }
        let mut had_work = false;

        // ── 1. Outer RX burst → classify → round-robin to workers or handshake ──

        let mut rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
        let nb_rx = port::rx_burst(outer_port_id, 0, &mut rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_rx as usize {
            let mbuf = unsafe { Mbuf::from_raw(rx_mbufs[i]) };
            rx_pkts += 1;
            let data = mbuf.data();

            match net::parse_packet(data) {
                Some(ParsedPacket::Udp(udp)) => {
                    if udp.payload.is_empty() {
                        continue;
                    }

                    arp_table.learn(udp.src_ip, udp.src_mac);

                    // Filter: only process packets destined for our IP:port.
                    if udp.dst_ip != identity.local_ip || udp.dst_port != identity.local_port {
                        continue;
                    }

                    let first_byte = udp.payload[0];
                    if first_byte & 0x80 == 0 {
                        // Short header → round-robin to worker's decrypt_rx.
                        let worker_id = rr_decrypt % n_workers;
                        rr_decrypt = rr_decrypt.wrapping_add(1);
                        let raw = mbuf.into_raw();
                        if !workers[worker_id].decrypt_rx.enqueue(raw) {
                            unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                            dispatch_drop += 1;
                        }
                    } else {
                        // Long header → handshake via quinn-proto.
                        rx_buf.clear();
                        rx_buf.extend_from_slice(udp.payload);
                        let quic_data = rx_buf.split();
                        let remote_addr = SocketAddr::new(udp.src_ip.into(), udp.src_port);

                        let responses = multi_state.handle_incoming(
                            now,
                            remote_addr,
                            udp.ecn,
                            quic_data,
                            &mut response_buf,
                        );

                        for buf in responses {
                            let dst_mac = arp_table
                                .lookup(udp.src_ip)
                                .unwrap_or(udp.src_mac);
                            ip_id = ip_id.wrapping_add(1);
                            let frame_len = net::build_udp_packet(
                                &identity.local_mac,
                                &dst_mac,
                                identity.local_ip,
                                udp.src_ip,
                                identity.local_port,
                                udp.src_port,
                                &buf,
                                &mut pkt_buf,
                                0,
                                ip_id,
                                checksum_mode,
                            );
                            pending_frames.push(pkt_buf[..frame_len].to_vec());
                        }
                    }
                }
                Some(ParsedPacket::Arp(arp)) => {
                    arp_table.learn(arp.sender_ip, arp.sender_mac);
                    if arp.is_request && arp.target_ip == identity.local_ip {
                        let reply =
                            net::build_arp_reply(&arp, identity.local_mac, identity.local_ip);
                        pending_frames.push(reply);
                    }
                }
                Some(ParsedPacket::Ipv4Raw(_)) | None => {}
            }
        }

        if nb_rx > 0 {
            had_work = true;
        }

        // ── 2. Inner RX burst → round-robin to workers' encrypt_rx ──

        let mut inner_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] =
            [std::ptr::null_mut(); BURST_SIZE];
        let nb_inner = port::rx_burst(inner.port_id, 0, &mut inner_rx_mbufs, INNER_BURST_SIZE);
        inner_rx_pkts += nb_inner as u64;

        for i in 0..nb_inner as usize {
            let mbuf = unsafe { Mbuf::from_raw(inner_rx_mbufs[i]) };
            let data = mbuf.data();

            if data.len() < ETH_HLEN {
                continue;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            match ethertype {
                0x0800 => {
                    // IPv4: round-robin to worker's encrypt_rx.
                    let worker_id = rr_encrypt % n_workers;
                    rr_encrypt = rr_encrypt.wrapping_add(1);
                    let raw = mbuf.into_raw();
                    if !workers[worker_id].encrypt_rx.enqueue(raw) {
                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                        dispatch_drop += 1;
                    }
                }
                0x0806 => {
                    // Inner ARP reply.
                    if let Some(ParsedPacket::Arp(arp)) = net::parse_packet(data) {
                        if arp.is_request {
                            let inner_mac: [u8; 6] = inner.eth_hdr.bytes[6..12]
                                .try_into()
                                .expect("eth_hdr always 14 bytes");
                            let reply = net::build_arp_reply(&arp, inner_mac, arp.target_ip);
                            if let Ok(mut reply_mbuf) = Mbuf::alloc(mempool) {
                                if reply_mbuf.write_packet(&reply).is_ok() {
                                    let raw = reply_mbuf.into_raw();
                                    let mut tx = [raw];
                                    let sent = port::tx_burst(inner.port_id, 0, &mut tx, 1);
                                    if sent == 0 {
                                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                    }
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if nb_inner > 0 {
            had_work = true;
        }

        // ── 3. Drain worker inner_tx rings → inner port TX ──

        for worker in workers {
            let nb = worker.inner_tx.dequeue_burst(&mut inner_tx_collect);
            if nb > 0 {
                had_work = true;
                let sent = port::tx_burst(
                    inner.port_id,
                    0,
                    &mut inner_tx_collect[..nb as usize],
                    nb as u16,
                );
                inner_tx_pkts += sent as u64;
                for j in sent as usize..nb as usize {
                    unsafe { ffi::shim_rte_pktmbuf_free(inner_tx_collect[j]) };
                }
            }
        }

        // ── 3b. Drain worker outer_tx rings → outer port TX ──

        for worker in workers {
            let nb = worker.outer_tx.dequeue_burst(&mut outer_tx_collect);
            if nb > 0 {
                had_work = true;
                let sent = port::tx_burst(
                    outer_port_id,
                    0,
                    &mut outer_tx_collect[..nb as usize],
                    nb as u16,
                );
                tx_pkts += sent as u64;
                for j in sent as usize..nb as usize {
                    unsafe { ffi::shim_rte_pktmbuf_free(outer_tx_collect[j]) };
                }
            }
        }

        // Refresh `now` only when there was actual work (skip clock_gettime on idle polls).
        if multi_state.handshakes.is_empty() && had_work {
            now = Instant::now();
        }

        // ── 4. Drive handshakes (skip entirely when no handshakes in progress) ──

        if !multi_state.handshakes.is_empty() {
            let drive_result = multi_state.poll_handshakes();

            for ch in drive_result.completed {
                if let Some((mut hs, conn_state)) = multi_state.extract_connection(ch) {
                    // Drain final handshake transmits.
                    drain_handshake_transmits(
                        &mut hs.connection,
                        now,
                        outer_port_id,
                        0,
                        mempool,
                        identity,
                        arp_table,
                        &mut transmit_buf,
                        &mut tx_pkts,
                        &mut ip_id,
                        checksum_mode,
                    );

                    match manager.promote_handshake(&hs, conn_state, peers) {
                        PromoteResult::Accepted {
                            cid_key, cid_bytes, tunnel_ip: peer_ip,
                            allowed_ips, remote_addr, keepalive_interval,
                            conn_state, evicted,
                        } => {
                            if let Some(evicted) = evicted {
                                tracing::info!(
                                    tunnel_ip = %evicted.tunnel_ip,
                                    "pipeline: evicted stale connection"
                                );
                                // Notify workers to remove evicted connection.
                                for worker in workers.iter() {
                                    if let Ok(mut ctrl) = worker.control.lock() {
                                        ctrl.push(PipelineControlMessage::RemoveConnection {
                                            cid: evicted.cid_key,
                                        });
                                    }
                                }
                            }

                            // Convert to SharedConnectionState for pipeline workers.
                            let shared = Arc::new(conn_state.into_shared());

                            // Broadcast to ALL workers.
                            for worker in workers.iter() {
                                if let Ok(mut ctrl) = worker.control.lock() {
                                    ctrl.push(PipelineControlMessage::AddConnection {
                                        conn: Arc::clone(&shared),
                                        tunnel_ip: peer_ip,
                                        remote_addr,
                                        remote_mac: arp_table.lookup(
                                            match remote_addr.ip() {
                                                std::net::IpAddr::V4(ip) => ip,
                                                _ => Ipv4Addr::UNSPECIFIED,
                                            }
                                        ).unwrap_or([0xff; 6]),
                                        cid: cid_key,
                                    });
                                }
                            }

                            // Track on core 0 via ConnectionManager.
                            manager.insert_connection(cid_key, ConnEntry {
                                conn: shared,
                                tunnel_ip: peer_ip,
                                allowed_ips,
                                remote_addr,
                                keepalive_interval,
                                last_tx: now,
                                last_rx: now,
                                owd_tracker: quictun_proto::rate_control::OwdTracker::new(),
                                rate_controller: rate_control_config.map(
                                    quictun_proto::rate_control::RateController::new,
                                ),
                            });

                            tracing::info!(
                                tunnel_ip = %peer_ip,
                                remote = %remote_addr,
                                cid = %hex::encode(&cid_bytes),
                                n_workers,
                                "pipeline: connection broadcast to all workers"
                            );
                        }
                        PromoteResult::Rejected { remote_addr, reason, .. } => {
                            tracing::warn!(
                                remote = %remote_addr,
                                reason = ?reason,
                                "pipeline: handshake rejected"
                            );
                        }
                    }
                }
            }

            // Drain handshake transmits for in-progress connections.
            for hs in multi_state.handshakes.values_mut() {
                drain_handshake_transmits(
                    &mut hs.connection,
                    now,
                    outer_port_id,
                    0,
                    mempool,
                    identity,
                    arp_table,
                    &mut transmit_buf,
                    &mut tx_pkts,
                    &mut ip_id,
                    checksum_mode,
                );
            }

            // Handle handshake timeouts.
            for hs in multi_state.handshakes.values_mut() {
                if let Some(t) = hs.connection.poll_timeout() {
                    if now >= t {
                        hs.connection.handle_timeout(now);
                    }
                }
            }
        }

        // ── 5. Send pending raw frames ──
        send_raw_frames(outer_port_id, 0, mempool, &mut pending_frames, &mut tx_pkts, checksum_mode)?;

        // ── 6. Timer-driven ACK generation (every ~25ms) ──

        if now.duration_since(last_ack) >= ACK_INTERVAL {
            for (_, entry) in manager.iter() {
                if entry.conn.replay.needs_ack() {
                    match entry.conn.encrypt_ack(entry.queuing_delay_us(), &mut ack_buf) {
                        Ok(result) => {
                            let remote_ip = match entry.remote_addr.ip() {
                                std::net::IpAddr::V4(ip) => ip,
                                _ => Ipv4Addr::UNSPECIFIED,
                            };
                            let remote_mac = arp_table.lookup(remote_ip)
                                .unwrap_or([0xff; 6]);
                            ip_id = ip_id.wrapping_add(1);
                            let frame_len = net::HEADER_SIZE + result.len;
                            if let Ok(mut mbuf) = Mbuf::alloc(mempool) {
                                if let Ok(buf) = mbuf.alloc_space(frame_len as u16) {
                                    net::build_udp_packet(
                                        &identity.local_mac,
                                        &remote_mac,
                                        identity.local_ip,
                                        remote_ip,
                                        identity.local_port,
                                        entry.remote_addr.port(),
                                        &ack_buf[..result.len],
                                        buf,
                                        0,
                                        ip_id,
                                        checksum_mode,
                                    );
                                    match checksum_mode {
                                        ChecksumMode::HardwareUdpOnly => {
                                            mbuf.set_tx_udp_checksum_offload()
                                        }
                                        ChecksumMode::HardwareFull => {
                                            mbuf.set_tx_full_checksum_offload()
                                        }
                                        _ => {}
                                    }
                                    let raw = mbuf.into_raw();
                                    let mut tx = [raw];
                                    let sent = port::tx_burst(outer_port_id, 0, &mut tx, 1);
                                    tx_pkts += sent as u64;
                                    if sent == 0 {
                                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::trace!(error = %e, "pipeline: ACK encrypt failed");
                        }
                    }
                }
            }
            last_ack = now;
        }

        // ── 7. Sweep timeouts (idle, key exhaustion, keepalive) ──

        {
            let actions = manager.sweep_timeouts();
            for action in actions {
                match action {
                    ManagerAction::SendKeepalive { cid_key } => {
                        if let Some(entry) = manager.get_mut(&cid_key) {
                            let mut ka_buf = [0u8; 256];
                            if let Ok(result) = entry.conn.tx.encrypt_datagram(&[], &mut ka_buf, None) {
                                let remote_ip = match entry.remote_addr.ip() {
                                    std::net::IpAddr::V4(ip) => ip,
                                    _ => Ipv4Addr::UNSPECIFIED,
                                };
                                let ka_mac = arp_table.lookup(remote_ip)
                                    .unwrap_or([0xff; 6]);
                                ip_id = ip_id.wrapping_add(1);
                                let frame_len = net::HEADER_SIZE + result.len;
                                if let Ok(mut mbuf) = Mbuf::alloc(mempool) {
                                    if let Ok(buf) = mbuf.alloc_space(frame_len as u16) {
                                        net::build_udp_packet(
                                            &identity.local_mac,
                                            &ka_mac,
                                            identity.local_ip,
                                            remote_ip,
                                            identity.local_port,
                                            entry.remote_addr.port(),
                                            &ka_buf[..result.len],
                                            buf,
                                            0,
                                            ip_id,
                                            checksum_mode,
                                        );
                                        match checksum_mode {
                                            ChecksumMode::HardwareUdpOnly => {
                                                mbuf.set_tx_udp_checksum_offload()
                                            }
                                            ChecksumMode::HardwareFull => {
                                                mbuf.set_tx_full_checksum_offload()
                                            }
                                            _ => {}
                                        }
                                        let raw = mbuf.into_raw();
                                        let mut burst = [raw];
                                        let sent = port::tx_burst(outer_port_id, 0, &mut burst, 1);
                                        tx_pkts += sent as u64;
                                        if sent == 0 {
                                            unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                        }
                                    }
                                }
                                entry.last_tx = now;
                            }
                        }
                    }
                    ManagerAction::ConnectionRemoved { cid_key, tunnel_ip: tip, reason, .. } => {
                        tracing::info!(
                            tunnel_ip = %tip,
                            reason = ?reason,
                            "pipeline: connection removed by sweep"
                        );
                        // Notify workers to remove the connection.
                        for worker in workers.iter() {
                            if let Ok(mut ctrl) = worker.control.lock() {
                                ctrl.push(PipelineControlMessage::RemoveConnection {
                                    cid: cid_key,
                                });
                            }
                        }
                    }
                }
            }
        }

        // ── 8. Key rotation (track dispatch count) ──

        // Count how many packets were dispatched per connection this iteration.
        // We don't track per-connection — approximate with total dispatched / n_connections.
        if nb_rx > 0 && !manager.is_empty() {
            let per_conn = nb_rx as u64 / manager.len() as u64;
            if per_conn > 0 {
                for (_, entry) in manager.iter() {
                    entry.conn.maybe_initiate_key_update(per_conn);
                }
            }
        }

        // ── Stats ──
        if now.duration_since(last_stats).as_secs() >= 2 {
            tracing::info!(
                rx_pkts,
                tx_pkts,
                inner_rx_pkts,
                inner_tx_pkts,
                dispatch_drop,
                connections = manager.len(),
                handshakes = multi_state.handshakes.len(),
                "pipeline I/O stats"
            );
            last_stats = now;
        }

        // ── Adaptive polling ──
        if adaptive_poll {
            if !had_work {
                empty_polls += 1;
                if empty_polls > EMPTY_POLL_THRESHOLD {
                    std::thread::sleep(Duration::from_micros(delay_us as u64));
                    delay_us = delay_us.saturating_mul(2).min(MAX_DELAY_US);
                }
            } else {
                empty_polls = 0;
                delay_us = MIN_DELAY_US;
            }
        }
    }

    Ok(())
}

/// Run a pipeline crypto worker on a dedicated core.
///
/// Workers share `Arc<SharedConnectionState>` for all connections.
/// - `decrypt_rx`: dequeue outer QUIC packets, decrypt in-place, build inner
///   frames, TX directly to inner port on the worker's own TX queue.
/// - `encrypt_rx`: dequeue inner IP packets, encrypt via TxState, TX directly
///   to outer NIC on the worker's own TX queue.
#[allow(clippy::too_many_arguments)]
pub fn run_pipeline_worker(
    mempool: *mut ffi::rte_mempool,
    rings: &PipelineRings,
    inner_eth_hdr: &InnerEthHeader,
    identity: &NetIdentity,
    shutdown: &AtomicBool,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    core_id: usize,
) -> Result<()> {
    const CID_LEN: usize = 8;

    // All connections (shared state): CID (as u64) → pipeline connection entry.
    let mut connections: FxHashMap<u64, PipelineConnection> = FxHashMap::default();

    let mut ip_id: u16 = (core_id as u16).wrapping_mul(10000);

    // Stats.
    let mut decrypt_ok: u64 = 0;
    let mut encrypt_ok: u64 = 0;
    let mut decrypt_fail: u64 = 0;
    let mut last_stats = Instant::now();

    // Adaptive polling.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    // Reusable mbuf arrays.
    let mut dec_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
    let mut enc_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
    let mut outer_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);
    let mut inner_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);

    tracing::info!(core = core_id, "pipeline worker started");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!(core = core_id, "pipeline worker: shutdown");
            break;
        }

        let mut had_work = false;

        // ── 0. Check control channel ──
        if let Ok(mut ctrl) = rings.control.try_lock() {
            for msg in ctrl.drain(..) {
                match msg {
                    PipelineControlMessage::AddConnection {
                        conn,
                        tunnel_ip,
                        remote_addr,
                        remote_mac,
                        cid,
                    } => {
                        tracing::info!(
                            core = core_id,
                            tunnel_ip = %tunnel_ip,
                            "pipeline worker: added connection"
                        );
                        connections.insert(cid, PipelineConnection {
                            conn,
                            tunnel_ip,
                            remote_addr,
                            remote_mac,
                        });
                    }
                    PipelineControlMessage::RemoveConnection { cid } => {
                        if let Some(entry) = connections.remove(&cid) {
                            tracing::info!(
                                core = core_id,
                                tunnel_ip = %entry.tunnel_ip,
                                "pipeline worker: removed connection"
                            );
                        }
                    }
                }
            }
        }

        // ── 1. Decrypt RX: dequeue → decrypt → build inner frame → enqueue inner_tx ──

        let nb_dec = rings.decrypt_rx.dequeue_burst(&mut dec_rx_mbufs);
        inner_tx_mbufs.clear();

        for i in 0..nb_dec as usize {
            let mut mbuf = unsafe { Mbuf::from_raw(dec_rx_mbufs[i]) };
            let data = mbuf.data_mut();

            // Parse to get UDP payload offset.
            let Some(ParsedPacket::Udp(udp)) = net::parse_packet(data) else {
                continue;
            };
            if udp.payload.is_empty() || udp.payload[0] & 0x80 != 0 {
                continue;
            }
            let src_mac = udp.src_mac;
            let src_ip = udp.src_ip;
            let src_port = udp.src_port;
            let payload_offset =
                unsafe { udp.payload.as_ptr().offset_from(data.as_ptr()) as usize };
            let payload_len = udp.payload.len();

            // Extract CID to find connection.
            if payload_len < 1 + CID_LEN {
                continue;
            }
            let cid_key = cid_to_u64(&data[payload_offset + 1..payload_offset + 1 + CID_LEN]);

            let Some(entry) = connections.get(&cid_key) else {
                decrypt_fail += 1;
                continue;
            };

            match entry
                .conn
                .decrypt_in_place(&mut data[payload_offset..payload_offset + payload_len])
            {
                Ok(decrypted) => {
                    decrypt_ok += 1;

                    // Process ACK from peer (atomic update).
                    if let Some(ref ack) = decrypted.ack {
                        entry.conn.process_ack(ack);
                    }

                    // Build inner frames for each datagram.
                    for range in &decrypted.datagrams {
                        let abs_start = payload_offset + range.start;
                        let abs_end = payload_offset + range.end;
                        let datagram_len = abs_end - abs_start;
                        let frame_len = ETH_HLEN + datagram_len;
                        if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
                            if let Ok(buf) = out_mbuf.alloc_space(frame_len as u16) {
                                buf[..ETH_HLEN].copy_from_slice(&inner_eth_hdr.bytes);
                                buf[ETH_HLEN..frame_len]
                                    .copy_from_slice(&data[abs_start..abs_end]);
                                inner_tx_mbufs.push(out_mbuf.into_raw());
                            }
                        }
                    }
                }
                Err(_) => {
                    decrypt_fail += 1;
                }
            }
        }

        if nb_dec > 0 {
            had_work = true;
        }

        // Enqueue inner TX mbufs to core 0 via ring (virtio-user only has 1 queue pair).
        if !inner_tx_mbufs.is_empty() {
            let enqueued = rings.inner_tx.enqueue_burst(&inner_tx_mbufs);
            for j in enqueued as usize..inner_tx_mbufs.len() {
                unsafe { ffi::shim_rte_pktmbuf_free(inner_tx_mbufs[j]) };
            }
        }

        // ── 2. Encrypt RX: dequeue inner → encrypt → TX directly to outer port ──

        let nb_enc = rings.encrypt_rx.dequeue_burst(&mut enc_rx_mbufs);
        outer_tx_mbufs.clear();

        for i in 0..nb_enc as usize {
            let mbuf = unsafe { Mbuf::from_raw(enc_rx_mbufs[i]) };
            let data = mbuf.data();
            if data.len() < ETH_HLEN + 20 {
                continue;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            if ethertype != 0x0800 {
                continue;
            }

            let ip_payload = &data[ETH_HLEN..];

            // For pipeline mode, use the first/only connection for encrypt.
            // In multi-peer mode, we'd route by dest IP → tunnel_ip → connection.
            // For now, use the first connection (single-peer case, dominant use).
            let Some(entry) = connections.values().next() else {
                continue;
            };

            let max_quic_len = 1
                + entry.conn.local_cid_len() // remote_cid on the wire = our local_cid_len
                + 4
                + 1
                + ip_payload.len()
                + entry.conn.tag_len();
            let max_frame_len = net::HEADER_SIZE + max_quic_len;
            let Ok(max_frame_len_u16) = u16::try_from(max_frame_len) else {
                continue;
            };

            if let Ok(mut tx_mbuf) = Mbuf::alloc(mempool) {
                if let Ok(buf) = tx_mbuf.alloc_space(max_frame_len_u16) {
                    match entry.conn.tx.encrypt_datagram(
                        ip_payload,
                        &mut buf[net::HEADER_SIZE..],
                        None,
                    ) {
                        Ok(result) => {
                            let remote_ip = match entry.remote_addr.ip() {
                                std::net::IpAddr::V4(ip) => ip,
                                _ => Ipv4Addr::UNSPECIFIED,
                            };
                            ip_id = ip_id.wrapping_add(1);
                            let actual_len = net::build_udp_packet_inplace(
                                &identity.local_mac,
                                &entry.remote_mac,
                                identity.local_ip,
                                remote_ip,
                                identity.local_port,
                                entry.remote_addr.port(),
                                result.len,
                                buf,
                                0,
                                ip_id,
                                checksum_mode,
                            );
                            tx_mbuf.truncate(actual_len as u16);
                            match checksum_mode {
                                ChecksumMode::HardwareUdpOnly => {
                                    tx_mbuf.set_tx_udp_checksum_offload()
                                }
                                ChecksumMode::HardwareFull => {
                                    tx_mbuf.set_tx_full_checksum_offload()
                                }
                                _ => {}
                            }
                            outer_tx_mbufs.push(tx_mbuf.into_raw());
                            encrypt_ok += 1;
                        }
                        Err(e) => {
                            tracing::trace!(core = core_id, error = %e, "pipeline encrypt failed");
                        }
                    }
                }
            }
        }

        if nb_enc > 0 {
            had_work = true;
        }

        // Enqueue encrypted packets to outer_tx ring for core 0 to TX.
        if !outer_tx_mbufs.is_empty() {
            let enqueued = rings.outer_tx.enqueue_burst(&outer_tx_mbufs);
            for j in enqueued as usize..outer_tx_mbufs.len() {
                unsafe { ffi::shim_rte_pktmbuf_free(outer_tx_mbufs[j]) };
            }
        }

        // ── Stats ──
        if had_work {
            now = Instant::now();
        }
        if now.duration_since(last_stats).as_secs() >= 2 {
            tracing::info!(
                core = core_id,
                decrypt_ok,
                encrypt_ok,
                decrypt_fail,
                connections = connections.len(),
                "pipeline worker stats"
            );
            last_stats = now;
        }

        // ── Adaptive polling ──
        if adaptive_poll {
            if !had_work {
                empty_polls += 1;
                if empty_polls > EMPTY_POLL_THRESHOLD {
                    std::thread::sleep(Duration::from_micros(delay_us as u64));
                    delay_us = delay_us.saturating_mul(2).min(MAX_DELAY_US);
                }
            } else {
                empty_polls = 0;
                delay_us = MIN_DELAY_US;
            }
        }
    }

    Ok(())
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

// ── Entry point (single-core / multi-core dispatch) ─────────────────────

/// Top-level entry point for virtio/TAP mode (single-core or multicore).
///
/// Handles the single vs multicore dispatch, thread spawning, and scope join.
/// Called from `event_loop::run()` after shared setup.
#[allow(clippy::too_many_arguments)]
pub fn entry(
    outer_port_id: u16,
    mempool: *mut ffi::rte_mempool,
    multi_state: &mut MultiQuicState,
    inner_ports: Vec<InnerPort>,
    identity: &NetIdentity,
    arp_table: &mut ArpTable,
    shutdown: Arc<AtomicBool>,
    dpdk_config: &DpdkConfig,
    checksum_mode: ChecksumMode,
    server_config_clone: Option<Arc<quinn_proto::ServerConfig>>,
) -> Result<()> {
    let n_cores = dpdk_config.n_cores.max(1);

    if n_cores == 1 {
        let inner = inner_ports
            .into_iter()
            .next()
            .expect("exactly 1 inner port");
        return run(
            outer_port_id,
            0, // queue_id
            mempool,
            multi_state,
            identity,
            arp_table,
            inner,
            shutdown,
            dpdk_config.adaptive_poll,
            checksum_mode,
            &dpdk_config.peers,
            dpdk_config.tunnel_ip,
            dpdk_config.max_peers,
            dpdk_config.idle_timeout,
            dpdk_config.rate_control_config,
        );
    }

    // Multi-core: pipeline architecture (SharedConnectionState).
    // Core 0 = I/O, Workers 1..N = crypto (round-robin, any-connection).
    let n_workers = n_cores - 1;

    // Build multi-client QUIC state (listener only for multi-core).
    let multi_server_config = server_config_clone
        .ok_or_else(|| anyhow::anyhow!("multi-core DPDK requires listener mode"))?;
    let mut multi_state = MultiQuicState::new(multi_server_config);

    // Create per-worker pipeline ring bundles.
    let mut pipeline_rings: Vec<PipelineRings> = Vec::with_capacity(n_workers);
    for i in 0..n_workers {
        pipeline_rings.push(PipelineRings::new(i)?);
    }

    // Single inner port on core 0.
    let inner = inner_ports
        .into_iter()
        .next()
        .expect("at least 1 inner port");

    let adaptive_poll = dpdk_config.adaptive_poll;

    // Spawn pipeline worker threads (pinned to cores 1..N).
    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(n_workers);

        for (idx, rings) in pipeline_rings.iter().enumerate() {
            let shutdown = shutdown.clone();
            let worker_identity = identity.clone();
            let inner_eth_hdr = &inner.eth_hdr;
            let mempool = SendPtr(mempool);

            handles.push(s.spawn(move || -> Result<()> {
                let mempool = mempool.as_ptr();
                let core_idx = idx + 1; // core 0 is I/O
                // Pin thread to CPU.
                #[cfg(target_os = "linux")]
                {
                    let mut cpuset: libc::cpu_set_t = unsafe { std::mem::zeroed() };
                    unsafe { libc::CPU_SET(core_idx, &mut cpuset) };
                    let ret = unsafe {
                        libc::sched_setaffinity(
                            0,
                            std::mem::size_of::<libc::cpu_set_t>(),
                            &cpuset,
                        )
                    };
                    if ret == 0 {
                        tracing::info!(core = core_idx, "pinned pipeline worker to CPU");
                    } else {
                        tracing::warn!(core = core_idx, "failed to pin pipeline worker to CPU");
                    }
                }

                run_pipeline_worker(
                    mempool,
                    rings,
                    inner_eth_hdr,
                    &worker_identity,
                    &shutdown,
                    adaptive_poll,
                    checksum_mode,
                    core_idx,
                )
            }));
        }

        // Run pipeline I/O on core 0 (this thread).
        let io_result = run_pipeline_io(
            outer_port_id,
            mempool,
            &mut multi_state,
            &pipeline_rings,
            identity,
            arp_table,
            &inner,
            &dpdk_config.peers,
            &shutdown,
            adaptive_poll,
            checksum_mode,
            dpdk_config.tunnel_ip,
            dpdk_config.max_peers,
            dpdk_config.idle_timeout,
            dpdk_config.rate_control_config,
        );

        // Signal shutdown and wait for workers.
        shutdown.store(true, Ordering::Release);
        let mut result = io_result;
        for handle in handles {
            if let Err(e) = handle.join().expect("pipeline worker panicked") {
                if result.is_ok() {
                    result = Err(e);
                }
            }
        }
        result
    })
}
