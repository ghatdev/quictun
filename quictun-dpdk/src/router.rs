//! Router-mode polling loop for DPDK.
//!
//! Single NIC handles both encrypted QUIC and plaintext forwarded traffic.
//! No inner port (TAP/virtio-user) — all routing done in userspace.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::BytesMut;
use rustc_hash::FxHashMap;

use crate::dispatch::{
    ConnectionEntry, ControlMessage, DpdkDispatchTable,
    RouterPipelineConnection, RouterPipelineControlMessage, RouterPipelineRings,
    WorkerRings,
};
use crate::ffi;
use crate::mbuf::Mbuf;
use crate::net::{self, ArpTable, ChecksumMode, NetIdentity, ParsedPacket};
use crate::port;
use crate::shared::{BUF_SIZE, MultiQuicState};
use quictun_core::{icmp, mss};
use quictun_core::manager::{ConnEntry, ConnectionManager, ManagerAction, PromoteResult};
use quictun_core::nat::{self, NatForwardKey, NatTable};
use quictun_core::peer::PeerConfig;
use quictun_core::routing::{RouteAction, RoutingTable};
use quictun_proto::cid_to_u64;
use quictun_proto::shared::SharedConnectionState;

use crate::engine::resolve_completed_handshake;
use crate::event_loop::{DpdkConfig, SendPtr};

use quictun_proto::local::LocalConnectionState;

/// Minimal view of a connection for building TX frames.
///
/// Abstracts over [`ConnectionEntry`] (multi-core workers, has cached MAC) and
/// [`ConnEntry<LocalConnectionState>`] (single-core ConnectionManager, no MAC).
pub(crate) struct ConnView<'a> {
    pub conn: &'a mut LocalConnectionState,
    pub remote_addr: SocketAddr,
    pub remote_mac: [u8; 6],
}

impl<'a> From<&'a mut ConnectionEntry> for ConnView<'a> {
    fn from(e: &'a mut ConnectionEntry) -> Self {
        ConnView {
            conn: &mut e.conn,
            remote_addr: e.remote_addr,
            remote_mac: e.remote_mac,
        }
    }
}

/// Connection table lookup trait for router helper functions.
///
/// Returns a [`ConnView`] that provides the fields needed to build TX frames.
/// MAC address comes from the entry (multi-core cache) or ArpTable (single-core).
pub(crate) trait ConnLookup {
    fn conn_view(&mut self, key: &u64) -> Option<ConnView<'_>>;
}

impl ConnLookup for FxHashMap<u64, ConnectionEntry> {
    fn conn_view(&mut self, key: &u64) -> Option<ConnView<'_>> {
        self.get_mut(key).map(|e| ConnView {
            conn: &mut e.conn,
            remote_addr: e.remote_addr,
            remote_mac: e.remote_mac,
        })
    }
}

/// Wrapper that pairs ConnectionManager with ArpTable for ConnLookup.
///
/// Single-core paths use this: MAC is resolved from ArpTable at lookup time
/// instead of being cached per-connection.
pub(crate) struct ManagerWithArp<'a> {
    pub manager: &'a mut ConnectionManager<LocalConnectionState>,
    pub arp_table: &'a ArpTable,
}

impl ConnLookup for ManagerWithArp<'_> {
    fn conn_view(&mut self, key: &u64) -> Option<ConnView<'_>> {
        self.manager.get_mut(key).map(|e| {
            let remote_ip = match e.remote_addr.ip() {
                std::net::IpAddr::V4(ip) => ip,
                _ => Ipv4Addr::UNSPECIFIED,
            };
            let mac = self.arp_table.lookup(remote_ip).unwrap_or([0xff; 6]);
            ConnView {
                conn: &mut e.conn,
                remote_addr: e.remote_addr,
                remote_mac: mac,
            }
        })
    }
}

/// Maximum burst size for rx/tx.
const BURST_SIZE: usize = 32;

/// Number of consecutive empty polls before entering backoff sleep.
const EMPTY_POLL_THRESHOLD: u32 = 1024;
/// Minimum sleep duration in microseconds during adaptive backoff.
const MIN_DELAY_US: u32 = 1;
/// Maximum sleep duration in microseconds during adaptive backoff.
const MAX_DELAY_US: u32 = 100;

const CID_LEN: usize = 8;
const ETH_HLEN: usize = 14;

/// NAT sweep interval.
const NAT_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// ARP refresh interval (send ARP requests for stale entries).
const ARP_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// ARP stale threshold for refresh probing (seconds).
const ARP_STALE_THRESHOLD_SECS: u64 = 30;

/// Run the single-core router-mode polling loop.
///
/// A single NIC handles:
/// - Encrypted QUIC traffic (decrypt → route → encrypt or forward)
/// - Plaintext return traffic (reverse NAT → encrypt to peer)
/// - ARP requests/replies
#[allow(clippy::too_many_arguments)]
pub fn run_router(
    outer_port_id: u16,
    queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    multi_state: &mut MultiQuicState,
    identity: &NetIdentity,
    arp_table: &mut ArpTable,
    shutdown: Arc<AtomicBool>,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    peers: &[PeerConfig],
    enable_nat: bool,
    mss_clamp_val: u16,
    tunnel_ip: Ipv4Addr,
    tunnel_mtu: u16,
    max_peers: usize,
    idle_timeout: Duration,
) -> Result<()> {
    let mut response_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut pkt_buf = [0u8; 2048];
    let mut ip_id: u16 = 0;
    let mut rx_buf = BytesMut::with_capacity(2048);

    let mut pending_frames: Vec<Vec<u8>> = Vec::new();

    // Connection lifecycle manager (used for promote, sweep, connection table).
    // Router keeps its own RoutingTable separately (pre-populated from config).
    let mut manager = ConnectionManager::<LocalConnectionState>::new(
        tunnel_ip,
        false, // default_external (router's RoutingTable handles this)
        max_peers,
        idle_timeout,
    );

    // NAT table (per-core, no locking).
    let mut nat_table = NatTable::new(identity.local_ip);

    // Routing table (from peer allowed_ips).
    let mut routing_table = RoutingTable::new(tunnel_ip, enable_nat);
    for peer in peers {
        // Use tunnel IP as the CID key placeholder — will be resolved at handshake.
        let cid_key = u32::from(peer.tunnel_ip) as u64;
        routing_table.add_peer_routes(cid_key, &peer.allowed_ips);
    }

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut quic_rx: u64 = 0;
    let mut decrypt_fail: u64 = 0;
    let mut nat_forward: u64 = 0;
    let mut nat_reverse: u64 = 0;
    let mut hub_spoke: u64 = 0;
    let mut ttl_drop: u64 = 0;
    let mut no_route_drop: u64 = 0;
    let mut frag_needed: u64 = 0;
    let mut mac_fail: u64 = 0;
    let mut arp_refresh_count: u64 = 0;
    let mut last_stats = Instant::now();
    let mut last_nat_sweep = Instant::now();
    let mut last_arp_refresh = Instant::now();

    // Adaptive polling.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    let mut outer_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);
    let mut pending_outer_tx: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);

    // Drain initial handshake transmits (connector Client Hello).
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

    tracing::info!("DPDK router engine started (polling loop)");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("shutdown signal received");
            break;
        }

        if !multi_state.handshakes.is_empty() {
            now = Instant::now();
        }

        // ── RX burst from NIC ──
        outer_tx_mbufs.clear();

        let mut rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
        let nb_rx = port::rx_burst(outer_port_id, queue_id, &mut rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_rx as usize {
            let mut mbuf = unsafe { Mbuf::from_raw(rx_mbufs[i]) };
            rx_pkts += 1;

            let data = mbuf.data_mut();

            match net::parse_packet_extended(data) {
                Some(ParsedPacket::Udp(udp)) => {
                    if udp.dst_port == identity.local_port && udp.dst_ip == identity.local_ip {
                        // QUIC packet destined for us.
                        if udp.payload.is_empty() {
                            continue;
                        }

                        let payload_offset =
                            unsafe { udp.payload.as_ptr().offset_from(data.as_ptr()) as usize };
                        let payload_len = udp.payload.len();
                        let first_byte = udp.payload[0];

                        arp_table.learn(udp.src_ip, udp.src_mac);

                        if first_byte & 0x80 == 0 {
                            // Short header → decrypt via connection table.
                            quic_rx += 1;

                            if payload_len < 1 + CID_LEN {
                                continue;
                            }
                            let cid_key = cid_to_u64(
                                &data[payload_offset + 1..payload_offset + 1 + CID_LEN],
                            );

                            // Decrypt and collect datagram byte ranges.
                            // We release the mutable borrow of `manager` before
                            // calling handle_decrypted_packet (which needs &mut manager).
                            let src_mac = udp.src_mac;
                            let src_ip = udp.src_ip;
                            let src_port = udp.src_port;
                            let decrypt_result = {
                                let Some(entry) = manager.get_mut(&cid_key) else {
                                    decrypt_fail += 1;
                                    continue;
                                };
                                match entry.conn.decrypt_packet_in_place(
                                    &mut data[payload_offset..payload_offset + payload_len],
                                ) {
                                    Ok(decrypted) => {
                                        // Update peer address on every authenticated packet.
                                        entry.remote_addr = SocketAddr::new(src_ip.into(), src_port);
                                        entry.last_rx = now;

                                        if let Some(ref ack) = decrypted.ack {
                                            entry.conn.process_ack(ack);
                                        }
                                        let ranges: Vec<(usize, usize)> = decrypted
                                            .datagrams
                                            .iter()
                                            .map(|r| (payload_offset + r.start, payload_offset + r.end))
                                            .collect();
                                        Some((ranges, entry.tunnel_ip))
                                    }
                                    Err(_) => {
                                        decrypt_fail += 1;
                                        None
                                    }
                                }
                            };

                            if let Some((ranges, src_tunnel_ip)) = decrypt_result {
                                for (abs_start, abs_end) in &ranges {
                                    let inner_pkt = &mut data[*abs_start..*abs_end];

                                    if mss_clamp_val > 0 {
                                        mss::clamp_mss(inner_pkt, mss_clamp_val);
                                    }

                                    let mut conn_lookup = ManagerWithArp {
                                        manager: &mut manager,
                                        arp_table,
                                    };
                                    handle_decrypted_packet(
                                        inner_pkt,
                                        cid_key,
                                        src_tunnel_ip,
                                        &routing_table,
                                        &mut nat_table,
                                        &mut conn_lookup,
                                        identity,
                                        arp_table,
                                        mempool,
                                        &mut outer_tx_mbufs,
                                        &mut ip_id,
                                        checksum_mode,
                                        enable_nat,
                                        &mut pkt_buf,
                                        &mut nat_forward,
                                        &mut hub_spoke,
                                        &mut ttl_drop,
                                        &mut no_route_drop,
                                        &mut frag_needed,
                                        &mut mac_fail,
                                        now,
                                        tunnel_ip,
                                        tunnel_mtu,
                                    );
                                }
                            }
                        } else {
                            // Long header → handshake.
                            quic_rx += 1;
                            rx_buf.clear();
                            rx_buf.extend_from_slice(
                                &data[payload_offset..payload_offset + payload_len],
                            );
                            let quic_data = rx_buf.split();

                            let remote_addr =
                                SocketAddr::new(udp.src_ip.into(), udp.src_port);
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
                                    .unwrap_or([0xff; 6]);
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
                    } else if enable_nat {
                        // Non-QUIC UDP destined for us (return traffic from internet).
                        // Reverse NAT lookup.
                        arp_table.learn(udp.src_ip, udp.src_mac);

                        if let Some(dnat_result) = nat_table.lookup_reverse(
                            17, // UDP
                            udp.dst_port,
                            udp.src_ip,
                            udp.src_port,
                            now,
                        ) {
                            nat_reverse += 1;

                            // Build the original inner packet, apply DNAT, encrypt to peer.
                            // We need the IP packet without Ethernet header.
                            let ip_start = ETH_HLEN;
                            let ip_pkt = &data[ip_start..];

                            let mut conn_lookup = ManagerWithArp {
                                manager: &mut manager,
                                arp_table,
                            };
                            encrypt_return_to_peer(
                                ip_pkt,
                                &dnat_result,
                                &mut conn_lookup,
                                identity,
                                arp_table,
                                mempool,
                                &mut outer_tx_mbufs,
                                &mut ip_id,
                                checksum_mode,
                                mss_clamp_val,
                            );
                        }
                    }
                }
                Some(ParsedPacket::Ipv4Raw(ipv4)) => {
                    // Non-UDP IPv4 (TCP, ICMP return traffic).
                    if !enable_nat {
                        continue;
                    }
                    arp_table.learn(ipv4.src_ip, ipv4.src_mac);

                    // For TCP: reverse NAT by (proto, dst_port).
                    if ipv4.protocol == 6 {
                        // TCP
                        let tcp_start = ipv4.ip_header_len;
                        if ipv4.payload.len() >= tcp_start + 4 {
                            let dst_port = u16::from_be_bytes([
                                ipv4.payload[tcp_start + 2],
                                ipv4.payload[tcp_start + 3],
                            ]);
                            let src_port = u16::from_be_bytes([
                                ipv4.payload[tcp_start],
                                ipv4.payload[tcp_start + 1],
                            ]);

                            if let Some(dnat_result) = nat_table.lookup_reverse(
                                6, dst_port, ipv4.src_ip, src_port, now,
                            ) {
                                nat_reverse += 1;

                                let mut conn_lookup = ManagerWithArp {
                                    manager: &mut manager,
                                    arp_table,
                                };
                                encrypt_return_to_peer(
                                    ipv4.payload,
                                    &dnat_result,
                                    &mut conn_lookup,
                                    identity,
                                    arp_table,
                                    mempool,
                                    &mut outer_tx_mbufs,
                                    &mut ip_id,
                                    checksum_mode,
                                    mss_clamp_val,
                                );
                            }
                        }
                    } else if ipv4.protocol == 1 {
                        // ICMP return — check if it's a reply to something we NAT'd.
                        // For echo replies, use (proto=ICMP, id as port).
                        let icmp_start = ipv4.ip_header_len;
                        if ipv4.payload.len() >= icmp_start + 8 {
                            let icmp_type = ipv4.payload[icmp_start];
                            // Echo reply (type 0) or other ICMP responses.
                            if icmp_type == 0 {
                                let icmp_id = u16::from_be_bytes([
                                    ipv4.payload[icmp_start + 4],
                                    ipv4.payload[icmp_start + 5],
                                ]);
                                if let Some(dnat_result) = nat_table.lookup_reverse(
                                    1, icmp_id, ipv4.src_ip, 0, now,
                                ) {
                                    nat_reverse += 1;
                                    let mut conn_lookup = ManagerWithArp {
                                        manager: &mut manager,
                                        arp_table,
                                    };
                                    encrypt_return_to_peer(
                                        ipv4.payload,
                                        &dnat_result,
                                        &mut conn_lookup,
                                        identity,
                                        arp_table,
                                        mempool,
                                        &mut outer_tx_mbufs,
                                        &mut ip_id,
                                        checksum_mode,
                                        mss_clamp_val,
                                    );
                                }
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
                None => {}
            }
        }

        // ── Poll for completed handshakes (skip when no handshakes in progress) ──
        if !multi_state.handshakes.is_empty() {
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
                                    "router: evicted stale connection"
                                );
                            }
                            manager.insert_connection(cid_key, ConnEntry {
                                conn: conn_state,
                                tunnel_ip: peer_ip,
                                allowed_ips: allowed_ips.clone(),
                                remote_addr,
                                keepalive_interval,
                                last_tx: now,
                                last_rx: now,
                            });

                            // Rebuild router's own routing table with actual CID keys.
                            routing_table = RoutingTable::new(tunnel_ip, enable_nat);
                            for p in peers {
                                let key = if p.tunnel_ip == peer_ip {
                                    cid_key
                                } else if let Some((&existing_cid, _)) = manager.iter()
                                    .find(|(_, e)| e.tunnel_ip == p.tunnel_ip)
                                {
                                    existing_cid
                                } else {
                                    u32::from(p.tunnel_ip) as u64
                                };
                                routing_table.add_peer_routes(key, &p.allowed_ips);
                            }

                            tracing::info!(
                                cid = hex::encode(&cid_bytes),
                                tunnel_ip = %peer_ip,
                                remote = %remote_addr,
                                "router: connection established"
                            );
                        }
                        PromoteResult::Rejected { remote_addr, reason, .. } => {
                            tracing::warn!(
                                remote = %remote_addr,
                                reason = ?reason,
                                "router: handshake rejected"
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

        // ── Batch TX ──

        // Send pending handshake/ARP frames.
        for frame in pending_frames.drain(..) {
            if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
                if out_mbuf.write_packet(&frame).is_ok() {
                    match checksum_mode {
                        ChecksumMode::HardwareUdpOnly => out_mbuf.set_tx_udp_checksum_offload(),
                        ChecksumMode::HardwareFull => out_mbuf.set_tx_full_checksum_offload(),
                        _ => {}
                    }
                    outer_tx_mbufs.push(out_mbuf.into_raw());
                }
            }
        }

        // Retry pending outer TX from last iteration.
        if !pending_outer_tx.is_empty() {
            let nb = pending_outer_tx.len() as u16;
            let sent = port::tx_burst(outer_port_id, queue_id, &mut pending_outer_tx, nb);
            if sent < nb {
                for raw in &pending_outer_tx[sent as usize..] {
                    unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
                }
            }
            pending_outer_tx.clear();
        }

        // Send new TX mbufs.
        if !outer_tx_mbufs.is_empty() {
            let nb = outer_tx_mbufs.len() as u16;
            let sent = port::tx_burst(outer_port_id, queue_id, &mut outer_tx_mbufs, nb);
            tx_pkts += sent as u64;

            if sent < nb {
                // Save unsent for retry next iteration.
                for raw in &outer_tx_mbufs[sent as usize..] {
                    pending_outer_tx.push(*raw);
                }
            }
        }

        // ── Periodic tasks ──

        let had_traffic = nb_rx > 0 || !outer_tx_mbufs.is_empty();

        // NAT sweep.
        if enable_nat && now.duration_since(last_nat_sweep) >= NAT_SWEEP_INTERVAL {
            now = Instant::now();
            let before = nat_table.len();
            nat_table.sweep(now);
            let expired = before - nat_table.len();
            if expired > 0 {
                tracing::debug!(expired, remaining = nat_table.len(), "NAT sweep");
            }
            last_nat_sweep = now;
        }

        // ARP refresh.
        if now.duration_since(last_arp_refresh) >= ARP_REFRESH_INTERVAL {
            let stale = arp_table.stale_entries(ARP_STALE_THRESHOLD_SECS);
            for stale_ip in &stale {
                let request = net::build_arp_request(identity.local_mac, identity.local_ip, *stale_ip);
                pending_frames.push(request);
                arp_refresh_count += 1;
            }
            last_arp_refresh = now;
        }

        // Connection sweep (idle timeout, key exhaustion, keepalive).
        if !manager.is_empty() && now.duration_since(last_nat_sweep) < Duration::from_millis(100) {
            // Piggyback on the NAT sweep clock refresh (avoid extra Instant::now).
            let actions = manager.sweep_timeouts();
            for action in actions {
                match action {
                    ManagerAction::SendKeepalive { cid_key } => {
                        if let Some(entry) = manager.get_mut(&cid_key) {
                            let mut ka_buf = [0u8; 256];
                            if let Ok(result) = entry.conn.encrypt_datagram(&[], &mut ka_buf) {
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
                            "router: connection removed by sweep"
                        );
                    }
                }
            }
        }

        // Stats.
        if now.duration_since(last_stats) >= Duration::from_secs(10) {
            now = Instant::now();
            tracing::info!(
                rx = rx_pkts,
                tx = tx_pkts,
                quic = quic_rx,
                decrypt_fail,
                nat_fwd = nat_forward,
                nat_rev = nat_reverse,
                hub_spoke,
                ttl_drop,
                no_route_drop,
                frag_needed,
                mac_fail,
                arp_refresh = arp_refresh_count,
                nat_entries = nat_table.len(),
                connections = manager.len(),
                "router stats"
            );
            last_stats = now;
        }

        // Adaptive polling.
        if adaptive_poll {
            if had_traffic {
                empty_polls = 0;
                delay_us = MIN_DELAY_US;
            } else {
                empty_polls += 1;
                if empty_polls > EMPTY_POLL_THRESHOLD {
                    std::thread::sleep(Duration::from_micros(delay_us as u64));
                    delay_us = (delay_us * 2).min(MAX_DELAY_US);
                }
            }
        }

        // Refresh time for non-handshake path (less frequent).
        if multi_state.handshakes.is_empty() && had_traffic {
            now = Instant::now();
        }
    }

    Ok(())
}

/// Handle a decrypted inner packet: route, NAT, or forward to peer.
#[allow(clippy::too_many_arguments)]
fn handle_decrypted_packet(
    inner_pkt: &[u8],
    src_cid: u64,
    src_tunnel_ip: Ipv4Addr,
    routing_table: &RoutingTable,
    nat_table: &mut NatTable,
    connections: &mut impl ConnLookup,
    identity: &NetIdentity,
    arp_table: &ArpTable,
    mempool: *mut ffi::rte_mempool,
    outer_tx_mbufs: &mut Vec<*mut ffi::rte_mbuf>,
    ip_id: &mut u16,
    checksum_mode: ChecksumMode,
    enable_nat: bool,
    pkt_buf: &mut [u8],
    nat_forward_count: &mut u64,
    hub_spoke_count: &mut u64,
    ttl_drop_count: &mut u64,
    no_route_drop_count: &mut u64,
    frag_needed_count: &mut u64,
    mac_fail_count: &mut u64,
    now: Instant,
    tunnel_ip: Ipv4Addr,
    tunnel_mtu: u16,
) {
    if inner_pkt.len() < 20 {
        return;
    }

    // Fragmentation Needed check: if packet exceeds tunnel MTU and DF bit is set.
    if tunnel_mtu > 0 && inner_pkt.len() > tunnel_mtu as usize {
        let df_set = (inner_pkt[6] & 0x40) != 0;
        if df_set {
            *frag_needed_count += 1;
            if let Some(icmp_pkt) = icmp::build_frag_needed(inner_pkt, tunnel_ip, tunnel_mtu) {
                if let Some(entry) = connections.conn_view(&src_cid) {
                    encrypt_and_send(
                        &icmp_pkt,
                        entry,
                        identity,
                        mempool,
                        outer_tx_mbufs,
                        ip_id,
                        checksum_mode,
                        pkt_buf,
                    );
                }
            }
            return;
        }
    }

    let dst_ip = Ipv4Addr::new(inner_pkt[16], inner_pkt[17], inner_pkt[18], inner_pkt[19]);

    match routing_table.lookup(dst_ip) {
        RouteAction::ForwardToPeer(peer_cid) => {
            // Hub-and-spoke: re-encrypt to another peer.
            if let Some(peer_entry) = connections.conn_view(&peer_cid) {
                *hub_spoke_count += 1;
                encrypt_and_send(
                    inner_pkt,
                    peer_entry,
                    identity,
                    mempool,
                    outer_tx_mbufs,
                    ip_id,
                    checksum_mode,
                    pkt_buf,
                );
            }
        }
        RouteAction::ForwardExternal => {
            if !enable_nat {
                return;
            }
            *nat_forward_count += 1;

            // SNAT: rewrite source to our NIC IP, allocate port.
            let proto = inner_pkt[9];
            let src_ip = Ipv4Addr::new(inner_pkt[12], inner_pkt[13], inner_pkt[14], inner_pkt[15]);
            let (src_port, dst_port) = extract_ports(inner_pkt, proto);

            let nat_key = NatForwardKey {
                proto,
                src_ip,
                src_port,
                dst_ip,
                dst_port,
            };

            let Some(snat_result) =
                nat_table.lookup_or_create(&nat_key, src_cid, src_tunnel_ip, now)
            else {
                return; // port exhaustion
            };

            // Build forwarded Ethernet frame: Eth + modified IP packet.
            let dst_mac = arp_table.lookup(dst_ip);
            let Some(dst_mac) = dst_mac else {
                *mac_fail_count += 1;
                return;
            };

            let frame_len = ETH_HLEN + inner_pkt.len();
            if frame_len > pkt_buf.len() {
                return;
            }

            // Copy Eth header + IP packet into buffer.
            pkt_buf[0..6].copy_from_slice(&dst_mac);
            pkt_buf[6..12].copy_from_slice(&identity.local_mac);
            pkt_buf[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4
            pkt_buf[ETH_HLEN..frame_len].copy_from_slice(inner_pkt);

            // Apply SNAT to the IP packet portion (after Ethernet header).
            nat::apply_snat(
                &mut pkt_buf[ETH_HLEN..frame_len],
                identity.local_ip,
                snat_result.nat_port,
            );

            // Decrement TTL.
            let ttl = pkt_buf[ETH_HLEN + 8];
            if ttl <= 1 {
                *ttl_drop_count += 1;
                if let Some(icmp_pkt) = icmp::build_time_exceeded(inner_pkt, tunnel_ip) {
                    if let Some(entry) = connections.conn_view(&src_cid) {
                        encrypt_and_send(
                            &icmp_pkt,
                            entry,
                            identity,
                            mempool,
                            outer_tx_mbufs,
                            ip_id,
                            checksum_mode,
                            pkt_buf,
                        );
                    }
                }
                return;
            }
            pkt_buf[ETH_HLEN + 8] = ttl - 1;
            // Fix IP checksum for TTL change.
            fix_ttl_checksum(&mut pkt_buf[ETH_HLEN..], ttl);

            if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
                if out_mbuf.write_packet(&pkt_buf[..frame_len]).is_ok() {
                    outer_tx_mbufs.push(out_mbuf.into_raw());
                }
            }
        }
        RouteAction::Local => {
            // ICMP echo reply.
            let mut reply = inner_pkt.to_vec();
            if quictun_core::icmp::echo_reply_inplace(&mut reply) {
                // Send reply back to the peer that sent it.
                if let Some(entry) = connections.conn_view(&src_cid) {
                    encrypt_and_send(
                        &reply,
                        entry,
                        identity,
                        mempool,
                        outer_tx_mbufs,
                        ip_id,
                        checksum_mode,
                        pkt_buf,
                    );
                }
            }
        }
        RouteAction::Drop => {
            *no_route_drop_count += 1;
            if let Some(icmp_pkt) = icmp::build_dest_unreachable(inner_pkt, tunnel_ip, 0) {
                if let Some(entry) = connections.conn_view(&src_cid) {
                    encrypt_and_send(
                        &icmp_pkt,
                        entry,
                        identity,
                        mempool,
                        outer_tx_mbufs,
                        ip_id,
                        checksum_mode,
                        pkt_buf,
                    );
                }
            }
        }
    }
}

/// Encrypt a return packet (after DNAT) and send to the peer.
#[allow(clippy::too_many_arguments)]
fn encrypt_return_to_peer(
    ip_pkt: &[u8],
    dnat: &nat::DnatResult,
    connections: &mut impl ConnLookup,
    identity: &NetIdentity,
    arp_table: &ArpTable,
    mempool: *mut ffi::rte_mempool,
    outer_tx_mbufs: &mut Vec<*mut ffi::rte_mbuf>,
    ip_id: &mut u16,
    checksum_mode: ChecksumMode,
    mss_clamp_val: u16,
) {
    // Copy packet and apply DNAT.
    let mut modified = ip_pkt.to_vec();
    nat::apply_dnat(&mut modified, dnat.orig_src_ip, dnat.orig_src_port);

    // MSS clamp on return path (SYN-ACK).
    if mss_clamp_val > 0 {
        mss::clamp_mss(&mut modified, mss_clamp_val);
    }

    let Some(entry) = connections.conn_view(&dnat.peer_cid) else {
        return;
    };

    let mut pkt_buf = [0u8; 2048];
    encrypt_and_send(
        &modified,
        entry,
        identity,
        mempool,
        outer_tx_mbufs,
        ip_id,
        checksum_mode,
        &mut pkt_buf,
    );
}

/// Encrypt an inner packet and build a QUIC frame for TX.
#[allow(clippy::too_many_arguments)]
fn encrypt_and_send(
    inner_pkt: &[u8],
    mut entry: ConnView<'_>,
    identity: &NetIdentity,
    mempool: *mut ffi::rte_mempool,
    outer_tx_mbufs: &mut Vec<*mut ffi::rte_mbuf>,
    ip_id: &mut u16,
    checksum_mode: ChecksumMode,
    pkt_buf: &mut [u8],
) {
    let max_quic_len = 1
        + entry.conn.remote_cid().len()
        + 4
        + 1
        + inner_pkt.len()
        + entry.conn.tag_len();
    let max_frame_len = net::HEADER_SIZE + max_quic_len;
    let Ok(max_frame_len_u16) = u16::try_from(max_frame_len) else {
        return;
    };

    if let Ok(mut tx_mbuf) = Mbuf::alloc(mempool) {
        if let Ok(buf) = tx_mbuf.alloc_space(max_frame_len_u16) {
            match entry.conn.encrypt_datagram(inner_pkt, &mut buf[net::HEADER_SIZE..]) {
                Ok(result) => {
                    let remote_ip = match entry.remote_addr.ip() {
                        std::net::IpAddr::V4(ip) => ip,
                        _ => Ipv4Addr::UNSPECIFIED,
                    };
                    *ip_id = ip_id.wrapping_add(1);
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
                        *ip_id,
                        checksum_mode,
                    );
                    tx_mbuf.truncate(actual_len as u16);
                    match checksum_mode {
                        ChecksumMode::HardwareUdpOnly => {
                            tx_mbuf.set_tx_udp_checksum_offload();
                        }
                        ChecksumMode::HardwareFull => {
                            tx_mbuf.set_tx_full_checksum_offload();
                        }
                        _ => {}
                    }
                    outer_tx_mbufs.push(tx_mbuf.into_raw());
                }
                Err(_) => {
                    // Encryption failed — mbuf dropped
                }
            }
        }
    }
}

/// Extract L4 source and destination ports from an IP packet.
fn extract_ports(ip_pkt: &[u8], proto: u8) -> (u16, u16) {
    let ihl = (ip_pkt[0] & 0x0f) as usize * 4;
    match proto {
        6 | 17 => {
            // TCP or UDP: ports at offset 0 and 2 of L4 header.
            if ip_pkt.len() >= ihl + 4 {
                let src = u16::from_be_bytes([ip_pkt[ihl], ip_pkt[ihl + 1]]);
                let dst = u16::from_be_bytes([ip_pkt[ihl + 2], ip_pkt[ihl + 3]]);
                (src, dst)
            } else {
                (0, 0)
            }
        }
        1 => {
            // ICMP: use ID as "port" for echo request/reply.
            if ip_pkt.len() >= ihl + 8 {
                let id = u16::from_be_bytes([ip_pkt[ihl + 4], ip_pkt[ihl + 5]]);
                (id, 0)
            } else {
                (0, 0)
            }
        }
        _ => (0, 0),
    }
}

/// Fix IP checksum after TTL decrement (incremental RFC 1624).
fn fix_ttl_checksum(ip_hdr: &mut [u8], old_ttl: u8) {
    let new_ttl = ip_hdr[8]; // already decremented by caller
    let old_word = u16::from_be_bytes([old_ttl, ip_hdr[9]]);
    let new_word = u16::from_be_bytes([new_ttl, ip_hdr[9]]);
    let old_cksum = u16::from_be_bytes([ip_hdr[10], ip_hdr[11]]);

    let mut sum: i32 = !(old_cksum) as u16 as i32;
    sum += !(old_word) as u16 as i32;
    sum += new_word as i32;
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    while sum < 0 {
        sum += 0x10000;
    }
    let new_cksum = !(sum as u16);
    ip_hdr[10..12].copy_from_slice(&new_cksum.to_be_bytes());
}

/// Drain quinn-proto transmits during handshake.
#[allow(clippy::too_many_arguments)]
fn drain_handshake_transmits(
    connection: &mut quinn_proto::Connection,
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
        let Some(transmit) = connection.poll_transmit(now, 1, transmit_buf) else {
            break;
        };
        let payload = &transmit_buf[..transmit.size];
        let remote = transmit.destination;
        let remote_ip = match remote.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => continue,
        };
        let dst_mac = arp_table.lookup(remote_ip).unwrap_or([0xff; 6]);

        let frame_len = net::HEADER_SIZE + payload.len();
        if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
            if let Ok(buf) = out_mbuf.alloc_space(frame_len as u16) {
                *ip_id = ip_id.wrapping_add(1);
                net::build_udp_packet(
                    &identity.local_mac,
                    &dst_mac,
                    identity.local_ip,
                    remote_ip,
                    identity.local_port,
                    remote.port(),
                    payload,
                    buf,
                    0,
                    *ip_id,
                    checksum_mode,
                );
                match checksum_mode {
                    ChecksumMode::HardwareUdpOnly => out_mbuf.set_tx_udp_checksum_offload(),
                    ChecksumMode::HardwareFull => out_mbuf.set_tx_full_checksum_offload(),
                    _ => {}
                }
                let raw = out_mbuf.into_raw();
                let mut tx = [raw];
                let sent = port::tx_burst(outer_port_id, queue_id, &mut tx, 1);
                if sent == 0 {
                    unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                } else {
                    *tx_count += 1;
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Multi-core router mode
// ═══════════════════════════════════════════════════════════════════════

/// Run the multi-core router dispatcher on core 0.
///
/// Classifies NIC RX packets and dispatches them to worker cores via rings.
/// Handles QUIC handshakes directly (no worker involvement).
#[allow(clippy::too_many_arguments)]
pub fn run_router_dispatcher(
    outer_port_id: u16,
    mempool: *mut ffi::rte_mempool,
    multi_state: &mut MultiQuicState,
    dispatch_table: &mut DpdkDispatchTable,
    workers: &[WorkerRings],
    identity: &NetIdentity,
    arp_table: &mut ArpTable,
    shutdown: &AtomicBool,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    peers: &[PeerConfig],
    enable_nat: bool,
    tunnel_ip: Ipv4Addr,
    n_workers: usize,
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
    let mut return_dispatch: u64 = 0;
    let mut arp_refresh_count: u64 = 0;
    let mut last_stats = Instant::now();
    let mut last_arp_refresh = Instant::now();

    // Adaptive polling.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    tracing::info!(n_workers, "router dispatcher started on core 0");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("router dispatcher: shutdown signal received");
            break;
        }

        if !multi_state.handshakes.is_empty() {
            now = Instant::now();
        }
        let mut had_work = false;

        // ── NIC RX burst → classify and dispatch ──

        let mut rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
        let nb_rx = port::rx_burst(outer_port_id, 0, &mut rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_rx as usize {
            let mbuf = unsafe { Mbuf::from_raw(rx_mbufs[i]) };
            rx_pkts += 1;
            let data = mbuf.data();

            match net::parse_packet_extended(data) {
                Some(ParsedPacket::Udp(udp)) => {
                    if udp.dst_port == identity.local_port && udp.dst_ip == identity.local_ip {
                        // QUIC packet destined for us.
                        if udp.payload.is_empty() {
                            continue;
                        }

                        arp_table.learn(udp.src_ip, udp.src_mac);

                        let first_byte = udp.payload[0];
                        if first_byte & 0x80 == 0 {
                            // Short header → dispatch by CID to worker.
                            if udp.payload.len() >= 1 + CID_LEN {
                                let cid_bytes = &udp.payload[1..1 + CID_LEN];
                                if let Some(worker_id) = dispatch_table.lookup_cid(cid_bytes) {
                                    let raw = mbuf.into_raw();
                                    if !workers[worker_id].outer_rx.enqueue(raw) {
                                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                    }
                                } else {
                                    dispatch_miss += 1;
                                }
                            }
                        } else {
                            // Long header → handshake on dispatcher.
                            rx_buf.clear();
                            rx_buf.extend_from_slice(udp.payload);
                            let quic_data = rx_buf.split();
                            let remote_addr =
                                SocketAddr::new(udp.src_ip.into(), udp.src_port);

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
                                    .unwrap_or([0xff; 6]);
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
                    } else if enable_nat {
                        // Non-QUIC UDP return traffic → dispatch by dst_port range to worker.
                        arp_table.learn(udp.src_ip, udp.src_mac);
                        if let Some(worker_id) =
                            nat::worker_for_port(udp.dst_port, n_workers)
                        {
                            return_dispatch += 1;
                            let raw = mbuf.into_raw();
                            if !workers[worker_id].outer_rx.enqueue(raw) {
                                unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                            }
                        }
                    }
                }
                Some(ParsedPacket::Ipv4Raw(ipv4)) => {
                    if !enable_nat {
                        continue;
                    }
                    arp_table.learn(ipv4.src_ip, ipv4.src_mac);

                    // Dispatch TCP/ICMP return traffic by port range.
                    let dst_port = match ipv4.protocol {
                        6 => {
                            // TCP: dst_port at offset 2-3 of TCP header.
                            let tcp_start = ipv4.ip_header_len;
                            if ipv4.payload.len() >= tcp_start + 4 {
                                u16::from_be_bytes([
                                    ipv4.payload[tcp_start + 2],
                                    ipv4.payload[tcp_start + 3],
                                ])
                            } else {
                                continue;
                            }
                        }
                        1 => {
                            // ICMP: use ID as port (echo reply, type 0).
                            let icmp_start = ipv4.ip_header_len;
                            if ipv4.payload.len() >= icmp_start + 8 {
                                let icmp_type = ipv4.payload[icmp_start];
                                if icmp_type == 0 {
                                    u16::from_be_bytes([
                                        ipv4.payload[icmp_start + 4],
                                        ipv4.payload[icmp_start + 5],
                                    ])
                                } else {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        }
                        _ => continue,
                    };

                    if let Some(worker_id) = nat::worker_for_port(dst_port, n_workers) {
                        return_dispatch += 1;
                        let raw = mbuf.into_raw();
                        if !workers[worker_id].outer_rx.enqueue(raw) {
                            unsafe { ffi::shim_rte_pktmbuf_free(raw) };
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
                None => {}
            }
        }

        if nb_rx > 0 {
            had_work = true;
        }

        // Refresh `now` only when there was actual work.
        if multi_state.handshakes.is_empty() && had_work {
            now = Instant::now();
        }

        // ── Drive handshakes (skip when no handshakes in progress) ──

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

                    // Send AddRouterConnection to the assigned worker.
                    if let Ok(mut ctrl) = workers[worker_id].control.lock() {
                        ctrl.push(ControlMessage::AddRouterConnection {
                            conn: resolved.conn,
                            tunnel_ip: resolved.tunnel_ip,
                            remote_addr: resolved.remote_addr,
                            remote_mac: resolved.remote_mac,
                            allowed_ips: resolved.allowed_ips.clone(),
                        });
                    }

                    // Broadcast PeerAssignment to ALL workers.
                    for w in workers {
                        if let Ok(mut ctrl) = w.control.lock() {
                            ctrl.push(ControlMessage::PeerAssignment {
                                peer_cid: resolved.cid,
                                tunnel_ip: resolved.tunnel_ip,
                                worker_id,
                                allowed_ips: resolved.allowed_ips.clone(),
                            });
                        }
                    }

                    tracing::info!(
                        tunnel_ip = %resolved.tunnel_ip,
                        worker = worker_id,
                        cid = %hex::encode(&resolved.cid_bytes),
                        "router: connection assigned to worker"
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
                if let Some(t) = hs.connection.poll_timeout() {
                    if now >= t {
                        hs.connection.handle_timeout(now);
                    }
                }
            }
        }

        // ── Drain worker TX rings (workers enqueue, dispatcher sends) ──

        for w in workers.iter() {
            let mut worker_tx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] =
                [std::ptr::null_mut(); BURST_SIZE];
            let nb_worker_tx = w.inner_tx.dequeue_burst(&mut worker_tx_mbufs);
            if nb_worker_tx > 0 {
                let n = nb_worker_tx as usize;
                let sent = port::tx_burst(
                    outer_port_id,
                    0,
                    &mut worker_tx_mbufs,
                    nb_worker_tx as u16,
                );
                tx_pkts += sent as u64;
                for raw in &worker_tx_mbufs[sent as usize..n] {
                    unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
                }
            }
        }

        // ── Send pending frames (handshake responses, ARP replies) ──

        for frame in pending_frames.drain(..) {
            if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
                if out_mbuf.write_packet(&frame).is_ok() {
                    match checksum_mode {
                        ChecksumMode::HardwareUdpOnly => out_mbuf.set_tx_udp_checksum_offload(),
                        ChecksumMode::HardwareFull => out_mbuf.set_tx_full_checksum_offload(),
                        _ => {}
                    }
                    let raw = out_mbuf.into_raw();
                    let mut tx = [raw];
                    let sent = port::tx_burst(outer_port_id, 0, &mut tx, 1);
                    if sent > 0 {
                        tx_pkts += 1;
                    } else {
                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                    }
                }
            }
        }

        // ── Stats ──

        // ARP refresh.
        if now.duration_since(last_arp_refresh) >= ARP_REFRESH_INTERVAL {
            let stale = arp_table.stale_entries(ARP_STALE_THRESHOLD_SECS);
            for stale_ip in &stale {
                let request = net::build_arp_request(identity.local_mac, identity.local_ip, *stale_ip);
                pending_frames.push(request);
                arp_refresh_count += 1;
            }
            last_arp_refresh = now;
        }

        if now.duration_since(last_stats) >= Duration::from_secs(10) {
            tracing::info!(
                rx = rx_pkts,
                tx = tx_pkts,
                dispatch_miss,
                return_dispatch,
                arp_refresh = arp_refresh_count,
                handshakes = multi_state.handshakes.len(),
                "router dispatcher stats"
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

/// Run a multi-core router worker on core N.
///
/// Drains outer_rx (QUIC + return traffic), decrypts, routes via RoutingTable,
/// and handles cross-core forwarding via forward_rx rings.
#[allow(clippy::too_many_arguments)]
pub fn run_router_worker(
    _outer_port_id: u16,
    _tx_queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    rings: &WorkerRings,
    workers: &[WorkerRings],
    identity: &NetIdentity,
    arp_table: &ArpTable,
    shutdown: &AtomicBool,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    peers: &[PeerConfig],
    enable_nat: bool,
    mss_clamp_val: u16,
    tunnel_ip: Ipv4Addr,
    tunnel_mtu: u16,
    core_id: usize,
    port_start: u16,
    port_end: u16,
) -> Result<()> {
    // Per-connection state.
    let mut connections: FxHashMap<u64, ConnectionEntry> = FxHashMap::default();
    let mut ip_to_cid: FxHashMap<Ipv4Addr, u64> = FxHashMap::default();
    // Peer CID → worker index (for cross-core forwarding).
    let mut peer_to_worker: FxHashMap<u64, usize> = FxHashMap::default();

    let worker_index = core_id - 1; // core_id is 1-based, worker_index is 0-based.

    // NAT table with partitioned port range.
    let mut nat_table = if enable_nat {
        NatTable::with_port_range(identity.local_ip, port_start, port_end)
    } else {
        NatTable::new(identity.local_ip) // won't be used
    };

    // Routing table — starts with peer config placeholders, rebuilt on PeerAssignment.
    let mut routing_table = RoutingTable::new(tunnel_ip, enable_nat);
    for peer in peers {
        let cid_key = u32::from(peer.tunnel_ip) as u64;
        routing_table.add_peer_routes(cid_key, &peer.allowed_ips);
    }

    let mut pkt_buf = [0u8; 2048];
    let mut ip_id: u16 = (core_id as u16).wrapping_mul(10000);

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut decrypt_fail: u64 = 0;
    let mut nat_forward: u64 = 0;
    let mut nat_reverse: u64 = 0;
    let mut hub_spoke: u64 = 0;
    let mut fwd_rx_count: u64 = 0;
    let mut fwd_rx_drop: u64 = 0;
    let mut ttl_drop: u64 = 0;
    let mut no_route_drop: u64 = 0;
    let mut frag_needed: u64 = 0;
    let mut mac_fail: u64 = 0;
    let mut last_stats = Instant::now();
    let mut last_nat_sweep = Instant::now();

    // Adaptive polling.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    // Reusable mbuf arrays.
    let mut outer_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
    let mut fwd_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
    let mut outer_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);

    tracing::info!(
        core = core_id,
        nat_ports = format!("{port_start}-{port_end}"),
        "router worker started"
    );

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!(core = core_id, "router worker: shutdown signal received");
            break;
        }

        let mut had_work = false;

        // ── 0. Check control channel ──

        if let Ok(mut ctrl) = rings.control.try_lock() {
            for msg in ctrl.drain(..) {
                match msg {
                    ControlMessage::AddRouterConnection {
                        conn,
                        tunnel_ip: peer_tunnel_ip,
                        remote_addr,
                        remote_mac,
                        allowed_ips,
                    } => {
                        let cid_bytes = conn.local_cid().to_vec();
                        let cid = cid_to_u64(&cid_bytes);
                        tracing::info!(
                            core = core_id,
                            tunnel_ip = %peer_tunnel_ip,
                            cid = %hex::encode(&cid_bytes),
                            "router worker: added connection"
                        );
                        ip_to_cid.insert(peer_tunnel_ip, cid);
                        connections.insert(
                            cid,
                            ConnectionEntry {
                                conn,
                                tunnel_ip: peer_tunnel_ip,
                                remote_addr,
                                remote_mac,
                            },
                        );
                        // Rebuild routing table with this connection's real CID.
                        rebuild_routing_table(
                            &mut routing_table,
                            tunnel_ip,
                            enable_nat,
                            peers,
                            &ip_to_cid,
                            &peer_to_worker,
                        );
                        let _ = allowed_ips; // used via PeerAssignment broadcast
                    }
                    ControlMessage::PeerAssignment {
                        peer_cid,
                        tunnel_ip: peer_tunnel_ip,
                        worker_id,
                        allowed_ips: _,
                    } => {
                        peer_to_worker.insert(peer_cid, worker_id);
                        // Also map tunnel_ip → cid if not already known.
                        ip_to_cid.entry(peer_tunnel_ip).or_insert(peer_cid);
                        // Rebuild routing table with real CID.
                        rebuild_routing_table(
                            &mut routing_table,
                            tunnel_ip,
                            enable_nat,
                            peers,
                            &ip_to_cid,
                            &peer_to_worker,
                        );
                    }
                    ControlMessage::AddConnection { .. }
                    | ControlMessage::RemoveConnection { .. } => {
                        // Not used in router mode.
                    }
                }
            }
        }

        // ── 1. Drain outer_rx ring ──

        let nb_rx = rings.outer_rx.dequeue_burst(&mut outer_rx_mbufs);
        outer_tx_mbufs.clear();

        for i in 0..nb_rx as usize {
            let mut mbuf = unsafe { Mbuf::from_raw(outer_rx_mbufs[i]) };
            rx_pkts += 1;
            let data = mbuf.data_mut();

            match net::parse_packet_extended(data) {
                Some(ParsedPacket::Udp(udp)) => {
                    if udp.dst_port == identity.local_port && udp.dst_ip == identity.local_ip {
                        // QUIC short header packet (dispatcher already verified this).
                        if udp.payload.is_empty() {
                            continue;
                        }

                        let payload_offset =
                            unsafe { udp.payload.as_ptr().offset_from(data.as_ptr()) as usize };
                        let payload_len = udp.payload.len();

                        if payload_len < 1 + CID_LEN {
                            continue;
                        }
                        let cid_key = cid_to_u64(
                            &data[payload_offset + 1..payload_offset + 1 + CID_LEN],
                        );

                        let src_mac = udp.src_mac;
                        let src_ip = udp.src_ip;
                        let src_port = udp.src_port;
                        let decrypt_result = {
                            let Some(entry) = connections.get_mut(&cid_key) else {
                                decrypt_fail += 1;
                                continue;
                            };
                            match entry.conn.decrypt_packet_in_place(
                                &mut data[payload_offset..payload_offset + payload_len],
                            ) {
                                Ok(decrypted) => {
                                    // Update peer address on every authenticated packet.
                                    entry.remote_addr = SocketAddr::new(src_ip.into(), src_port);
                                    entry.remote_mac = src_mac;

                                    if let Some(ref ack) = decrypted.ack {
                                        entry.conn.process_ack(ack);
                                    }
                                    let ranges: Vec<(usize, usize)> = decrypted
                                        .datagrams
                                        .iter()
                                        .map(|r| {
                                            (payload_offset + r.start, payload_offset + r.end)
                                        })
                                        .collect();
                                    Some((ranges, entry.tunnel_ip))
                                }
                                Err(_) => {
                                    decrypt_fail += 1;
                                    None
                                }
                            }
                        };

                        if let Some((ranges, src_tunnel_ip)) = decrypt_result {
                            for (abs_start, abs_end) in &ranges {
                                let inner_pkt = &data[*abs_start..*abs_end];

                                if inner_pkt.len() < 20 {
                                    continue;
                                }

                                if mss_clamp_val > 0 {
                                    let inner_mut = &mut data[*abs_start..*abs_end];
                                    mss::clamp_mss(inner_mut, mss_clamp_val);
                                }

                                let inner_pkt = &data[*abs_start..*abs_end];

                                // Find the CID for the source connection.
                                let src_cid = cid_to_u64(
                                    &data[payload_offset + 1..payload_offset + 1 + CID_LEN],
                                );

                                // Fragmentation Needed check.
                                if tunnel_mtu > 0 && inner_pkt.len() > tunnel_mtu as usize {
                                    let df_set = (inner_pkt[6] & 0x40) != 0;
                                    if df_set {
                                        frag_needed += 1;
                                        if let Some(icmp_pkt) = icmp::build_frag_needed(inner_pkt, tunnel_ip, tunnel_mtu) {
                                            if let Some(entry) = connections.get_mut(&src_cid) {
                                                encrypt_and_send(
                                                    &icmp_pkt,
                                                    entry.into(),
                                                    identity,
                                                    mempool,
                                                    &mut outer_tx_mbufs,
                                                    &mut ip_id,
                                                    checksum_mode,
                                                    &mut pkt_buf,
                                                );
                                            }
                                        }
                                        continue;
                                    }
                                }

                                let dst_ip = Ipv4Addr::new(
                                    inner_pkt[16],
                                    inner_pkt[17],
                                    inner_pkt[18],
                                    inner_pkt[19],
                                );

                                match routing_table.lookup(dst_ip) {
                                    RouteAction::ForwardToPeer(peer_cid) => {
                                        // Check if peer is on this worker or another.
                                        let target_worker = peer_to_worker
                                            .get(&peer_cid)
                                            .copied();

                                        if target_worker == Some(worker_index)
                                            || target_worker.is_none()
                                        {
                                            // Same worker: encrypt and TX directly.
                                            if let Some(peer_entry) =
                                                connections.get_mut(&peer_cid)
                                            {
                                                hub_spoke += 1;
                                                encrypt_and_send(
                                                    inner_pkt,
                                                    peer_entry.into(),
                                                    identity,
                                                    mempool,
                                                    &mut outer_tx_mbufs,
                                                    &mut ip_id,
                                                    checksum_mode,
                                                    &mut pkt_buf,
                                                );
                                            }
                                        } else {
                                            // Different worker: forward via forward_rx ring.
                                            let target_w = target_worker.expect("checked above");
                                            if let Ok(mut fwd_mbuf) = Mbuf::alloc(mempool) {
                                                if fwd_mbuf
                                                    .write_packet(inner_pkt)
                                                    .is_ok()
                                                {
                                                    let raw = fwd_mbuf.into_raw();
                                                    if !workers[target_w]
                                                        .forward_rx
                                                        .enqueue_mp(raw)
                                                    {
                                                        unsafe {
                                                            ffi::shim_rte_pktmbuf_free(raw)
                                                        };
                                                        fwd_rx_drop += 1;
                                                    } else {
                                                        hub_spoke += 1;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    RouteAction::ForwardExternal => {
                                        if !enable_nat {
                                            continue;
                                        }
                                        nat_forward += 1;

                                        let proto = inner_pkt[9];
                                        let src_ip = Ipv4Addr::new(
                                            inner_pkt[12],
                                            inner_pkt[13],
                                            inner_pkt[14],
                                            inner_pkt[15],
                                        );
                                        let (src_port, dst_port) =
                                            extract_ports(inner_pkt, proto);

                                        let nat_key = NatForwardKey {
                                            proto,
                                            src_ip,
                                            src_port,
                                            dst_ip,
                                            dst_port,
                                        };

                                        let Some(snat_result) = nat_table.lookup_or_create(
                                            &nat_key,
                                            src_cid,
                                            src_tunnel_ip,
                                            now,
                                        ) else {
                                            continue;
                                        };

                                        let dst_mac = arp_table.lookup(dst_ip);
                                        let Some(dst_mac) = dst_mac else {
                                            mac_fail += 1;
                                            continue;
                                        };

                                        let frame_len = ETH_HLEN + inner_pkt.len();
                                        if frame_len > pkt_buf.len() {
                                            continue;
                                        }

                                        pkt_buf[0..6].copy_from_slice(&dst_mac);
                                        pkt_buf[6..12].copy_from_slice(&identity.local_mac);
                                        pkt_buf[12..14].copy_from_slice(&[0x08, 0x00]);
                                        pkt_buf[ETH_HLEN..frame_len]
                                            .copy_from_slice(inner_pkt);

                                        nat::apply_snat(
                                            &mut pkt_buf[ETH_HLEN..frame_len],
                                            identity.local_ip,
                                            snat_result.nat_port,
                                        );

                                        let ttl = pkt_buf[ETH_HLEN + 8];
                                        if ttl <= 1 {
                                            ttl_drop += 1;
                                            if let Some(icmp_pkt) = icmp::build_time_exceeded(inner_pkt, tunnel_ip) {
                                                if let Some(entry) = connections.get_mut(&src_cid) {
                                                    encrypt_and_send(
                                                        &icmp_pkt,
                                                        entry.into(),
                                                        identity,
                                                        mempool,
                                                        &mut outer_tx_mbufs,
                                                        &mut ip_id,
                                                        checksum_mode,
                                                        &mut pkt_buf,
                                                    );
                                                }
                                            }
                                            continue;
                                        }
                                        pkt_buf[ETH_HLEN + 8] = ttl - 1;
                                        fix_ttl_checksum(&mut pkt_buf[ETH_HLEN..], ttl);

                                        if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
                                            if out_mbuf
                                                .write_packet(&pkt_buf[..frame_len])
                                                .is_ok()
                                            {
                                                outer_tx_mbufs.push(out_mbuf.into_raw());
                                            }
                                        }
                                    }
                                    RouteAction::Local => {
                                        let mut reply = inner_pkt.to_vec();
                                        if quictun_core::icmp::echo_reply_inplace(&mut reply) {
                                            if let Some(entry) =
                                                connections.get_mut(&src_cid)
                                            {
                                                encrypt_and_send(
                                                    &reply,
                                                    entry.into(),
                                                    identity,
                                                    mempool,
                                                    &mut outer_tx_mbufs,
                                                    &mut ip_id,
                                                    checksum_mode,
                                                    &mut pkt_buf,
                                                );
                                            }
                                        }
                                    }
                                    RouteAction::Drop => {
                                        no_route_drop += 1;
                                        if let Some(icmp_pkt) = icmp::build_dest_unreachable(inner_pkt, tunnel_ip, 0) {
                                            if let Some(entry) = connections.get_mut(&src_cid) {
                                                encrypt_and_send(
                                                    &icmp_pkt,
                                                    entry.into(),
                                                    identity,
                                                    mempool,
                                                    &mut outer_tx_mbufs,
                                                    &mut ip_id,
                                                    checksum_mode,
                                                    &mut pkt_buf,
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } else if enable_nat {
                        // Return traffic (non-QUIC UDP) dispatched by port range.
                        let ip_start = ETH_HLEN;
                        let ip_pkt = &data[ip_start..];

                        if let Some(dnat_result) = nat_table.lookup_reverse(
                            17,
                            udp.dst_port,
                            udp.src_ip,
                            udp.src_port,
                            now,
                        ) {
                            nat_reverse += 1;
                            encrypt_return_to_peer(
                                ip_pkt,
                                &dnat_result,
                                &mut connections,
                                identity,
                                arp_table,
                                mempool,
                                &mut outer_tx_mbufs,
                                &mut ip_id,
                                checksum_mode,
                                mss_clamp_val,
                            );
                        }
                    }
                }
                Some(ParsedPacket::Ipv4Raw(ipv4)) => {
                    if !enable_nat {
                        continue;
                    }
                    // Non-UDP return traffic (TCP, ICMP).
                    if ipv4.protocol == 6 {
                        let tcp_start = ipv4.ip_header_len;
                        if ipv4.payload.len() >= tcp_start + 4 {
                            let dst_port = u16::from_be_bytes([
                                ipv4.payload[tcp_start + 2],
                                ipv4.payload[tcp_start + 3],
                            ]);
                            let src_port = u16::from_be_bytes([
                                ipv4.payload[tcp_start],
                                ipv4.payload[tcp_start + 1],
                            ]);

                            if let Some(dnat_result) =
                                nat_table.lookup_reverse(6, dst_port, ipv4.src_ip, src_port, now)
                            {
                                nat_reverse += 1;
                                encrypt_return_to_peer(
                                    ipv4.payload,
                                    &dnat_result,
                                    &mut connections,
                                    identity,
                                    arp_table,
                                    mempool,
                                    &mut outer_tx_mbufs,
                                    &mut ip_id,
                                    checksum_mode,
                                    mss_clamp_val,
                                );
                            }
                        }
                    } else if ipv4.protocol == 1 {
                        let icmp_start = ipv4.ip_header_len;
                        if ipv4.payload.len() >= icmp_start + 8 {
                            let icmp_type = ipv4.payload[icmp_start];
                            if icmp_type == 0 {
                                let icmp_id = u16::from_be_bytes([
                                    ipv4.payload[icmp_start + 4],
                                    ipv4.payload[icmp_start + 5],
                                ]);
                                if let Some(dnat_result) = nat_table.lookup_reverse(
                                    1, icmp_id, ipv4.src_ip, 0, now,
                                ) {
                                    nat_reverse += 1;
                                    encrypt_return_to_peer(
                                        ipv4.payload,
                                        &dnat_result,
                                        &mut connections,
                                        identity,
                                        arp_table,
                                        mempool,
                                        &mut outer_tx_mbufs,
                                        &mut ip_id,
                                        checksum_mode,
                                        mss_clamp_val,
                                    );
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if nb_rx > 0 {
            had_work = true;
        }

        // ── 2. Drain forward_rx ring (packets from other workers to encrypt for local peers) ──

        let nb_fwd = rings.forward_rx.dequeue_burst(&mut fwd_rx_mbufs);

        for i in 0..nb_fwd as usize {
            let mbuf = unsafe { Mbuf::from_raw(fwd_rx_mbufs[i]) };
            let data = mbuf.data();
            fwd_rx_count += 1;

            // This is a raw IP packet. Find the destination peer and encrypt.
            if data.len() < 20 {
                continue;
            }
            let dst_ip = Ipv4Addr::new(data[16], data[17], data[18], data[19]);

            if let Some(&cid) = ip_to_cid.get(&dst_ip) {
                if let Some(entry) = connections.get_mut(&cid) {
                    encrypt_and_send(
                        data,
                        entry.into(),
                        identity,
                        mempool,
                        &mut outer_tx_mbufs,
                        &mut ip_id,
                        checksum_mode,
                        &mut pkt_buf,
                    );
                }
            }
        }

        if nb_fwd > 0 {
            had_work = true;
        }

        // ── 3. TX: enqueue to inner_tx ring for dispatcher to send ──
        // Workers cannot TX directly — virtio doesn't support multi-queue TX.
        // Dispatcher drains inner_tx and sends on TX queue 0.

        if !outer_tx_mbufs.is_empty() {
            for raw in &outer_tx_mbufs {
                if !rings.inner_tx.enqueue(*raw) {
                    unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
                }
            }
            tx_pkts += outer_tx_mbufs.len() as u64;
        }

        // ── 4. Periodic tasks ──

        if had_work {
            now = Instant::now();
        }

        // NAT sweep.
        if enable_nat && now.duration_since(last_nat_sweep) >= NAT_SWEEP_INTERVAL {
            now = Instant::now();
            let before = nat_table.len();
            nat_table.sweep(now);
            let expired = before - nat_table.len();
            if expired > 0 {
                tracing::debug!(core = core_id, expired, remaining = nat_table.len(), "NAT sweep");
            }
            last_nat_sweep = now;
        }

        // Stats.
        if now.duration_since(last_stats) >= Duration::from_secs(10) {
            now = Instant::now();
            tracing::info!(
                core = core_id,
                rx = rx_pkts,
                tx = tx_pkts,
                decrypt_fail,
                nat_fwd = nat_forward,
                nat_rev = nat_reverse,
                hub_spoke,
                fwd_rx = fwd_rx_count,
                fwd_rx_drop,
                ttl_drop,
                no_route_drop,
                frag_needed,
                mac_fail,
                nat_entries = nat_table.len(),
                connections = connections.len(),
                "router worker stats"
            );
            last_stats = now;
        }

        // Adaptive polling.
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

/// Rebuild the routing table from peer configs using real CIDs where available.
fn rebuild_routing_table(
    routing_table: &mut RoutingTable,
    tunnel_ip: Ipv4Addr,
    enable_nat: bool,
    peers: &[PeerConfig],
    ip_to_cid: &FxHashMap<Ipv4Addr, u64>,
    _peer_to_worker: &FxHashMap<u64, usize>,
) {
    *routing_table = RoutingTable::new(tunnel_ip, enable_nat);
    for peer in peers {
        let cid_key = ip_to_cid
            .get(&peer.tunnel_ip)
            .copied()
            .unwrap_or(u32::from(peer.tunnel_ip) as u64);
        routing_table.add_peer_routes(cid_key, &peer.allowed_ips);
    }
}

// ═══════════════════════════════════════════════════════════════════════
//  Router pipeline (SharedConnectionState)
// ═══════════════════════════════════════════════════════════════════════

/// ACK generation interval for router pipeline I/O.
const ROUTER_ACK_INTERVAL: Duration = Duration::from_millis(25);

/// Run the router pipeline I/O thread on core 0.
///
/// Core 0 responsibilities:
/// - Outer RX: parse, handshake (long header), round-robin short header to workers
/// - NAT return traffic: route by dst_port to worker via `return_rx`
/// - Handshake driving, ACK, keepalive, key rotation, ARP
#[allow(clippy::too_many_arguments)]
pub fn run_router_pipeline_io(
    outer_port_id: u16,
    mempool: *mut ffi::rte_mempool,
    multi_state: &mut MultiQuicState,
    workers: &[RouterPipelineRings],
    identity: &NetIdentity,
    arp_table: &mut ArpTable,
    shutdown: &AtomicBool,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    peers: &[PeerConfig],
    enable_nat: bool,
    tunnel_ip: Ipv4Addr,
    n_workers: usize,
    max_peers: usize,
    idle_timeout: Duration,
) -> Result<()> {
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
        enable_nat,
        max_peers,
        idle_timeout,
    );

    // Round-robin counter for worker dispatch.
    let mut rr_decrypt: usize = 0;

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut dispatch_drop: u64 = 0;
    let mut return_dispatch: u64 = 0;
    let mut arp_refresh_count: u64 = 0;
    let mut last_stats = Instant::now();
    let mut last_arp_refresh = Instant::now();

    // Timer state.
    let mut last_ack = Instant::now();

    // Adaptive polling.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    tracing::info!(n_workers, "router pipeline I/O started on core 0");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("router pipeline I/O: shutdown signal received");
            break;
        }

        // During handshake, quinn-proto needs accurate time every iteration.
        // After all handshakes complete, skip clock_gettime (saves ~4% CPU).
        if !multi_state.handshakes.is_empty() {
            now = Instant::now();
        }
        let mut had_work = false;

        // ── 1. NIC RX burst → classify and dispatch ──

        let mut rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
        let nb_rx = port::rx_burst(outer_port_id, 0, &mut rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_rx as usize {
            let mbuf = unsafe { Mbuf::from_raw(rx_mbufs[i]) };
            rx_pkts += 1;
            let data = mbuf.data();

            match net::parse_packet_extended(data) {
                Some(ParsedPacket::Udp(udp)) => {
                    if udp.dst_port == identity.local_port && udp.dst_ip == identity.local_ip {
                        if udp.payload.is_empty() {
                            continue;
                        }

                        arp_table.learn(udp.src_ip, udp.src_mac);

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
                            // Long header → handshake on core 0.
                            rx_buf.clear();
                            rx_buf.extend_from_slice(udp.payload);
                            let quic_data = rx_buf.split();
                            let remote_addr =
                                SocketAddr::new(udp.src_ip.into(), udp.src_port);

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
                                    .unwrap_or([0xff; 6]);
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
                    } else if enable_nat {
                        // Non-QUIC UDP return traffic → dispatch by dst_port to worker.
                        arp_table.learn(udp.src_ip, udp.src_mac);
                        if let Some(worker_id) = nat::worker_for_port(udp.dst_port, n_workers) {
                            return_dispatch += 1;
                            let raw = mbuf.into_raw();
                            if !workers[worker_id].return_rx.enqueue(raw) {
                                unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                                dispatch_drop += 1;
                            }
                        }
                    }
                }
                Some(ParsedPacket::Ipv4Raw(ipv4)) => {
                    if !enable_nat {
                        continue;
                    }
                    arp_table.learn(ipv4.src_ip, ipv4.src_mac);

                    // Dispatch TCP/ICMP return traffic by port range.
                    let dst_port = match ipv4.protocol {
                        6 => {
                            let tcp_start = ipv4.ip_header_len;
                            if ipv4.payload.len() >= tcp_start + 4 {
                                u16::from_be_bytes([
                                    ipv4.payload[tcp_start + 2],
                                    ipv4.payload[tcp_start + 3],
                                ])
                            } else {
                                continue;
                            }
                        }
                        1 => {
                            let icmp_start = ipv4.ip_header_len;
                            if ipv4.payload.len() >= icmp_start + 8 {
                                let icmp_type = ipv4.payload[icmp_start];
                                if icmp_type == 0 {
                                    u16::from_be_bytes([
                                        ipv4.payload[icmp_start + 4],
                                        ipv4.payload[icmp_start + 5],
                                    ])
                                } else {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        }
                        _ => continue,
                    };

                    if let Some(worker_id) = nat::worker_for_port(dst_port, n_workers) {
                        return_dispatch += 1;
                        let raw = mbuf.into_raw();
                        if !workers[worker_id].return_rx.enqueue(raw) {
                            unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                            dispatch_drop += 1;
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
                None => {}
            }
        }

        if nb_rx > 0 {
            had_work = true;
        }

        // Refresh `now` only when there was actual work (skip clock_gettime on idle polls).
        if multi_state.handshakes.is_empty() && had_work {
            now = Instant::now();
        }

        // ── 2. Drive handshakes (skip entirely when no handshakes in progress) ──

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
                                    "router pipeline: evicted stale connection"
                                );
                                // Notify workers to remove evicted connection.
                                for worker in workers.iter() {
                                    if let Ok(mut ctrl) = worker.control.lock() {
                                        ctrl.push(RouterPipelineControlMessage::RemoveConnection {
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
                                    ctrl.push(RouterPipelineControlMessage::AddConnection {
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
                                        allowed_ips: allowed_ips.clone(),
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
                            });

                            tracing::info!(
                                tunnel_ip = %peer_ip,
                                remote = %remote_addr,
                                cid = %hex::encode(&cid_bytes),
                                n_workers,
                                "router pipeline: connection broadcast to all workers"
                            );
                        }
                        PromoteResult::Rejected { remote_addr, reason, .. } => {
                            tracing::warn!(
                                remote = %remote_addr,
                                reason = ?reason,
                                "router pipeline: handshake rejected"
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

        // ── 3. Send pending raw frames ──

        for frame in pending_frames.drain(..) {
            if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
                if out_mbuf.write_packet(&frame).is_ok() {
                    match checksum_mode {
                        ChecksumMode::HardwareUdpOnly => out_mbuf.set_tx_udp_checksum_offload(),
                        ChecksumMode::HardwareFull => out_mbuf.set_tx_full_checksum_offload(),
                        _ => {}
                    }
                    let raw = out_mbuf.into_raw();
                    let mut tx = [raw];
                    let sent = port::tx_burst(outer_port_id, 0, &mut tx, 1);
                    if sent > 0 {
                        tx_pkts += 1;
                    } else {
                        unsafe { ffi::shim_rte_pktmbuf_free(raw) };
                    }
                }
            }
        }

        // ── 4. Timer-driven ACK generation (every ~25ms) ──

        if now.duration_since(last_ack) >= ROUTER_ACK_INTERVAL {
            for (_, entry) in manager.iter() {
                if entry.conn.replay.needs_ack() {
                    match entry.conn.encrypt_ack(&mut ack_buf) {
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
                            tracing::trace!(error = %e, "router pipeline: ACK encrypt failed");
                        }
                    }
                }
            }
            last_ack = now;
        }

        // ── 5. Sweep timeouts (idle, key exhaustion, keepalive) ──

        {
            let actions = manager.sweep_timeouts();
            for action in actions {
                match action {
                    ManagerAction::SendKeepalive { cid_key } => {
                        if let Some(entry) = manager.get_mut(&cid_key) {
                            let mut ka_buf = [0u8; 256];
                            if let Ok(result) = entry.conn.tx.encrypt_datagram(&[], &mut ka_buf) {
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
                            "router pipeline: connection removed by sweep"
                        );
                        // Notify workers to remove the connection.
                        for worker in workers.iter() {
                            if let Ok(mut ctrl) = worker.control.lock() {
                                ctrl.push(RouterPipelineControlMessage::RemoveConnection {
                                    cid: cid_key,
                                });
                            }
                        }
                    }
                }
            }
        }

        // ── 6. Key rotation ──

        if nb_rx > 0 && !manager.is_empty() {
            let per_conn = nb_rx as u64 / manager.len() as u64;
            if per_conn > 0 {
                for (_, entry) in manager.iter() {
                    entry.conn.maybe_initiate_key_update(per_conn);
                }
            }
        }

        // ── 7. ARP refresh ──

        if now.duration_since(last_arp_refresh) >= ARP_REFRESH_INTERVAL {
            let stale = arp_table.stale_entries(ARP_STALE_THRESHOLD_SECS);
            for stale_ip in &stale {
                let request =
                    net::build_arp_request(identity.local_mac, identity.local_ip, *stale_ip);
                pending_frames.push(request);
                arp_refresh_count += 1;
            }
            last_arp_refresh = now;
        }

        // ── Stats ──

        if now.duration_since(last_stats) >= Duration::from_secs(10) {
            tracing::info!(
                rx = rx_pkts,
                tx = tx_pkts,
                dispatch_drop,
                return_dispatch,
                arp_refresh = arp_refresh_count,
                connections = manager.len(),
                handshakes = multi_state.handshakes.len(),
                "router pipeline I/O stats"
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

/// Run a router pipeline worker on core N.
///
/// Workers share `Arc<SharedConnectionState>` for all connections.
/// - `decrypt_rx`: dequeue outer QUIC packets → decrypt → route → NAT → encrypt → direct TX
/// - `return_rx`: dequeue NAT return traffic → reverse NAT → encrypt to peer → direct TX
#[allow(clippy::too_many_arguments)]
pub fn run_router_pipeline_worker(
    outer_port_id: u16,
    tx_queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    rings: &RouterPipelineRings,
    identity: &NetIdentity,
    arp_table: &ArpTable,
    shutdown: &AtomicBool,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    peers: &[PeerConfig],
    enable_nat: bool,
    mss_clamp_val: u16,
    tunnel_ip: Ipv4Addr,
    tunnel_mtu: u16,
    core_id: usize,
    port_start: u16,
    port_end: u16,
) -> Result<()> {
    // All connections (shared state): CID (as u64) → pipeline connection entry.
    let mut connections: FxHashMap<u64, RouterPipelineConnection> = FxHashMap::default();
    // Tunnel IP → CID for routing.
    let mut ip_to_cid: FxHashMap<Ipv4Addr, u64> = FxHashMap::default();

    // NAT table with partitioned port range.
    let mut nat_table = if enable_nat {
        NatTable::with_port_range(identity.local_ip, port_start, port_end)
    } else {
        NatTable::new(identity.local_ip)
    };

    // Routing table — starts with peer config placeholders, rebuilt on AddConnection.
    let mut routing_table = RoutingTable::new(tunnel_ip, enable_nat);
    for peer in peers {
        let cid_key = u32::from(peer.tunnel_ip) as u64;
        routing_table.add_peer_routes(cid_key, &peer.allowed_ips);
    }

    let mut pkt_buf = [0u8; 2048];
    let mut ip_id: u16 = (core_id as u16).wrapping_mul(10000);

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut decrypt_ok: u64 = 0;
    let mut decrypt_fail: u64 = 0;
    let mut nat_forward: u64 = 0;
    let mut nat_reverse: u64 = 0;
    let mut hub_spoke: u64 = 0;
    let mut ttl_drop: u64 = 0;
    let mut no_route_drop: u64 = 0;
    let mut frag_needed: u64 = 0;
    let mut mac_fail: u64 = 0;
    let mut last_stats = Instant::now();
    let mut last_nat_sweep = Instant::now();

    // Adaptive polling.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;
    let mut now = Instant::now();

    // Reusable mbuf arrays.
    let mut dec_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
    let mut ret_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] = [std::ptr::null_mut(); BURST_SIZE];
    let mut outer_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);

    tracing::info!(
        core = core_id,
        tx_queue = tx_queue_id,
        nat_ports = format!("{port_start}-{port_end}"),
        "router pipeline worker started"
    );

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!(core = core_id, "router pipeline worker: shutdown");
            break;
        }

        let mut had_work = false;

        // ── 0. Check control channel ──

        if let Ok(mut ctrl) = rings.control.try_lock() {
            for msg in ctrl.drain(..) {
                match msg {
                    RouterPipelineControlMessage::AddConnection {
                        conn,
                        tunnel_ip: peer_tunnel_ip,
                        remote_addr,
                        remote_mac,
                        cid,
                        allowed_ips,
                    } => {
                        tracing::info!(
                            core = core_id,
                            tunnel_ip = %peer_tunnel_ip,
                            "router pipeline worker: added connection"
                        );
                        ip_to_cid.insert(peer_tunnel_ip, cid);
                        connections.insert(cid, RouterPipelineConnection {
                            conn,
                            tunnel_ip: peer_tunnel_ip,
                            remote_addr,
                            remote_mac,
                        });
                        // Rebuild routing table with real CID.
                        rebuild_routing_table_shared(
                            &mut routing_table,
                            tunnel_ip,
                            enable_nat,
                            peers,
                            &ip_to_cid,
                        );
                        let _ = allowed_ips; // routes come from peer config
                    }
                    RouterPipelineControlMessage::RemoveConnection { cid } => {
                        if let Some(entry) = connections.remove(&cid) {
                            ip_to_cid.remove(&entry.tunnel_ip);
                            tracing::info!(
                                core = core_id,
                                tunnel_ip = %entry.tunnel_ip,
                                "router pipeline worker: removed connection"
                            );
                            rebuild_routing_table_shared(
                                &mut routing_table,
                                tunnel_ip,
                                enable_nat,
                                peers,
                                &ip_to_cid,
                            );
                        }
                    }
                }
            }
        }

        // ── 1. Decrypt RX: dequeue → decrypt → route → NAT → encrypt → direct TX ──

        let nb_dec = rings.decrypt_rx.dequeue_burst(&mut dec_rx_mbufs);
        outer_tx_mbufs.clear();

        for i in 0..nb_dec as usize {
            let mut mbuf = unsafe { Mbuf::from_raw(dec_rx_mbufs[i]) };
            rx_pkts += 1;
            let data = mbuf.data_mut();

            let Some(ParsedPacket::Udp(udp)) = net::parse_packet_extended(data) else {
                continue;
            };
            if udp.payload.is_empty() || udp.payload[0] & 0x80 != 0 {
                continue;
            }

            let payload_offset =
                unsafe { udp.payload.as_ptr().offset_from(data.as_ptr()) as usize };
            let payload_len = udp.payload.len();

            if payload_len < 1 + CID_LEN {
                continue;
            }
            let cid_key = cid_to_u64(&data[payload_offset + 1..payload_offset + 1 + CID_LEN]);

            let Some(entry) = connections.get(&cid_key) else {
                decrypt_fail += 1;
                continue;
            };

            let src_tunnel_ip = entry.tunnel_ip;

            match entry.conn.decrypt_in_place(
                &mut data[payload_offset..payload_offset + payload_len],
            ) {
                Ok(decrypted) => {
                    decrypt_ok += 1;

                    if let Some(ref ack) = decrypted.ack {
                        entry.conn.process_ack(ack);
                    }

                    for range in &decrypted.datagrams {
                        let abs_start = payload_offset + range.start;
                        let abs_end = payload_offset + range.end;
                        let inner_pkt = &data[abs_start..abs_end];

                        if inner_pkt.len() < 20 {
                            continue;
                        }

                        if mss_clamp_val > 0 {
                            let inner_mut = &mut data[abs_start..abs_end];
                            mss::clamp_mss(inner_mut, mss_clamp_val);
                        }

                        let inner_pkt = &data[abs_start..abs_end];

                        // Fragmentation Needed check.
                        if tunnel_mtu > 0 && inner_pkt.len() > tunnel_mtu as usize {
                            let df_set = (inner_pkt[6] & 0x40) != 0;
                            if df_set {
                                frag_needed += 1;
                                if let Some(icmp_pkt) =
                                    icmp::build_frag_needed(inner_pkt, tunnel_ip, tunnel_mtu)
                                {
                                    encrypt_and_send_shared(
                                        &icmp_pkt,
                                        entry,
                                        identity,
                                        mempool,
                                        &mut outer_tx_mbufs,
                                        &mut ip_id,
                                        checksum_mode,
                                    );
                                }
                                continue;
                            }
                        }

                        let dst_ip = Ipv4Addr::new(
                            inner_pkt[16],
                            inner_pkt[17],
                            inner_pkt[18],
                            inner_pkt[19],
                        );

                        match routing_table.lookup(dst_ip) {
                            RouteAction::ForwardToPeer(peer_cid) => {
                                // All workers have all connections → encrypt locally.
                                if let Some(peer_entry) = connections.get(&peer_cid) {
                                    hub_spoke += 1;
                                    encrypt_and_send_shared(
                                        inner_pkt,
                                        peer_entry,
                                        identity,
                                        mempool,
                                        &mut outer_tx_mbufs,
                                        &mut ip_id,
                                        checksum_mode,
                                    );
                                }
                            }
                            RouteAction::ForwardExternal => {
                                if !enable_nat {
                                    continue;
                                }
                                nat_forward += 1;

                                let proto = inner_pkt[9];
                                let src_ip = Ipv4Addr::new(
                                    inner_pkt[12],
                                    inner_pkt[13],
                                    inner_pkt[14],
                                    inner_pkt[15],
                                );
                                let (src_port, dst_port) = extract_ports(inner_pkt, proto);

                                let nat_key = NatForwardKey {
                                    proto,
                                    src_ip,
                                    src_port,
                                    dst_ip,
                                    dst_port,
                                };

                                let Some(snat_result) = nat_table.lookup_or_create(
                                    &nat_key,
                                    cid_key,
                                    src_tunnel_ip,
                                    now,
                                ) else {
                                    continue;
                                };

                                let Some(dst_mac) = arp_table.lookup(dst_ip) else {
                                    mac_fail += 1;
                                    continue;
                                };

                                let frame_len = ETH_HLEN + inner_pkt.len();
                                if frame_len > pkt_buf.len() {
                                    continue;
                                }

                                pkt_buf[0..6].copy_from_slice(&dst_mac);
                                pkt_buf[6..12].copy_from_slice(&identity.local_mac);
                                pkt_buf[12..14].copy_from_slice(&[0x08, 0x00]);
                                pkt_buf[ETH_HLEN..frame_len].copy_from_slice(inner_pkt);

                                nat::apply_snat(
                                    &mut pkt_buf[ETH_HLEN..frame_len],
                                    identity.local_ip,
                                    snat_result.nat_port,
                                );

                                let ttl = pkt_buf[ETH_HLEN + 8];
                                if ttl <= 1 {
                                    ttl_drop += 1;
                                    if let Some(icmp_pkt) =
                                        icmp::build_time_exceeded(inner_pkt, tunnel_ip)
                                    {
                                        encrypt_and_send_shared(
                                            &icmp_pkt,
                                            entry,
                                            identity,
                                            mempool,
                                            &mut outer_tx_mbufs,
                                            &mut ip_id,
                                            checksum_mode,
                                        );
                                    }
                                    continue;
                                }
                                pkt_buf[ETH_HLEN + 8] = ttl - 1;
                                fix_ttl_checksum(&mut pkt_buf[ETH_HLEN..], ttl);

                                if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
                                    if out_mbuf
                                        .write_packet(&pkt_buf[..frame_len])
                                        .is_ok()
                                    {
                                        outer_tx_mbufs.push(out_mbuf.into_raw());
                                    }
                                }
                            }
                            RouteAction::Local => {
                                let mut reply = inner_pkt.to_vec();
                                if quictun_core::icmp::echo_reply_inplace(&mut reply) {
                                    encrypt_and_send_shared(
                                        &reply,
                                        entry,
                                        identity,
                                        mempool,
                                        &mut outer_tx_mbufs,
                                        &mut ip_id,
                                        checksum_mode,
                                    );
                                }
                            }
                            RouteAction::Drop => {
                                no_route_drop += 1;
                                if let Some(icmp_pkt) =
                                    icmp::build_dest_unreachable(inner_pkt, tunnel_ip, 0)
                                {
                                    encrypt_and_send_shared(
                                        &icmp_pkt,
                                        entry,
                                        identity,
                                        mempool,
                                        &mut outer_tx_mbufs,
                                        &mut ip_id,
                                        checksum_mode,
                                    );
                                }
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

        // ── 2. Return RX: dequeue NAT return traffic → reverse NAT → encrypt → TX ──

        let nb_ret = rings.return_rx.dequeue_burst(&mut ret_rx_mbufs);

        for i in 0..nb_ret as usize {
            let mbuf = unsafe { Mbuf::from_raw(ret_rx_mbufs[i]) };
            let data = mbuf.data();

            match net::parse_packet_extended(data) {
                Some(ParsedPacket::Udp(udp)) => {
                    if let Some(dnat_result) = nat_table.lookup_reverse(
                        17,
                        udp.dst_port,
                        udp.src_ip,
                        udp.src_port,
                        now,
                    ) {
                        nat_reverse += 1;
                        let ip_start = ETH_HLEN;
                        let ip_pkt = &data[ip_start..];
                        encrypt_return_to_peer_shared(
                            ip_pkt,
                            &dnat_result,
                            &connections,
                            identity,
                            mempool,
                            &mut outer_tx_mbufs,
                            &mut ip_id,
                            checksum_mode,
                            mss_clamp_val,
                        );
                    }
                }
                Some(ParsedPacket::Ipv4Raw(ipv4)) => {
                    if ipv4.protocol == 6 {
                        let tcp_start = ipv4.ip_header_len;
                        if ipv4.payload.len() >= tcp_start + 4 {
                            let dst_port = u16::from_be_bytes([
                                ipv4.payload[tcp_start + 2],
                                ipv4.payload[tcp_start + 3],
                            ]);
                            let src_port = u16::from_be_bytes([
                                ipv4.payload[tcp_start],
                                ipv4.payload[tcp_start + 1],
                            ]);
                            if let Some(dnat_result) =
                                nat_table.lookup_reverse(6, dst_port, ipv4.src_ip, src_port, now)
                            {
                                nat_reverse += 1;
                                encrypt_return_to_peer_shared(
                                    ipv4.payload,
                                    &dnat_result,
                                    &connections,
                                    identity,
                                    mempool,
                                    &mut outer_tx_mbufs,
                                    &mut ip_id,
                                    checksum_mode,
                                    mss_clamp_val,
                                );
                            }
                        }
                    } else if ipv4.protocol == 1 {
                        let icmp_start = ipv4.ip_header_len;
                        if ipv4.payload.len() >= icmp_start + 8 {
                            let icmp_type = ipv4.payload[icmp_start];
                            if icmp_type == 0 {
                                let icmp_id = u16::from_be_bytes([
                                    ipv4.payload[icmp_start + 4],
                                    ipv4.payload[icmp_start + 5],
                                ]);
                                if let Some(dnat_result) =
                                    nat_table.lookup_reverse(1, icmp_id, ipv4.src_ip, 0, now)
                                {
                                    nat_reverse += 1;
                                    encrypt_return_to_peer_shared(
                                        ipv4.payload,
                                        &dnat_result,
                                        &connections,
                                        identity,
                                        mempool,
                                        &mut outer_tx_mbufs,
                                        &mut ip_id,
                                        checksum_mode,
                                        mss_clamp_val,
                                    );
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        if nb_ret > 0 {
            had_work = true;
        }

        // ── 3. TX directly to outer port on this worker's queue ──

        if !outer_tx_mbufs.is_empty() {
            let nb_tx = outer_tx_mbufs.len() as u16;
            let sent = port::tx_burst(outer_port_id, tx_queue_id, &mut outer_tx_mbufs, nb_tx);
            tx_pkts += sent as u64;
            for j in sent as usize..outer_tx_mbufs.len() {
                unsafe { ffi::shim_rte_pktmbuf_free(outer_tx_mbufs[j]) };
            }
        }

        // ── 4. Periodic tasks ──

        if had_work {
            now = Instant::now();
        }

        // NAT sweep.
        if enable_nat && now.duration_since(last_nat_sweep) >= NAT_SWEEP_INTERVAL {
            now = Instant::now();
            let before = nat_table.len();
            nat_table.sweep(now);
            let expired = before - nat_table.len();
            if expired > 0 {
                tracing::debug!(core = core_id, expired, remaining = nat_table.len(), "NAT sweep");
            }
            last_nat_sweep = now;
        }

        // Stats.
        if now.duration_since(last_stats) >= Duration::from_secs(10) {
            now = Instant::now();
            tracing::info!(
                core = core_id,
                rx = rx_pkts,
                tx = tx_pkts,
                decrypt_ok,
                decrypt_fail,
                nat_fwd = nat_forward,
                nat_rev = nat_reverse,
                hub_spoke,
                ttl_drop,
                no_route_drop,
                frag_needed,
                mac_fail,
                nat_entries = nat_table.len(),
                connections = connections.len(),
                "router pipeline worker stats"
            );
            last_stats = now;
        }

        // Adaptive polling.
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

/// Encrypt an inner packet via shared state and queue for TX.
#[allow(clippy::too_many_arguments)]
fn encrypt_and_send_shared(
    inner_pkt: &[u8],
    entry: &RouterPipelineConnection,
    identity: &NetIdentity,
    mempool: *mut ffi::rte_mempool,
    outer_tx_mbufs: &mut Vec<*mut ffi::rte_mbuf>,
    ip_id: &mut u16,
    checksum_mode: ChecksumMode,
) {
    let max_quic_len = 1
        + entry.conn.tx.remote_cid().len()
        + 4
        + 1
        + inner_pkt.len()
        + entry.conn.tag_len();
    let max_frame_len = net::HEADER_SIZE + max_quic_len;
    let Ok(max_frame_len_u16) = u16::try_from(max_frame_len) else {
        return;
    };

    if let Ok(mut tx_mbuf) = Mbuf::alloc(mempool) {
        if let Ok(buf) = tx_mbuf.alloc_space(max_frame_len_u16) {
            match entry.conn.tx.encrypt_datagram(inner_pkt, &mut buf[net::HEADER_SIZE..]) {
                Ok(result) => {
                    let remote_ip = match entry.remote_addr.ip() {
                        std::net::IpAddr::V4(ip) => ip,
                        _ => Ipv4Addr::UNSPECIFIED,
                    };
                    *ip_id = ip_id.wrapping_add(1);
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
                        *ip_id,
                        checksum_mode,
                    );
                    tx_mbuf.truncate(actual_len as u16);
                    match checksum_mode {
                        ChecksumMode::HardwareUdpOnly => {
                            tx_mbuf.set_tx_udp_checksum_offload();
                        }
                        ChecksumMode::HardwareFull => {
                            tx_mbuf.set_tx_full_checksum_offload();
                        }
                        _ => {}
                    }
                    outer_tx_mbufs.push(tx_mbuf.into_raw());
                }
                Err(_) => {}
            }
        }
    }
}

/// Encrypt a return packet (after DNAT) via shared state and send to the peer.
#[allow(clippy::too_many_arguments)]
fn encrypt_return_to_peer_shared(
    ip_pkt: &[u8],
    dnat: &nat::DnatResult,
    connections: &FxHashMap<u64, RouterPipelineConnection>,
    identity: &NetIdentity,
    mempool: *mut ffi::rte_mempool,
    outer_tx_mbufs: &mut Vec<*mut ffi::rte_mbuf>,
    ip_id: &mut u16,
    checksum_mode: ChecksumMode,
    mss_clamp_val: u16,
) {
    let mut modified = ip_pkt.to_vec();
    nat::apply_dnat(&mut modified, dnat.orig_src_ip, dnat.orig_src_port);

    if mss_clamp_val > 0 {
        mss::clamp_mss(&mut modified, mss_clamp_val);
    }

    let Some(entry) = connections.get(&dnat.peer_cid) else {
        return;
    };

    encrypt_and_send_shared(
        &modified,
        entry,
        identity,
        mempool,
        outer_tx_mbufs,
        ip_id,
        checksum_mode,
    );
}

/// Rebuild routing table for pipeline workers (no peer_to_worker needed).
fn rebuild_routing_table_shared(
    routing_table: &mut RoutingTable,
    tunnel_ip: Ipv4Addr,
    enable_nat: bool,
    peers: &[PeerConfig],
    ip_to_cid: &FxHashMap<Ipv4Addr, u64>,
) {
    *routing_table = RoutingTable::new(tunnel_ip, enable_nat);
    for peer in peers {
        let cid_key = ip_to_cid
            .get(&peer.tunnel_ip)
            .copied()
            .unwrap_or(u32::from(peer.tunnel_ip) as u64);
        routing_table.add_peer_routes(cid_key, &peer.allowed_ips);
    }
}

// ── Entry point (single-core / multi-core dispatch) ────────────────��────

/// Top-level entry point for router mode (single-core or multicore).
///
/// Handles the single vs multicore dispatch, port reconfiguration for
/// multi-queue TX, thread spawning, and scope join.
/// Called from `event_loop::run()` after shared setup.
#[allow(clippy::too_many_arguments)]
pub fn entry(
    outer_port_id: u16,
    mempool: *mut ffi::rte_mempool,
    multi_state: &mut MultiQuicState,
    identity: &mut NetIdentity,
    arp_table: &mut ArpTable,
    shutdown: Arc<AtomicBool>,
    dpdk_config: &DpdkConfig,
    checksum_mode: ChecksumMode,
    server_config_clone: Option<Arc<quinn_proto::ServerConfig>>,
) -> Result<()> {
    let n_cores = dpdk_config.n_cores.max(1);
    let mss_clamp = if dpdk_config.mss_clamp > 0 {
        dpdk_config.mss_clamp
    } else {
        dpdk_config.tunnel_mtu.saturating_sub(40) // auto: MTU - IP(20) - TCP(20)
    };

    if n_cores == 1 {
        tracing::info!(
            enable_nat = dpdk_config.enable_nat,
            mss_clamp,
            "starting router mode (single NIC, single core)"
        );
        return run_router(
            outer_port_id,
            0, // queue_id
            mempool,
            multi_state,
            identity,
            arp_table,
            shutdown,
            dpdk_config.adaptive_poll,
            checksum_mode,
            &dpdk_config.peers,
            dpdk_config.enable_nat,
            mss_clamp,
            dpdk_config.tunnel_ip,
            dpdk_config.tunnel_mtu,
            dpdk_config.max_peers,
            dpdk_config.idle_timeout,
        );
    }

    // Multi-core router: pipeline architecture (SharedConnectionState).
    // Core 0 = I/O (RX classify, handshake, ACK, keepalive),
    // Workers 1..N = crypto + routing + NAT (round-robin, any connection).
    let n_workers = n_cores - 1;

    // Restrict to listener mode.
    let multi_server_config = server_config_clone
        .ok_or_else(|| anyhow::anyhow!("multi-core router requires listener mode"))?;
    let mut multi_state = MultiQuicState::new(multi_server_config);

    // Router workers TX directly on per-worker TX queues. Reconfigure
    // outer port with N TX queues. (Virtio-pci drops on queue > 0;
    // router pipeline on virtio requires outer_tx ring approach — TODO.)
    crate::port::stop_port(outer_port_id);
    let (new_mac, hw_udp, hw_ip) =
        crate::port::configure_port_dispatcher(outer_port_id, n_cores as u16, mempool)?;
    identity.local_mac = new_mac;
    let checksum_mode = if dpdk_config.no_udp_checksum {
        ChecksumMode::None
    } else if hw_udp && hw_ip {
        ChecksumMode::HardwareFull
    } else if hw_udp {
        ChecksumMode::HardwareUdpOnly
    } else {
        ChecksumMode::Software
    };

    // Create per-worker router pipeline ring bundles (2 rings each).
    let mut pipeline_rings: Vec<RouterPipelineRings> = Vec::with_capacity(n_workers);
    for i in 0..n_workers {
        pipeline_rings.push(RouterPipelineRings::new(i)?);
    }

    // Compute NAT port ranges.
    let port_ranges = quictun_core::nat::compute_port_ranges(n_workers);

    let adaptive_poll = dpdk_config.adaptive_poll;
    let enable_nat = dpdk_config.enable_nat;
    let tunnel_ip = dpdk_config.tunnel_ip;
    let tunnel_mtu = dpdk_config.tunnel_mtu;
    let peers = &dpdk_config.peers;

    tracing::info!(
        n_workers,
        enable_nat,
        mss_clamp,
        "starting router pipeline mode (multi-core)"
    );

    std::thread::scope(|s| {
        let mut handles = Vec::with_capacity(n_workers);

        for (idx, rings) in pipeline_rings.iter().enumerate() {
            let shutdown = shutdown.clone();
            let worker_identity = identity.clone();
            let worker_arp = arp_table.clone();
            let mempool = SendPtr(mempool);
            let (port_start, port_end) = port_ranges[idx];
            let peers_ref = peers;

            handles.push(s.spawn(move || -> Result<()> {
                let mempool = mempool.as_ptr();
                let core_idx = idx + 1; // core 0 is I/O
                let tx_queue = core_idx as u16;

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
                        tracing::info!(core = core_idx, "pinned router pipeline worker to CPU");
                    } else {
                        tracing::warn!(core = core_idx, "failed to pin router pipeline worker to CPU");
                    }
                }

                run_router_pipeline_worker(
                    outer_port_id,
                    tx_queue,
                    mempool,
                    rings,
                    &worker_identity,
                    &worker_arp,
                    &shutdown,
                    adaptive_poll,
                    checksum_mode,
                    peers_ref,
                    enable_nat,
                    mss_clamp,
                    tunnel_ip,
                    tunnel_mtu,
                    core_idx,
                    port_start,
                    port_end,
                )
            }));
        }

        // Run pipeline I/O on core 0 (this thread).
        let io_result = run_router_pipeline_io(
            outer_port_id,
            mempool,
            &mut multi_state,
            &pipeline_rings,
            identity,
            arp_table,
            &shutdown,
            adaptive_poll,
            checksum_mode,
            peers,
            enable_nat,
            tunnel_ip,
            n_workers,
            dpdk_config.max_peers,
            dpdk_config.idle_timeout,
        );

        // Signal shutdown and wait for workers.
        shutdown.store(true, Ordering::Release);
        let mut result = io_result;
        for handle in handles {
            if let Err(e) = handle.join().expect("router pipeline worker panicked") {
                if result.is_ok() {
                    result = Err(e);
                }
            }
        }
        result
    })
}
