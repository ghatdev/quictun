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

use crate::dispatch::{ConnectionEntry, ControlMessage, DpdkDispatchTable, WorkerRings};
use crate::ffi;
use crate::mbuf::Mbuf;
use crate::net::{self, ArpTable, ChecksumMode, NetIdentity, ParsedPacket};
use crate::port;
use crate::shared::{BUF_SIZE, MultiQuicState};
use quictun_core::{icmp, mss};
use quictun_core::nat::{self, NatForwardKey, NatTable};
use quictun_core::peer::PeerConfig;
use quictun_core::routing::{RouteAction, RoutingTable};
use quictun_quic::cid_to_u64;

use crate::engine::resolve_completed_handshake;

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
    identity: &mut NetIdentity,
    arp_table: &mut ArpTable,
    shutdown: Arc<AtomicBool>,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
    peers: &[PeerConfig],
    enable_nat: bool,
    mss_clamp_val: u16,
    tunnel_ip: Ipv4Addr,
    tunnel_mtu: u16,
) -> Result<()> {
    let mut response_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut pkt_buf = [0u8; 2048];
    let mut ip_id: u16 = 0;
    let mut rx_buf = BytesMut::with_capacity(2048);

    let mut pending_frames: Vec<Vec<u8>> = Vec::new();

    // Connection table: CID → connection entry.
    let mut connections: FxHashMap<u64, ConnectionEntry> = FxHashMap::default();
    // Tunnel IP → CID for routing.
    let mut ip_to_cid: FxHashMap<Ipv4Addr, u64> = FxHashMap::default();

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
                            // We release the mutable borrow of `connections` before
                            // calling handle_decrypted_packet (which needs &mut connections).
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

                                    handle_decrypted_packet(
                                        inner_pkt,
                                        cid_key,
                                        src_tunnel_ip,
                                        &routing_table,
                                        &mut nat_table,
                                        &mut connections,
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

        // ── Poll for completed handshakes → register connections ──
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

                let Some(resolved) = resolve_completed_handshake(
                    &hs,
                    conn_state,
                    peers,
                    identity,
                    arp_table,
                ) else {
                    continue;
                };

                tracing::info!(
                    cid = hex::encode(&resolved.cid_bytes),
                    tunnel_ip = %resolved.tunnel_ip,
                    remote = %resolved.remote_addr,
                    "router: connection established"
                );

                // Update routing table with actual CID.
                // Rebuild with real CID keys for all known peers.
                routing_table = RoutingTable::new(tunnel_ip, enable_nat);
                for p in peers {
                    let key = if p.tunnel_ip == resolved.tunnel_ip {
                        resolved.cid
                    } else if let Some(&cid) = ip_to_cid.get(&p.tunnel_ip) {
                        cid
                    } else {
                        u32::from(p.tunnel_ip) as u64
                    };
                    routing_table.add_peer_routes(key, &p.allowed_ips);
                }

                ip_to_cid.insert(resolved.tunnel_ip, resolved.cid);
                connections.insert(
                    resolved.cid,
                    ConnectionEntry {
                        conn: resolved.conn,
                        tunnel_ip: resolved.tunnel_ip,
                        remote_addr: resolved.remote_addr,
                        remote_mac: resolved.remote_mac,
                    },
                );
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
                connections = connections.len(),
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
    connections: &mut FxHashMap<u64, ConnectionEntry>,
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
                if let Some(entry) = connections.get_mut(&src_cid) {
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
            if let Some(peer_entry) = connections.get_mut(&peer_cid) {
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
                    if let Some(entry) = connections.get_mut(&src_cid) {
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
                if let Some(entry) = connections.get_mut(&src_cid) {
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
                if let Some(entry) = connections.get_mut(&src_cid) {
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
    connections: &mut FxHashMap<u64, ConnectionEntry>,
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

    let Some(entry) = connections.get_mut(&dnat.peer_cid) else {
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
    entry: &mut ConnectionEntry,
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
    identity: &mut NetIdentity,
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

        now = Instant::now();
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

        // ── Drive handshakes ──

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
                // Register the quictun-quic CID (not the quinn-proto handshake CID).
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
                                                    entry,
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
                                                    peer_entry,
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
                                                        entry,
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
                                                    entry,
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
                                                    entry,
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
                        entry,
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
