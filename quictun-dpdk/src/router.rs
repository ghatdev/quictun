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

use crate::dispatch::ConnectionEntry;
use crate::ffi;
use crate::mbuf::Mbuf;
use crate::net::{self, ArpTable, ChecksumMode, NetIdentity, ParsedPacket};
use crate::port;
use crate::shared::{BUF_SIZE, MultiQuicState};
use quictun_core::mss;
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
    let mut last_stats = Instant::now();
    let mut last_nat_sweep = Instant::now();

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
                            let decrypt_result = {
                                let Some(entry) = connections.get_mut(&cid_key) else {
                                    decrypt_fail += 1;
                                    continue;
                                };
                                match entry.conn.decrypt_packet_in_place(
                                    &mut data[payload_offset..payload_offset + payload_len],
                                ) {
                                    Ok(decrypted) => {
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
                                        now,
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

                            for (len, buf) in responses {
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
                                    &buf[..len],
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
    now: Instant,
) {
    if inner_pkt.len() < 20 {
        return;
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
            let dst_mac = arp_table.lookup(dst_ip).or_else(|| {
                // Default gateway MAC — use remote_mac as gateway.
                identity.remote_mac
            });
            let Some(dst_mac) = dst_mac else {
                return; // no MAC for destination
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
                return; // TTL expired
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
        RouteAction::Drop => {}
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
            match entry.conn.encrypt_datagram(inner_pkt, None, &mut buf[net::HEADER_SIZE..]) {
                Ok(result) => {
                    let remote_ip = match entry.remote_addr.ip() {
                        std::net::IpAddr::V4(ip) => ip,
                        _ => identity.remote_ip,
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
    while let Some(transmit) = connection.poll_transmit(now, 1) {
        let payload = &transmit.contents;
        let remote = transmit.destination;
        let remote_ip = match remote.ip() {
            std::net::IpAddr::V4(ip) => ip,
            _ => continue,
        };
        let dst_mac = arp_table
            .lookup(remote_ip)
            .or(identity.remote_mac)
            .unwrap_or([0xff; 6]);

        transmit_buf.resize(net::HEADER_SIZE + payload.len(), 0);
        *ip_id = ip_id.wrapping_add(1);
        let frame_len = net::build_udp_packet(
            &identity.local_mac,
            &dst_mac,
            identity.local_ip,
            remote_ip,
            identity.local_port,
            remote.port(),
            payload,
            transmit_buf,
            0,
            *ip_id,
            checksum_mode,
        );

        if let Ok(mut out_mbuf) = Mbuf::alloc(mempool) {
            if out_mbuf.write_packet(&transmit_buf[..frame_len]).is_ok() {
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
