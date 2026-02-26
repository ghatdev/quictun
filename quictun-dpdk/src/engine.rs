use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::{Bytes, BytesMut};

use crate::ffi;
use crate::mbuf::Mbuf;
use crate::net::{self, ArpTable, ChecksumMode, NetIdentity, ParsedPacket};
use crate::port;
use crate::shared::{self, DriveResult, QuicState, BUF_SIZE};

/// Maximum burst size for rx/tx.
const BURST_SIZE: usize = 32;

/// Maximum number of GSO segments per poll_transmit call.
/// quinn-proto will pack up to this many QUIC packets into one transmit buffer.
const MAX_GSO_SEGMENTS: usize = 10;

/// Ethernet header size (dst MAC + src MAC + EtherType).
const ETH_HLEN: usize = 14;

/// Pre-computed Ethernet header for the AF_XDP inner interface.
///
/// Packets between the engine and the app-facing veth end always use the same
/// src/dst MACs, so we compute the header once and reuse it.
pub struct InnerEthHeader {
    /// Header bytes: [dst_mac(6)][src_mac(6)][0x08, 0x00] (IPv4).
    pub bytes: [u8; ETH_HLEN],
}

impl InnerEthHeader {
    /// Build the Ethernet header for engine → app direction.
    ///
    /// - `src_mac`: MAC of the xdp-facing veth end (DPDK port)
    /// - `dst_mac`: MAC of the app-facing veth end (kernel side)
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
/// Used by both AF_XDP (veth pair) and TAP PMD modes.
pub struct InnerPort {
    pub port_id: u16,
    pub eth_hdr: InnerEthHeader,
}

/// Number of consecutive empty polls before entering backoff sleep.
const EMPTY_POLL_THRESHOLD: u32 = 1024;
/// Minimum sleep duration in microseconds during adaptive backoff.
const MIN_DELAY_US: u32 = 1;
/// Maximum sleep duration in microseconds during adaptive backoff.
const MAX_DELAY_US: u32 = 100;

/// Run the DPDK polling engine.
///
/// This is the hot loop: RX burst → QUIC → inner write → drain transmits → TX burst.
/// No syscalls for network I/O (pure DPDK PMD polling).
pub fn run(
    outer_port_id: u16,
    queue_id: u16,
    mempool: *mut ffi::rte_mempool,
    state: &mut QuicState,
    identity: &mut NetIdentity,
    arp_table: &mut ArpTable,
    inner: InnerPort,
    shutdown: Arc<AtomicBool>,
    adaptive_poll: bool,
    checksum_mode: ChecksumMode,
) -> Result<()> {
    let mut response_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut drive_result = DriveResult::new();
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut pkt_buf = [0u8; 2048];
    let mut deadline = Instant::now() + Duration::from_secs(1);
    let mut ip_id: u16 = 0;

    // Pending packets to transmit (raw Ethernet frames for ARP replies, etc.).
    let mut pending_frames: Vec<Vec<u8>> = Vec::new();
    let mut peer_learned = identity.remote_port != 0;

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut quic_rx: u64 = 0;
    let mut inner_rx: u64 = 0;
    let mut inner_tx: u64 = 0;
    let mut last_stats = Instant::now();

    // Adaptive polling state.
    let mut empty_polls: u32 = 0;
    let mut delay_us: u32 = MIN_DELAY_US;

    // If connector, drain initial handshake transmits.
    drain_and_send(
        state,
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

    tracing::info!("DPDK engine started (polling loop)");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("shutdown signal received");
            break;
        }

        let now = Instant::now();

        // ── Phase 1a: RX burst from outer port → parse → feed QUIC ──

        let mut rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] =
            [std::ptr::null_mut(); BURST_SIZE];

        let nb_rx = port::rx_burst(outer_port_id, queue_id, &mut rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_rx as usize {
            // SAFETY: rx_burst wrote a valid mbuf pointer into rx_mbufs[i]; we take
            // exclusive ownership. The mbuf is freed on drop at end of this iteration.
            let mbuf = unsafe { Mbuf::from_raw(rx_mbufs[i]) };
            let data = mbuf.data();
            rx_pkts += 1;

            match net::parse_packet(data) {
                Some(ParsedPacket::Udp(udp)) => {
                    // Only process packets addressed to our IP:port.
                    if udp.dst_ip != identity.local_ip || udp.dst_port != identity.local_port {
                        continue;
                    }

                    // Learn peer MAC.
                    arp_table.learn(udp.src_ip, udp.src_mac);
                    if identity.remote_mac.is_none() {
                        identity.remote_mac = Some(udp.src_mac);
                        tracing::info!(
                            mac = %format_mac(&udp.src_mac),
                            ip = %udp.src_ip,
                            "learned peer MAC"
                        );
                    }

                    // Update remote_addr for listener (first packet reveals the peer).
                    if !peer_learned {
                        state.remote_addr = SocketAddr::new(udp.src_ip.into(), udp.src_port);
                        identity.remote_port = udp.src_port;
                        peer_learned = true;
                        tracing::info!(remote = %state.remote_addr, "learned peer address");
                    }

                    quic_rx += 1;
                    let quic_data = BytesMut::from(udp.payload);

                    let remote_addr = SocketAddr::new(udp.src_ip.into(), udp.src_port);
                    if let Some(event) =
                        state
                            .endpoint
                            .handle(now, remote_addr, None, udp.ecn, quic_data, &mut response_buf)
                    {
                        let responses =
                            shared::handle_datagram_event(state, event, &mut response_buf);

                        // Queue any stateless response transmits.
                        for (len, buf) in responses {
                            let dst_mac = identity
                                .remote_mac
                                .or_else(|| arp_table.lookup(identity.remote_ip))
                                .unwrap_or([0xff; 6]);

                            ip_id = ip_id.wrapping_add(1);
                            let frame_len = net::build_udp_packet(
                                &identity.local_mac,
                                &dst_mac,
                                identity.local_ip,
                                identity.remote_ip,
                                identity.local_port,
                                identity.remote_port,
                                &buf[..len],
                                &mut pkt_buf,
                                0, // no ECN for stateless responses
                                ip_id,
                                checksum_mode,
                            );
                            pending_frames.push(pkt_buf[..frame_len].to_vec());
                        }
                    }
                }
                Some(ParsedPacket::Arp(arp)) => {
                    // Learn MAC from any ARP we receive.
                    arp_table.learn(arp.sender_ip, arp.sender_mac);
                    if identity.remote_mac.is_none()
                        && arp.sender_ip == identity.remote_ip
                    {
                        identity.remote_mac = Some(arp.sender_mac);
                        tracing::info!(
                            mac = %format_mac(&arp.sender_mac),
                            ip = %arp.sender_ip,
                            "learned peer MAC via ARP"
                        );
                    }

                    // Reply to ARP requests for our IP.
                    if arp.is_request && arp.target_ip == identity.local_ip {
                        let reply =
                            net::build_arp_reply(&arp, identity.local_mac, identity.local_ip);
                        pending_frames.push(reply);
                    }
                }
                None => {}
            }
            // mbuf freed on drop
        }

        // ── Phase 1b: Read from inner port → send_datagram ──
        //
        // rx_burst handles ARP regardless of connection state,
        // then send IP packets via QUIC if connection exists.

        let mut inner_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] =
            [std::ptr::null_mut(); BURST_SIZE];
        let nb = port::rx_burst(inner.port_id, 0, &mut inner_rx_mbufs, BURST_SIZE as u16);

        let mut inner_ip_count: usize = 0;

        for i in 0..nb as usize {
            // SAFETY: inner rx_burst wrote a valid mbuf pointer; exclusive ownership taken.
            let mbuf = unsafe { Mbuf::from_raw(inner_rx_mbufs[i]) };
            let data = mbuf.data();
            if data.len() < ETH_HLEN {
                continue;
            }
            let ethertype = u16::from_be_bytes([data[12], data[13]]);
            match ethertype {
                0x0800 => {
                    // IPv4: strip Ethernet header, send via QUIC.
                    if let Some(conn) = state.connection.as_mut() {
                        inner_rx += 1;
                        let pkt = Bytes::copy_from_slice(&data[ETH_HLEN..]);
                        if let Err(e) = conn.datagrams().send(pkt, true) {
                            tracing::trace!(error = %e, "send_datagram failed (likely blocked)");
                        }
                        inner_ip_count += 1;
                    }
                }
                0x0806 => {
                    // ARP: reply to requests with our inner port MAC.
                    if let Some(ParsedPacket::Arp(arp)) = net::parse_packet(data) {
                        if arp.is_request {
                            let inner_mac: [u8; 6] = inner.eth_hdr.bytes[6..12].try_into().unwrap();
                            let reply = net::build_arp_reply(&arp, inner_mac, arp.target_ip);
                            if let Ok(mut reply_mbuf) = Mbuf::alloc(mempool) {
                                if reply_mbuf.write_packet(&reply).is_ok() {
                                    let raw = reply_mbuf.into_raw();
                                    let mut tx = [raw];
                                    let sent = port::tx_burst(inner.port_id, 0, &mut tx, 1);
                                    if sent == 0 {
                                        // SAFETY: tx_burst didn't send; we still own this mbuf.
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
        let _ = inner_ip_count;

        // ── Phase 1c: Timer check ───────────────────────────────────

        if now >= deadline {
            if let Some(conn) = state.connection.as_mut() {
                conn.handle_timeout(now);
            }
        }

        // ── Phase 2: Process QUIC events → write to inner port ──

        shared::process_events(state, &mut drive_result);

        {
            let mut tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::new();
            for datagram in &drive_result.datagrams {
                // Build Ethernet frame directly into mbuf (zero-copy).
                let frame_len = ETH_HLEN + datagram.len();
                if let Ok(mut mbuf) = Mbuf::alloc(mempool) {
                    if let Ok(buf) = mbuf.alloc_space(frame_len as u16) {
                        buf[..ETH_HLEN].copy_from_slice(&inner.eth_hdr.bytes);
                        buf[ETH_HLEN..frame_len].copy_from_slice(datagram);
                        tx_mbufs.push(mbuf.into_raw());
                        inner_tx += 1;
                    }
                }
            }
            if !tx_mbufs.is_empty() {
                let nb = tx_mbufs.len() as u16;
                let sent = port::tx_burst(inner.port_id, 0, &mut tx_mbufs, nb);
                for raw in &tx_mbufs[sent as usize..] {
                    // SAFETY: unsent mbufs are still owned by us.
                    unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
                }
            }
        }

        if drive_result.connected {
            tracing::info!("tunnel established via DPDK");
        }
        if drive_result.connection_lost {
            tracing::info!("connection lost, engine exiting");
            break;
        }

        // ── Phase 3: Drain transmits → build packets → TX burst ──────

        drain_and_send(
            state,
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

        // Send pending raw frames (ARP replies, stateless QUIC responses).
        send_raw_frames(outer_port_id, queue_id, mempool, &mut pending_frames, &mut tx_pkts)?;

        // ── Update timer deadline ────────────────────────────────────

        deadline = if let Some(conn) = state.connection.as_mut() {
            conn.poll_timeout()
                .unwrap_or(now + Duration::from_secs(1))
        } else {
            now + Duration::from_secs(1)
        };

        // ── Periodic stats ───────────────────────────────────────────

        if now.duration_since(last_stats).as_secs() >= 2 {
            tracing::debug!(
                rx_pkts,
                tx_pkts,
                quic_rx,
                inner_rx,
                inner_tx,
                "dpdk engine stats"
            );
            last_stats = now;
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
    let now = Instant::now();

    let dst_mac = identity
        .remote_mac
        .or_else(|| arp_table.lookup(identity.remote_ip))
        .unwrap_or([0xff; 6]); // broadcast if unknown (shouldn't happen after ARP)

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
            _ => identity.remote_ip,
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
            if checksum_mode == ChecksumMode::HardwareOffload {
                mbuf.set_tx_checksum_offload();
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
) -> Result<()> {
    if frames.is_empty() {
        return Ok(());
    }

    let mut tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(frames.len());

    for frame in frames.iter() {
        let mut mbuf = Mbuf::alloc(mempool)?;
        mbuf.write_packet(frame)?;
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

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
