use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::{Bytes, BytesMut};

use crate::ffi;
use crate::mbuf::{Mbuf, MbufSlice};
use crate::net::{self, ArpTable, ChecksumMode, NetIdentity, ParsedPacket};
use crate::port;
use crate::shared::{self, DriveResult, QuicState, BUF_SIZE};
use quictun_quic::ConnectionState;

/// Maximum burst size for rx/tx.
const BURST_SIZE: usize = 32;

/// Smaller burst size for inner→outer pipeline in quictun-quic mode.
/// Limits the outer TX burst to prevent virtio TX ring overflow during peaks.
/// quinn-proto's CC naturally paces sends; without CC we need to limit bursts.
const INNER_BURST_SIZE: u16 = 16;

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
    // Reusable BytesMut for feeding QUIC RX — avoids per-packet allocation.
    let mut rx_buf = BytesMut::with_capacity(2048);

    // Pending packets to transmit (raw Ethernet frames for ARP replies, etc.).
    let mut pending_frames: Vec<Vec<u8>> = Vec::new();
    let mut peer_learned = identity.remote_port != 0;

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

    // quictun-quic: fast data plane state (set after handshake completes).
    let mut quic_conn_state: Option<Arc<ConnectionState>> = None;
    // Pre-allocated mbuf vectors for batched TX (reused across loop iterations).
    let mut inner_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);
    let mut outer_tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);

    // Pending mbufs from a failed outer tx_burst (retry next iteration instead of dropping).
    let mut pending_outer_tx: Vec<*mut ffi::rte_mbuf> = Vec::with_capacity(BURST_SIZE);

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

    tracing::info!("DPDK engine started (polling loop)");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("shutdown signal received");
            break;
        }

        let now = Instant::now();

        // ── Phase 1a: RX burst from outer port → parse → feed QUIC ──

        // Reuse pre-allocated vectors for this iteration.
        inner_tx_mbufs.clear();

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

                    // Route: short header (1-RTT) → quictun-quic, long header → quinn-proto
                    if udp.payload.is_empty() {
                        continue;
                    }
                    let first_byte = udp.payload[0];
                    if first_byte & 0x80 == 0 && quic_conn_state.is_some() {
                        // Short header → quictun-quic fast path
                        let conn_state = quic_conn_state.as_ref().unwrap();
                        // Copy into mutable scratch buffer for in-place decrypt
                        let pkt_len = udp.payload.len();
                        if pkt_len <= pkt_buf.len() {
                            pkt_buf[..pkt_len].copy_from_slice(udp.payload);
                            match conn_state.decrypt_packet(&mut pkt_buf[..pkt_len]) {
                                Ok(decrypted) => {
                                    // Process ACK if present
                                    if let Some(ref ack) = decrypted.ack {
                                        let now_ns = quictun_quic::bbr::coarse_now_ns();
                                        conn_state.process_ack(ack, now_ns);
                                    }
                                    // Collect datagrams for batched inner TX
                                    for datagram in &decrypted.datagrams {
                                        let frame_len = ETH_HLEN + datagram.len();
                                        if let Ok(mut mbuf) = Mbuf::alloc(mempool) {
                                            if let Ok(buf) = mbuf.alloc_space(frame_len as u16) {
                                                buf[..ETH_HLEN].copy_from_slice(&inner.eth_hdr.bytes);
                                                buf[ETH_HLEN..frame_len].copy_from_slice(datagram);
                                                inner_tx_mbufs.push(mbuf.into_raw());
                                                inner_tx += 1;
                                            }
                                        }
                                    }
                                }
                                Err(_e) => {
                                    decrypt_fail += 1;
                                }
                            }
                        }
                    } else if first_byte & 0x80 != 0 {
                        // Long header → quinn-proto (handshake, retry, etc.)
                        rx_buf.clear();
                        rx_buf.extend_from_slice(udp.payload);
                        let quic_data = rx_buf.split();

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

        // ── Phase 1b: Read from inner port → send_datagram ──
        //
        // Back-pressure: if the outer TX ring was full last iteration,
        // skip inner RX to let the TX queue drain. ARP is always handled.
        // This prevents sustained queue overflow that causes TCP retransmits.
        //
        // rx_burst handles ARP regardless of connection state,
        // then send IP packets via QUIC if connection exists.
        //
        let mut inner_rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] =
            [std::ptr::null_mut(); BURST_SIZE];
        // Use smaller burst for quictun-quic mode to prevent outer TX ring overflow.
        // Back-pressure: if we have pending unsent mbufs, skip inner RX and drain first.
        let inner_burst = if quic_conn_state.is_some() { INNER_BURST_SIZE } else { BURST_SIZE as u16 };
        let nb = if !pending_outer_tx.is_empty() {
            0 // back-pressure: drain pending mbufs first
        } else {
            port::rx_burst(inner.port_id, 0, &mut inner_rx_mbufs, inner_burst)
        };

        let mut inner_ip_count: usize = 0;
        // Reuse pre-allocated vector for quictun-quic TX batch.
        outer_tx_mbufs.clear();

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
                    if let Some(ref conn_state) = quic_conn_state {
                        // quictun-quic fast path: encrypt directly into outer mbuf.
                        // Eliminates the quic_tx_buf intermediate copy.
                        inner_rx += 1;
                        let ip_payload = &data[ETH_HLEN..];
                        // Max QUIC packet: header(1+cid+4) + DATAGRAM(1+payload) + AEAD tag
                        let max_quic_len = 1 + conn_state.remote_cid().len() + 4
                            + 1 + ip_payload.len() + conn_state.tag_len();
                        let max_frame_len = net::HEADER_SIZE + max_quic_len;

                        if let Ok(mut tx_mbuf) = Mbuf::alloc(mempool) {
                            if let Ok(buf) = tx_mbuf.alloc_space(max_frame_len as u16) {
                                // Encrypt QUIC packet directly at buf[HEADER_SIZE..]
                                match conn_state.encrypt_datagram(
                                    ip_payload,
                                    None,
                                    &mut buf[net::HEADER_SIZE..],
                                ) {
                                    Ok(result) => {
                                        let dst_mac = identity
                                            .remote_mac
                                            .or_else(|| arp_table.lookup(identity.remote_ip))
                                            .unwrap_or([0xff; 6]);
                                        ip_id = ip_id.wrapping_add(1);

                                        // Write headers around the already-placed payload.
                                        let actual_len = net::build_udp_packet_inplace(
                                            &identity.local_mac,
                                            &dst_mac,
                                            identity.local_ip,
                                            identity.remote_ip,
                                            identity.local_port,
                                            identity.remote_port,
                                            result.len,
                                            buf,
                                            0,
                                            ip_id,
                                            checksum_mode,
                                        );
                                        // Trim mbuf to actual frame size.
                                        tx_mbuf.truncate(actual_len as u16);
                                        if checksum_mode == ChecksumMode::HardwareOffload {
                                            tx_mbuf.set_tx_checksum_offload();
                                        }
                                        outer_tx_mbufs.push(tx_mbuf.into_raw());
                                    }
                                    Err(e) => {
                                        tracing::trace!(error = %e, "quictun-quic encrypt failed");
                                        // mbuf freed on drop (encrypt failed)
                                    }
                                }
                            }
                        }
                        inner_ip_count += 1;
                    } else if let Some(conn) = state.connection.as_mut() {
                        // Handshake still in progress: use quinn-proto path
                        inner_rx += 1;
                        // Zero-copy: transfer mbuf ownership to Bytes via MbufSlice.
                        // The mbuf lives until quinn consumes/drops the datagram.
                        let pkt = Bytes::from_owner(MbufSlice::new(mbuf, ETH_HLEN));
                        if let Err(e) = conn.datagrams().send(pkt, true) {
                            tracing::trace!(error = %e, "send_datagram failed (likely blocked)");
                        }
                        inner_ip_count += 1;
                        continue; // mbuf owned by Bytes now, skip drop
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

        // Drain pending mbufs from previous iteration first.
        if !pending_outer_tx.is_empty() {
            let nb_pend = pending_outer_tx.len() as u16;
            let sent = port::tx_burst(outer_port_id, queue_id, &mut pending_outer_tx, nb_pend);
            tx_pkts += sent as u64;
            if sent < nb_pend {
                // Still can't drain — keep the unsent ones, drop oldest to prevent unbounded growth.
                if pending_outer_tx.len() > 64 {
                    outer_tx_drop += (pending_outer_tx.len() - 64) as u64;
                    for raw in &pending_outer_tx[64..] {
                        unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
                    }
                    pending_outer_tx.truncate(64);
                }
                // Shift unsent to the front.
                let unsent: Vec<_> = pending_outer_tx[sent as usize..].to_vec();
                pending_outer_tx.clear();
                pending_outer_tx.extend(unsent);
            } else {
                pending_outer_tx.clear();
            }
        }

        // Batch TX for quictun-quic encrypted packets.
        if !outer_tx_mbufs.is_empty() {
            let nb_tx = outer_tx_mbufs.len() as u16;
            let sent = port::tx_burst(outer_port_id, queue_id, &mut outer_tx_mbufs, nb_tx);
            tx_pkts += sent as u64;
            if sent < nb_tx {
                // Save unsent mbufs for next iteration instead of dropping.
                pending_outer_tx.extend_from_slice(&outer_tx_mbufs[sent as usize..]);
            }
        }

        // ── Phase 1c-3: quinn-proto processing ────────────────────

        if quic_conn_state.is_none() {
            // Handshake in progress — run quinn-proto state machine

            if now >= deadline {
                if let Some(conn) = state.connection.as_mut() {
                    conn.handle_timeout(now);
                }
            }

            shared::process_events(state, &mut drive_result);

            {
                let mut tx_mbufs: Vec<*mut ffi::rte_mbuf> = Vec::new();
                for datagram in &drive_result.datagrams {
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
                        unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
                    }
                }
            }

            // Capture quictun-quic state on first Connected event
            if drive_result.connected {
                if let Some(cs) = drive_result.connection_state.take() {
                    tracing::info!("tunnel established via DPDK (quictun-quic data plane active)");
                    quic_conn_state = Some(cs);
                } else {
                    tracing::info!("tunnel established via DPDK");
                }
            }
            if drive_result.connection_lost {
                tracing::info!("connection lost, engine exiting");
                break;
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

            deadline = if let Some(conn) = state.connection.as_mut() {
                conn.poll_timeout()
                    .unwrap_or(now + Duration::from_secs(1))
            } else {
                now + Duration::from_secs(1)
            };
        }

        // Send pending raw frames (ARP replies, stateless QUIC responses).
        send_raw_frames(outer_port_id, queue_id, mempool, &mut pending_frames, &mut tx_pkts)?;

        // ── Periodic stats ───────────────────────────────────────────

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
