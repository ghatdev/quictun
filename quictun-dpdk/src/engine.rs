use std::net::SocketAddr;
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use crossbeam_channel::Receiver;

use crate::ffi;
use crate::mbuf::Mbuf;
use crate::net::{self, ArpTable, NetIdentity, ParsedPacket, HEADER_SIZE};
use crate::port;
use crate::shared::{self, DriveResult, QuicState, BUF_SIZE};

/// Maximum burst size for rx/tx.
const BURST_SIZE: usize = 32;

/// Run the DPDK polling engine.
///
/// This is the hot loop: RX burst → QUIC → TUN write → drain transmits → TX burst.
/// No syscalls for network I/O (pure DPDK PMD polling).
pub fn run(
    port_id: u16,
    mempool: *mut ffi::rte_mempool,
    state: &mut QuicState,
    identity: &mut NetIdentity,
    arp_table: &mut ArpTable,
    tun_fd: RawFd,
    tun_rx: Receiver<Vec<u8>>,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let mut response_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut drive_result = DriveResult::new();
    let mut transmit_buf: Vec<u8> = Vec::with_capacity(BUF_SIZE);
    let mut pkt_buf = [0u8; 2048];
    let mut deadline = Instant::now() + Duration::from_secs(1);

    // Pending packets to transmit (raw Ethernet frames for ARP replies, etc.).
    let mut pending_frames: Vec<Vec<u8>> = Vec::new();

    // Stats.
    let mut rx_pkts: u64 = 0;
    let mut tx_pkts: u64 = 0;
    let mut quic_rx: u64 = 0;
    let mut tun_reads: u64 = 0;
    let mut tun_writes: u64 = 0;
    let mut last_stats = Instant::now();

    // If connector, drain initial handshake transmits.
    drain_and_send(
        state,
        port_id,
        mempool,
        identity,
        arp_table,
        &mut transmit_buf,
        &mut pkt_buf,
        &mut tx_pkts,
    )?;

    tracing::info!("DPDK engine started (polling loop)");

    loop {
        if shutdown.load(Ordering::Relaxed) {
            tracing::info!("shutdown signal received");
            break;
        }

        let now = Instant::now();

        // ── Phase 1a: RX burst → parse → feed QUIC ──────────────────

        let mut rx_mbufs: [*mut ffi::rte_mbuf; BURST_SIZE] =
            [std::ptr::null_mut(); BURST_SIZE];

        let nb_rx = port::rx_burst(port_id, 0, &mut rx_mbufs, BURST_SIZE as u16);

        for i in 0..nb_rx as usize {
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
                    if state.remote_addr.port() == 0 {
                        state.remote_addr = SocketAddr::new(udp.src_ip.into(), udp.src_port);
                        identity.remote_port = udp.src_port;
                        tracing::info!(remote = %state.remote_addr, "learned peer address");
                    }

                    quic_rx += 1;
                    let quic_data = BytesMut::from(udp.payload);

                    let remote_addr = SocketAddr::new(udp.src_ip.into(), udp.src_port);
                    if let Some(event) =
                        state
                            .endpoint
                            .handle(now, remote_addr, None, quic_data, &mut response_buf)
                    {
                        let responses =
                            shared::handle_datagram_event(state, event, &mut response_buf);

                        // Queue any stateless response transmits.
                        for (len, buf) in responses {
                            let dst_mac = identity
                                .remote_mac
                                .or_else(|| arp_table.lookup(identity.remote_ip))
                                .unwrap_or([0xff; 6]);

                            let frame_len = net::build_udp_packet(
                                &identity.local_mac,
                                &dst_mac,
                                identity.local_ip,
                                identity.remote_ip,
                                identity.local_port,
                                identity.remote_port,
                                &buf[..len],
                                &mut pkt_buf,
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

        // ── Phase 1b: Drain TUN channel → send_datagram ─────────────

        if let Some(conn) = state.connection.as_mut() {
            while let Ok(pkt) = tun_rx.try_recv() {
                tun_reads += 1;
                if let Err(e) = conn.datagrams().send(Bytes::from(pkt)) {
                    tracing::trace!(error = %e, "send_datagram failed (likely blocked)");
                }
            }
        }

        // ── Phase 1c: Timer check ───────────────────────────────────

        if now >= deadline {
            if let Some(conn) = state.connection.as_mut() {
                conn.handle_timeout(now);
            }
        }

        // ── Phase 2: Process QUIC events → write TUN ─────────────────

        shared::process_events(state, &mut drive_result);

        for datagram in &drive_result.datagrams {
            let ret =
                unsafe { libc::write(tun_fd, datagram.as_ptr() as *const libc::c_void, datagram.len()) };
            if ret > 0 {
                tun_writes += 1;
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
            port_id,
            mempool,
            identity,
            arp_table,
            &mut transmit_buf,
            &mut pkt_buf,
            &mut tx_pkts,
        )?;

        // Send pending raw frames (ARP replies, stateless QUIC responses).
        send_raw_frames(port_id, mempool, &mut pending_frames, &mut tx_pkts)?;

        // ── Update timer deadline ────────────────────────────────────

        deadline = if let Some(conn) = state.connection.as_ref() {
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
                tun_reads,
                tun_writes,
                "dpdk engine stats"
            );
            last_stats = now;
        }
    }

    Ok(())
}

/// Drain quinn-proto transmits and send them as Ethernet frames via DPDK.
#[allow(clippy::too_many_arguments)]
fn drain_and_send(
    state: &mut QuicState,
    port_id: u16,
    mempool: *mut ffi::rte_mempool,
    identity: &NetIdentity,
    arp_table: &ArpTable,
    transmit_buf: &mut Vec<u8>,
    pkt_buf: &mut [u8],
    tx_count: &mut u64,
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
        let Some(transmit) = conn.poll_transmit(now, 1, transmit_buf) else {
            break;
        };

        let payload = &transmit_buf[..transmit.size];

        // Determine destination from transmit (uses state remote_addr by default).
        let dst_ip = match transmit.destination {
            SocketAddr::V4(v4) => *v4.ip(),
            _ => identity.remote_ip,
        };
        let dst_port = transmit.destination.port();
        let actual_dst_mac = arp_table.lookup(dst_ip).unwrap_or(dst_mac);

        // Build Eth/IP/UDP frame.
        let frame_len = net::build_udp_packet(
            &identity.local_mac,
            &actual_dst_mac,
            identity.local_ip,
            dst_ip,
            identity.local_port,
            dst_port,
            payload,
            pkt_buf,
        );

        // Allocate mbuf and copy frame into it.
        let mut mbuf = Mbuf::alloc(mempool)?;
        mbuf.write_packet(&pkt_buf[..frame_len])?;
        tx_mbufs.push(mbuf.into_raw());
    }

    if !tx_mbufs.is_empty() {
        let nb = tx_mbufs.len() as u16;
        let sent = port::tx_burst(port_id, 0, &mut tx_mbufs, nb);
        *tx_count += sent as u64;

        // Free any mbufs that tx_burst didn't consume.
        for raw in &tx_mbufs[sent as usize..] {
            unsafe { ffi::shim_rte_pktmbuf_free(*raw) };
        }
    }

    Ok(())
}

/// Send pre-built raw Ethernet frames (ARP replies, stateless QUIC responses).
fn send_raw_frames(
    port_id: u16,
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
    let sent = port::tx_burst(port_id, 0, &mut tx_mbufs, nb);
    *tx_count += sent as u64;

    for raw in &tx_mbufs[sent as usize..] {
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
