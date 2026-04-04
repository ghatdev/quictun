//! Per-batch crypto pipeline engine.
//!
//! Architecture:
//!   I/O thread (mio poll) — reads TUN + UDP, assigns PNs, queues batches
//!   N crypto workers      — AEAD seal/open + header protection (all &self)
//!   I/O thread            — polls completions, replay check, GSO send, TUN write
//!
//! Selected via `pipeline = true` + `threads >= 2` in `[engine]`.

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::ops::Range;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use bytes::BytesMut;
use crossbeam_channel::{Receiver, Sender};
use mio::unix::SourceFd;
use mio::{Events, Interest, Poll};
use quinn_proto::ConnectionId;
use rustc_hash::FxHashMap;
use smallvec::SmallVec;
use tracing::{debug, info, warn};

use quictun_core::peer::{self, PeerConfig};
use quictun_core::quic_state::MultiQuicState;
use quictun_core::routing::{RouteAction, RoutingTable};
use quictun_proto::frame::AckFrame;
use quictun_proto::split::{KeyUpdateState, RxState, TxState};
use quictun_proto::packet::ShortHeader;
use quictun_proto::{decrypt_payload_in_place, encrypt_packet, unprotect_header};
use quictun_proto::cid_to_u64;
use quinn_proto::crypto::{HeaderKey, PacketKey};

use crate::engine::{
    EndpointSetup, HANDSHAKE_BUF_SIZE, MAX_PACKET, NetConfig, RunResult, TOKEN_SIGNAL, TOKEN_TUN,
    TOKEN_UDP, create_signal_pipe, create_udp_socket, drain_signal_pipe, drain_transmits,
    install_signal_handler, send_responses, set_nonblocking,
};
#[cfg(target_os = "linux")]
use crate::engine::flush_gso_sync;
#[cfg(target_os = "linux")]
use crate::engine::GroTxPool;
use quictun_tun::TunOptions;

// ── Batch types ──────────────────────────────────────────────────────────

/// Encrypt batch: inner packets → QUIC packets.
/// Created by I/O thread, processed by crypto worker, consumed by I/O thread.
struct EncryptBatch {
    // Input: inner packets to encrypt.
    payloads: Vec<Vec<u8>>,
    // Key snapshot (taken at PN assignment time).
    pn_start: u64,
    key_phase: bool,
    largest_acked: u64,
    tag_len: usize,
    remote_cid: ConnectionId,
    packet_key: Arc<Box<dyn PacketKey>>,
    header_key: Arc<Box<dyn HeaderKey>>,
    // Routing.
    remote_addr: SocketAddr,
    cid_key: u64,
    // Output: contiguous GSO buffer + per-packet lengths.
    gso_buf: Vec<u8>,
    packet_lens: Vec<usize>,
    encrypt_count: usize,
}

// SAFETY: PacketKey and HeaderKey implementations are Send+Sync (confirmed in quinn-proto).
unsafe impl Send for EncryptBatch {}

/// Per-packet decrypt result from a crypto worker.
enum DecryptOutcome {
    /// Successfully decrypted.
    Ok {
        pn: u64,
        key_phase: bool,
        datagrams: SmallVec<[Range<usize>; 4]>,
        ack: Option<AckFrame>,
        close_received: bool,
    },
    /// AEAD or header unprotect failed.
    Failed,
    /// Header unprotected but key_phase differs from expected.
    /// Packet data is preserved (AEAD not attempted with wrong key).
    /// I/O thread retries with the correct key after committing rotation.
    KeyPhaseMismatch { hdr: ShortHeader },
}

/// Decrypt batch: QUIC packets → inner packets.
///
/// Uses a contiguous slab instead of Vec<Vec<u8>> to eliminate per-packet
/// heap allocation in the recvmmsg → decrypt path.
struct DecryptBatch {
    // Input: contiguous buffer holding all packet data.
    slab: Vec<u8>,
    // (offset, length) for each packet in the slab.
    offsets: Vec<(usize, usize)>,
    // Key snapshot from RxState.
    rx_header_key: Arc<Box<dyn HeaderKey>>,
    rx_packet_key: Arc<Box<dyn PacketKey>>,
    largest_rx_pn: u64,
    cid_len: usize,
    tag_len: usize,
    cid_key: u64,
    // Expected peer key phase (for detecting key rotation).
    peer_key_phase: bool,
    // Output: per-packet results.
    results: Vec<DecryptOutcome>,
}

impl DecryptBatch {
    fn packet(&self, i: usize) -> &[u8] {
        let (offset, len) = self.offsets[i];
        &self.slab[offset..offset + len]
    }

    fn packet_mut(&mut self, i: usize) -> &mut [u8] {
        let (offset, len) = self.offsets[i];
        &mut self.slab[offset..offset + len]
    }

    fn packet_count(&self) -> usize {
        self.offsets.len()
    }
}

unsafe impl Send for DecryptBatch {}

/// Job sent from I/O thread to crypto workers.
enum CryptoJob {
    Encrypt(Box<EncryptBatch>),
    Decrypt(Box<DecryptBatch>),
}

/// Completed job returned from crypto workers to I/O thread.
enum CryptoResult {
    Encrypt(Box<EncryptBatch>),
    Decrypt(Box<DecryptBatch>),
}

// ── Per-connection pipeline state ────────────────────────────────────────

struct PipelineConnEntry {
    tx: Arc<TxState>,
    rx: RxState,
    key_update: Arc<KeyUpdateState>,
    tunnel_ip: Ipv4Addr,
    allowed_ips: Vec<ipnet::Ipv4Net>,
    remote_addr: SocketAddr,
    keepalive_interval: Duration,
    last_tx: Instant,
    last_rx: Instant,
}

// ── Crypto worker ────────────────────────────────────────────────────────

fn crypto_worker(
    id: usize,
    job_rx: Receiver<CryptoJob>,
    done_tx: Sender<CryptoResult>,
) {
    debug!(worker = id, "crypto worker started");

    while let Ok(job) = job_rx.recv() {
        match job {
            CryptoJob::Encrypt(mut batch) => {
                let mut gso_pos = 0usize;
                let count = batch.payloads.len();
                batch.packet_lens.clear();
                batch.encrypt_count = 0;

                for i in 0..count {
                    let pn = batch.pn_start + i as u64;
                    match encrypt_packet(
                        &batch.payloads[i],
                        &batch.remote_cid,
                        pn,
                        batch.largest_acked,
                        batch.key_phase,
                        &**batch.packet_key,
                        &**batch.header_key,
                        batch.tag_len,
                        &mut batch.gso_buf[gso_pos..],
                    ) {
                        Ok(result) => {
                            batch.packet_lens.push(result.len);
                            gso_pos += result.len;
                            batch.encrypt_count += 1;
                        }
                        Err(e) => {
                            warn!(worker = id, error = %e, "encrypt failed in batch");
                            break;
                        }
                    }
                }

                let _ = done_tx.send(CryptoResult::Encrypt(batch));
            }
            CryptoJob::Decrypt(mut batch) => {
                let count = batch.packet_count();
                batch.results.clear();

                // Cache fields to avoid borrow conflicts with packet_mut.
                let cid_len = batch.cid_len;
                let tag_len = batch.tag_len;
                let largest_rx_pn = batch.largest_rx_pn;
                let peer_key_phase = batch.peer_key_phase;
                let rx_header_key = Arc::clone(&batch.rx_header_key);
                let rx_packet_key = Arc::clone(&batch.rx_packet_key);

                for i in 0..count {
                    match unprotect_header(
                        batch.packet_mut(i),
                        cid_len,
                        tag_len,
                        &**rx_header_key,
                        largest_rx_pn,
                    ) {
                        Ok(hdr) => {
                            // Key phase mismatch: skip AEAD (wrong key would corrupt buffer).
                            // Return to I/O thread for retry with rotated key.
                            if hdr.key_phase != peer_key_phase {
                                batch.results.push(DecryptOutcome::KeyPhaseMismatch { hdr });
                                continue;
                            }
                            match decrypt_payload_in_place(
                                batch.packet_mut(i),
                                &hdr,
                                &**rx_packet_key,
                            ) {
                                Ok(result) => {
                                    batch.results.push(DecryptOutcome::Ok {
                                        pn: hdr.pn,
                                        key_phase: hdr.key_phase,
                                        datagrams: result.datagrams,
                                        ack: result.ack,
                                        close_received: result.close_received,
                                    });
                                }
                                Err(_) => {
                                    batch.results.push(DecryptOutcome::Failed);
                                }
                            }
                        }
                        Err(_) => {
                            batch.results.push(DecryptOutcome::Failed);
                        }
                    }
                }

                let _ = done_tx.send(CryptoResult::Decrypt(batch));
            }
        }
    }

    debug!(worker = id, "crypto worker exiting");
}

// ── Pipeline engine ──────────────────────────────────────────────────────

pub fn run_pipeline(
    local_addr: SocketAddr,
    setup: EndpointSetup,
    config: NetConfig,
) -> Result<RunResult> {
    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });
    let n_workers = config.threads - 1;
    info!(
        threads = config.threads,
        workers = n_workers,
        "starting pipeline engine"
    );

    // 1. Create UDP socket + TUN device.
    let udp_socket = create_udp_socket(local_addr, config.recv_buf, config.send_buf)?;
    info!(local_addr = %udp_socket.local_addr()?, "UDP socket bound");

    let mut tun_opts = TunOptions::new(config.tunnel_ip, config.tunnel_prefix, config.tunnel_mtu);
    tun_opts.name = config.tunnel_name.clone();
    #[cfg(target_os = "linux")]
    {
        tun_opts.offload = config.offload;
    }
    let tun = quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;
    set_nonblocking(tun.as_raw_fd())?;

    // 2. Signal pipe.
    let (sig_read_fd, sig_write_fd) = create_signal_pipe()?;
    install_signal_handler(sig_write_fd)?;

    // 3. MultiQuicState.
    let mut multi_state = match &setup {
        EndpointSetup::Listener { server_config } => MultiQuicState::new(server_config.clone()),
        EndpointSetup::Connector { .. } => MultiQuicState::new_connector(),
    };
    multi_state.ack_interval = config.ack_interval;

    if let EndpointSetup::Connector {
        remote_addr,
        client_config,
    } = setup
    {
        multi_state.connect(client_config, remote_addr, &config.server_name)?;
        drain_transmits(&udp_socket, &mut multi_state)?;
    }

    // 4. Crypto worker channels.
    let channel_cap = config.channel_capacity;
    let (job_tx, job_rx) = crossbeam_channel::bounded::<CryptoJob>(channel_cap);
    let (done_tx, done_rx) = crossbeam_channel::bounded::<CryptoResult>(channel_cap);

    // 5. mio poll.
    let mut poll = Poll::new().context("failed to create mio::Poll")?;
    let mut events = Events::with_capacity(config.poll_events);

    let udp_raw_fd = udp_socket.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&udp_raw_fd), TOKEN_UDP, Interest::READABLE)?;
    let tun_raw_fd = tun.as_raw_fd();
    poll.registry()
        .register(&mut SourceFd(&tun_raw_fd), TOKEN_TUN, Interest::READABLE)?;
    poll.registry().register(
        &mut SourceFd(&sig_read_fd),
        TOKEN_SIGNAL,
        Interest::READABLE,
    )?;

    // 6. Connection table + routing.
    let mut connections: FxHashMap<u64, PipelineConnEntry> = FxHashMap::default();
    let mut routing_table = RoutingTable::new(config.tunnel_ip, false);
    let mut had_connection = false;

    // Buffers.
    let mut response_buf = vec![0u8; HANDSHAKE_BUF_SIZE];
    let mut encrypt_buf = vec![0u8; MAX_PACKET];

    // TUN write buffer for backpressure.
    let mut tun_write_pending: std::collections::VecDeque<Vec<u8>> =
        std::collections::VecDeque::with_capacity(config.tun_write_buf_capacity);

    // Linux: batch RX buffers.
    #[cfg(target_os = "linux")]
    let batch_size = config.batch_size;
    #[cfg(target_os = "linux")]
    let mut recv_bufs = vec![vec![0u8; MAX_PACKET]; batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_lens = vec![0usize; batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_addrs =
        vec![SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0); batch_size];
    #[cfg(target_os = "linux")]
    let mut recv_work = quictun_core::batch_io::RecvMmsgWork::new(batch_size);

    #[cfg(not(target_os = "linux"))]
    let mut recv_buf = vec![0u8; MAX_PACKET];

    // Linux: TUN offload buffers.
    #[cfg(target_os = "linux")]
    let offload_enabled = config.offload;
    #[cfg(target_os = "linux")]
    let mut tun_original_buf = if offload_enabled {
        vec![0u8; quictun_tun::VIRTIO_NET_HDR_LEN + 65535]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut tun_split_bufs = if offload_enabled {
        vec![vec![0u8; 1500]; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };
    #[cfg(target_os = "linux")]
    let mut tun_split_sizes = if offload_enabled {
        vec![0usize; quictun_tun::IDEAL_BATCH_SIZE]
    } else {
        Vec::new()
    };

    // ACK timer.
    let ack_timer_interval = Duration::from_millis(config.ack_timer_ms as u64);
    let mut next_ack_deadline = Instant::now() + ack_timer_interval;

    // Track in-flight batches for backpressure awareness.
    let mut in_flight_batches: usize = 0;

    // 7. Spawn crypto workers.
    let shutdown = Arc::new(AtomicBool::new(false));

    let result = std::thread::scope(|s| {
        // Spawn workers.
        let mut worker_handles = Vec::with_capacity(n_workers);
        for i in 0..n_workers {
            let rx = job_rx.clone();
            let tx = done_tx.clone();
            let handle = s.spawn(move || crypto_worker(i, rx, tx));
            worker_handles.push(handle);
        }
        // Drop our copies so channels close when workers exit.
        drop(job_rx);
        drop(done_tx);

        // 8. Main poll loop.
        let io_result = pipeline_io_loop(
            &udp_socket,
            &tun,
            sig_read_fd,
            &mut poll,
            &mut events,
            &mut multi_state,
            &mut connections,
            &mut routing_table,
            &mut had_connection,
            &config,
            is_connector,
            &job_tx,
            &done_rx,
            &mut response_buf,
            &mut encrypt_buf,
            &mut tun_write_pending,
            #[cfg(target_os = "linux")]
            &mut recv_bufs,
            #[cfg(target_os = "linux")]
            &mut recv_lens,
            #[cfg(target_os = "linux")]
            &mut recv_addrs,
            #[cfg(target_os = "linux")]
            &mut recv_work,
            #[cfg(not(target_os = "linux"))]
            &mut recv_buf,
            #[cfg(target_os = "linux")]
            &mut tun_original_buf,
            #[cfg(target_os = "linux")]
            &mut tun_split_bufs,
            #[cfg(target_os = "linux")]
            &mut tun_split_sizes,
            &mut next_ack_deadline,
            ack_timer_interval,
            &mut in_flight_batches,
        );

        // Shutdown: drop job_tx so workers exit.
        drop(job_tx);
        shutdown.store(true, Ordering::Release);

        for (i, handle) in worker_handles.into_iter().enumerate() {
            match handle.join() {
                Ok(()) => debug!(worker = i, "crypto worker exited"),
                Err(_) => warn!(worker = i, "crypto worker panicked"),
            }
        }

        io_result
    });

    result
}

#[allow(clippy::too_many_arguments)]
fn pipeline_io_loop(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    sig_read_fd: i32,
    poll: &mut Poll,
    events: &mut Events,
    multi_state: &mut MultiQuicState,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    routing_table: &mut RoutingTable,
    had_connection: &mut bool,
    config: &NetConfig,
    is_connector: bool,
    job_tx: &Sender<CryptoJob>,
    done_rx: &Receiver<CryptoResult>,
    response_buf: &mut Vec<u8>,
    encrypt_buf: &mut [u8],
    tun_write_pending: &mut std::collections::VecDeque<Vec<u8>>,
    #[cfg(target_os = "linux")] recv_bufs: &mut [Vec<u8>],
    #[cfg(target_os = "linux")] recv_lens: &mut [usize],
    #[cfg(target_os = "linux")] recv_addrs: &mut [SocketAddr],
    #[cfg(target_os = "linux")] recv_work: &mut quictun_core::batch_io::RecvMmsgWork,
    #[cfg(not(target_os = "linux"))] recv_buf: &mut [u8],
    #[cfg(target_os = "linux")] tun_original_buf: &mut [u8],
    #[cfg(target_os = "linux")] tun_split_bufs: &mut [Vec<u8>],
    #[cfg(target_os = "linux")] tun_split_sizes: &mut [usize],
    next_ack_deadline: &mut Instant,
    ack_timer_interval: Duration,
    in_flight_batches: &mut usize,
) -> Result<RunResult> {
    // Track idle iterations for falling back to epoll when no data flows.
    let mut idle_iters: u32 = 0;
    const BUSY_POLL_THRESHOLD: u32 = 64;

    // GRO TX pool and table for batched TUN writes.
    #[cfg(target_os = "linux")]
    let mut gro_tx_pool = GroTxPool::new();
    #[cfg(target_os = "linux")]
    let mut gro_table = if config.offload {
        Some(quictun_tun::GROTable::default())
    } else {
        None
    };

    loop {
        let mut signal_received = false;
        let mut udp_readable;
        let mut tun_readable;

        // Hot path: skip epoll when data is actively flowing.
        // All fds are non-blocking, so we just try I/O directly.
        // Only fall back to epoll after BUSY_POLL_THRESHOLD idle iterations.
        if *in_flight_batches > 0 || idle_iters < BUSY_POLL_THRESHOLD {
            // Busy-poll: assume both readable, let WouldBlock handle it.
            udp_readable = true;
            tun_readable = true;
            // Check signal pipe periodically (every 256 iterations).
            if idle_iters & 0xFF == 0xFF {
                let mut sig_byte = [0u8; 1];
                let ret = unsafe {
                    libc::read(sig_read_fd, sig_byte.as_mut_ptr() as *mut libc::c_void, 1)
                };
                if ret > 0 {
                    signal_received = true;
                }
            }
        } else {
            // Cold path: no data flowing, use epoll to block until event.
            let mut timeout = Duration::from_secs(5);
            for entry in connections.values() {
                let ka_rem = entry.keepalive_interval.saturating_sub(entry.last_tx.elapsed());
                let idle_rem = config.idle_timeout.saturating_sub(entry.last_rx.elapsed());
                timeout = timeout.min(ka_rem).min(idle_rem);
            }
            for hs in multi_state.handshakes.values_mut() {
                if let Some(deadline) = hs.connection.poll_timeout() {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    timeout = timeout.min(remaining);
                }
            }
            let ack_rem = next_ack_deadline.saturating_duration_since(Instant::now());
            timeout = timeout.min(ack_rem).max(Duration::from_millis(1));

            poll.poll(events, Some(timeout))?;

            udp_readable = false;
            tun_readable = false;
            for event in events.iter() {
                match event.token() {
                    TOKEN_SIGNAL => signal_received = true,
                    TOKEN_UDP => udp_readable = true,
                    TOKEN_TUN => tun_readable = true,
                    _ => {}
                }
            }
        }

        if signal_received {
            drain_signal_pipe(sig_read_fd);
            info!("received signal, shutting down pipeline engine");
            for entry in connections.values() {
                let mut close_buf = vec![0u8; MAX_PACKET];
                if let Ok(result) = entry.tx.encrypt_datagram(&[], &mut close_buf) {
                    let _ = udp.send_to(&close_buf[..result.len], entry.remote_addr);
                }
            }
            return Ok(RunResult::Shutdown);
        }

        // ── Drain completed batches ──────────────────────────────────
        drain_completions(
            udp,
            tun,
            connections,
            routing_table,
            done_rx,
            tun_write_pending,
            in_flight_batches,
            #[cfg(target_os = "linux")]
            config.offload,
            #[cfg(target_os = "linux")]
            &mut gro_tx_pool,
            #[cfg(target_os = "linux")]
            &mut gro_table,
        )?;

        // ── Drain buffered TUN writes ────────────────────────────────
        drain_tun_write_buf(tun, tun_write_pending);

        // ── UDP RX → decrypt batches ─────────────────────────────────
        if udp_readable {
            #[cfg(target_os = "linux")]
            {
                pipeline_udp_rx_linux(
                    udp,
                    connections,
                    config.cid_len,
                    multi_state,
                    recv_bufs,
                    recv_lens,
                    recv_addrs,
                    recv_work,
                    response_buf,
                    job_tx,
                    in_flight_batches,
                )?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                pipeline_udp_rx(
                    udp,
                    connections,
                    config.cid_len,
                    multi_state,
                    recv_buf,
                    response_buf,
                    job_tx,
                    in_flight_batches,
                )?;
            }
        }

        // ── Drain completions again (process results from batches submitted above) ──
        drain_completions(
            udp,
            tun,
            connections,
            routing_table,
            done_rx,
            tun_write_pending,
            in_flight_batches,
            #[cfg(target_os = "linux")]
            config.offload,
            #[cfg(target_os = "linux")]
            &mut gro_tx_pool,
            #[cfg(target_os = "linux")]
            &mut gro_table,
        )?;
        drain_tun_write_buf(tun, tun_write_pending);

        // ── TUN RX → encrypt batches ─────────────────────────────────
        if tun_readable {
            #[cfg(target_os = "linux")]
            {
                if config.offload {
                    pipeline_tun_rx_offload(
                        tun,
                        connections,
                        routing_table,
                        job_tx,
                        in_flight_batches,
                        tun_original_buf,
                        tun_split_bufs,
                        tun_split_sizes,
                    )?;
                } else {
                    pipeline_tun_rx(
                        tun,
                        connections,
                        routing_table,
                        job_tx,
                        in_flight_batches,
                    )?;
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                pipeline_tun_rx(
                    tun,
                    connections,
                    routing_table,
                    job_tx,
                    in_flight_batches,
                )?;
            }
        }

        // ── Drain completions once more (encrypt batches from TUN RX) ──
        drain_completions(
            udp,
            tun,
            connections,
            routing_table,
            done_rx,
            tun_write_pending,
            in_flight_batches,
            #[cfg(target_os = "linux")]
            config.offload,
            #[cfg(target_os = "linux")]
            &mut gro_tx_pool,
            #[cfg(target_os = "linux")]
            &mut gro_table,
        )?;

        // ── Timeouts + keepalives ────────────────────────────────────
        pipeline_timeouts(udp, connections, routing_table, multi_state, config.idle_timeout, encrypt_buf)?;

        // ── Standalone ACK timer ─────────────────────────────────────
        if Instant::now() >= *next_ack_deadline {
            pipeline_send_acks(udp, connections, encrypt_buf);
            *next_ack_deadline = Instant::now() + ack_timer_interval;
        }

        // ── Drive handshakes ─────────────────────────────────────────
        pipeline_drive_handshakes(
            udp,
            multi_state,
            connections,
            routing_table,
            &config.peers,
            config.max_peers,
        )?;

        if !*had_connection && !connections.is_empty() {
            *had_connection = true;
        }

        // ── ConnectionLost detection ─────────────────────────────────
        if is_connector
            && *had_connection
            && connections.is_empty()
            && multi_state.handshakes.is_empty()
        {
            info!("all connections lost, returning ConnectionLost for reconnect");
            return Ok(RunResult::ConnectionLost);
        }

        // Track idle iterations for busy-poll → epoll fallback.
        if *in_flight_batches > 0 {
            idle_iters = 0;
        } else {
            idle_iters = idle_iters.saturating_add(1);
        }
    }
}

// ── Drain completions ────────────────────────────────────────────────────

fn drain_completions(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    routing_table: &mut RoutingTable,
    done_rx: &Receiver<CryptoResult>,
    tun_write_pending: &mut std::collections::VecDeque<Vec<u8>>,
    in_flight_batches: &mut usize,
    #[cfg(target_os = "linux")] offload: bool,
    #[cfg(target_os = "linux")] gro_tx_pool: &mut GroTxPool,
    #[cfg(target_os = "linux")] gro_table: &mut Option<quictun_tun::GROTable>,
) -> Result<()> {
    while let Ok(result) = done_rx.try_recv() {
        *in_flight_batches = in_flight_batches.saturating_sub(1);
        match result {
            CryptoResult::Encrypt(batch) => {
                handle_encrypt_completion(udp, connections, &batch)?;
            }
            CryptoResult::Decrypt(mut batch) => {
                handle_decrypt_completion(
                    tun,
                    connections,
                    routing_table,
                    &mut batch,
                    tun_write_pending,
                    #[cfg(target_os = "linux")]
                    offload,
                    #[cfg(target_os = "linux")]
                    gro_tx_pool,
                );
            }
        }
    }

    // Flush accumulated GRO TX buffers to TUN.
    #[cfg(target_os = "linux")]
    if offload && !gro_tx_pool.is_empty() {
        if let Some(gro) = gro_table {
            match tun.send_multiple(gro, gro_tx_pool.as_mut_slice(), quictun_tun::VIRTIO_NET_HDR_LEN) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    for buf in gro_tx_pool.iter() {
                        tun_write_pending.push_back(buf.clone());
                    }
                }
                Err(e) => {
                    debug!(error = %e, "TUN send_multiple failed");
                }
            }
            gro_tx_pool.reset();
        }
    }

    Ok(())
}

fn handle_encrypt_completion(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    batch: &EncryptBatch,
) -> Result<()> {
    if batch.encrypt_count == 0 {
        return Ok(());
    }

    // Send encrypted packets via GSO (same-size grouping, chunked to max segments).
    #[cfg(target_os = "linux")]
    {
        let max_segs = quictun_core::batch_io::GSO_MAX_SEGMENTS;
        let mut pos = 0usize;
        let mut seg_start = 0usize;
        let mut seg_size = 0usize;
        let mut seg_count = 0usize;

        for i in 0..batch.encrypt_count {
            let len = batch.packet_lens[i];
            if seg_count == 0 {
                seg_size = len;
                seg_count = 1;
            } else if len == seg_size && seg_count < max_segs {
                seg_count += 1;
            } else {
                // Flush current GSO run (hit max segments or size change).
                flush_gso_sync(
                    udp,
                    &batch.gso_buf[seg_start..],
                    pos - seg_start,
                    seg_size,
                    batch.remote_addr,
                )?;
                seg_start = pos;
                seg_size = len;
                seg_count = 1;
            }
            pos += len;
        }
        if seg_count > 0 {
            flush_gso_sync(
                udp,
                &batch.gso_buf[seg_start..],
                pos - seg_start,
                seg_size,
                batch.remote_addr,
            )?;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut pos = 0usize;
        for i in 0..batch.encrypt_count {
            let len = batch.packet_lens[i];
            let _ = udp.send_to(&batch.gso_buf[pos..pos + len], batch.remote_addr);
            pos += len;
        }
    }

    // Update last_tx.
    if let Some(entry) = connections.get_mut(&batch.cid_key) {
        entry.last_tx = Instant::now();
    }

    Ok(())
}

fn handle_decrypt_completion(
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    routing_table: &mut RoutingTable,
    batch: &mut DecryptBatch,
    tun_write_pending: &mut std::collections::VecDeque<Vec<u8>>,
    #[cfg(target_os = "linux")] offload: bool,
    #[cfg(target_os = "linux")] gro_tx_pool: &mut GroTxPool,
) {
    let entry = match connections.get_mut(&batch.cid_key) {
        Some(e) => e,
        None => return,
    };

    let mut close_received = false;
    let mut has_key_mismatch = false;

    // Pass 1: process Ok results (immutable batch access, no clones).
    for (i, result) in batch.results.iter().enumerate() {
        match result {
            DecryptOutcome::Ok {
                pn,
                key_phase,
                datagrams,
                ack,
                close_received: pkt_close,
            } => {
                // Key phase check (sequential, on I/O thread).
                entry.rx.check_key_phase(*key_phase, &entry.key_update, &entry.tx);

                // Replay check (sequential).
                if !entry.rx.accept_decrypted_pn(*pn) {
                    continue; // Duplicate.
                }

                entry.last_rx = Instant::now();

                // Process ACK.
                if let Some(ack_frame) = ack {
                    entry.tx.update_largest_acked(ack_frame.largest_acked);
                }

                if *pkt_close {
                    close_received = true;
                }

                // Write datagrams to TUN (via GRO pool on Linux, per-packet otherwise).
                for range in datagrams {
                    let datagram = &batch.packet(i)[range.clone()];
                    if datagram.len() < 20 {
                        continue;
                    }
                    let src_ip =
                        Ipv4Addr::new(datagram[12], datagram[13], datagram[14], datagram[15]);
                    if !peer::is_allowed_source(&entry.allowed_ips, src_ip) {
                        debug!(src = %src_ip, "dropping: source IP not in allowed_ips");
                        continue;
                    }
                    #[cfg(target_os = "linux")]
                    if offload {
                        gro_tx_pool.push_datagram(datagram);
                    } else {
                        write_to_tun(tun, datagram, tun_write_pending, false);
                    }
                    #[cfg(not(target_os = "linux"))]
                    write_to_tun(tun, datagram, tun_write_pending);
                }
            }
            DecryptOutcome::KeyPhaseMismatch { .. } => {
                has_key_mismatch = true;
            }
            DecryptOutcome::Failed => {}
        }
    }

    // Pass 2: handle key phase mismatches (rare — once per 7M packets).
    // Needs mutable batch.packets access for AEAD retry.
    if has_key_mismatch {
        for i in 0..batch.results.len() {
            if let DecryptOutcome::KeyPhaseMismatch { hdr } = &batch.results[i] {
                let hdr = *hdr;

                // Commit key rotation on I/O thread (sequential, idempotent).
                entry.rx.check_key_phase(hdr.key_phase, &entry.key_update, &entry.tx);

                // Retry AEAD with rotated key.
                let key = entry.rx.packet_key();
                match decrypt_payload_in_place(batch.packet_mut(i), &hdr, &**key) {
                    Ok(result) => {
                        if !entry.rx.accept_decrypted_pn(hdr.pn) {
                            continue;
                        }
                        entry.last_rx = Instant::now();

                        if let Some(ack_frame) = &result.ack {
                            entry.tx.update_largest_acked(ack_frame.largest_acked);
                        }
                        if result.close_received {
                            close_received = true;
                        }

                        for datagram_range in &result.datagrams {
                            let datagram = &batch.packet(i)[datagram_range.clone()];
                            if datagram.len() < 20 {
                                continue;
                            }
                            let src_ip =
                                Ipv4Addr::new(datagram[12], datagram[13], datagram[14], datagram[15]);
                            if !peer::is_allowed_source(&entry.allowed_ips, src_ip) {
                                continue;
                            }
                            #[cfg(target_os = "linux")]
                            if offload {
                                gro_tx_pool.push_datagram(datagram);
                            } else {
                                write_to_tun(tun, datagram, tun_write_pending, false);
                            }
                            #[cfg(not(target_os = "linux"))]
                            write_to_tun(tun, datagram, tun_write_pending);
                        }

                        debug!("key rotation: retried decrypt on I/O thread succeeded");
                    }
                    Err(_) => {
                        debug!("key rotation: retry decrypt failed, dropping packet");
                    }
                }
            }
        }
    }

    if close_received {
        let cid_key = batch.cid_key;
        if let Some(removed) = connections.remove(&cid_key) {
            routing_table.remove_peer_routes(cid_key);
            info!(
                tunnel_ip = %removed.tunnel_ip,
                cid = %hex::encode(cid_key.to_ne_bytes()),
                "peer sent CONNECTION_CLOSE, removed"
            );
        }
    }
}

fn write_to_tun(
    tun: &tun_rs::SyncDevice,
    datagram: &[u8],
    pending: &mut std::collections::VecDeque<Vec<u8>>,
    #[cfg(target_os = "linux")] offload: bool,
) {
    #[cfg(target_os = "linux")]
    let data = if offload {
        let hdr_len = quictun_tun::VIRTIO_NET_HDR_LEN;
        let mut buf = vec![0u8; hdr_len + datagram.len()];
        buf[hdr_len..].copy_from_slice(datagram);
        buf
    } else {
        datagram.to_vec()
    };
    #[cfg(not(target_os = "linux"))]
    let data = datagram.to_vec();

    if !pending.is_empty() {
        if pending.len() >= pending.capacity().max(256) {
            pending.pop_front();
        }
        pending.push_back(data);
        return;
    }

    match tun.send(&data) {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
            pending.push_back(data);
        }
        Err(e) => {
            debug!(error = %e, "TUN write failed, dropping");
        }
    }
}

fn drain_tun_write_buf(
    tun: &tun_rs::SyncDevice,
    pending: &mut std::collections::VecDeque<Vec<u8>>,
) {
    while let Some(pkt) = pending.front() {
        match tun.send(pkt) {
            Ok(_) => {
                pending.pop_front();
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => {
                debug!(error = %e, "TUN drain write failed, dropping");
                pending.pop_front();
            }
        }
    }
}

// ── UDP RX: receive and create decrypt batches ───────────────────────────

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn pipeline_udp_rx_linux(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    recv_bufs: &mut [Vec<u8>],
    recv_lens: &mut [usize],
    recv_addrs: &mut [SocketAddr],
    recv_work: &mut quictun_core::batch_io::RecvMmsgWork,
    response_buf: &mut Vec<u8>,
    job_tx: &Sender<CryptoJob>,
    in_flight: &mut usize,
) -> Result<()> {
    loop {
        let max_batch = recv_bufs.len();
        let n_msgs = match quictun_core::batch_io::recvmmsg_batch(
            udp,
            recv_bufs,
            recv_lens,
            recv_addrs,
            max_batch,
            recv_work,
        ) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e).context("recvmmsg failed"),
        };

        // Group short-header packets by CID into slab buffers.
        let mut decrypt_groups: FxHashMap<u64, (Vec<u8>, Vec<(usize, usize)>)> =
            FxHashMap::default();

        for i in 0..n_msgs {
            let n = recv_lens[i];
            if n == 0 {
                continue;
            }

            if recv_bufs[i][0] & 0x80 != 0 {
                // Long header → handshake (process inline).
                let from = recv_addrs[i];
                let mut data = BytesMut::with_capacity(n);
                data.extend_from_slice(&recv_bufs[i][..n]);
                let now = Instant::now();
                let responses =
                    multi_state.handle_incoming(now, from, None, data, response_buf);
                send_responses(udp, &responses, from)?;
                continue;
            }

            // Short header → group by CID.
            if cid_len == 0 || n < 1 + cid_len {
                continue;
            }
            let cid_key = cid_to_u64(&recv_bufs[i][1..1 + cid_len]);

            if connections.contains_key(&cid_key) {
                let (slab, offsets) = decrypt_groups.entry(cid_key).or_default();
                let offset = slab.len();
                slab.extend_from_slice(&recv_bufs[i][..n]);
                offsets.push((offset, n));
            }
        }

        // Create decrypt batches per connection.
        for (cid_key, (slab, offsets)) in decrypt_groups {
            submit_decrypt_batch(connections, cid_key, slab, offsets, job_tx, in_flight);
        }

        if n_msgs < max_batch {
            return Ok(());
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn pipeline_udp_rx(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    recv_buf: &mut [u8],
    response_buf: &mut Vec<u8>,
    job_tx: &Sender<CryptoJob>,
    in_flight: &mut usize,
) -> Result<()> {
    let mut decrypt_groups: FxHashMap<u64, (Vec<u8>, Vec<(usize, usize)>)> =
        FxHashMap::default();

    loop {
        match udp.recv_from(recv_buf) {
            Ok((n, from)) => {
                if n == 0 {
                    continue;
                }
                if recv_buf[0] & 0x80 != 0 {
                    let mut data = BytesMut::with_capacity(n);
                    data.extend_from_slice(&recv_buf[..n]);
                    let now = Instant::now();
                    let responses =
                        multi_state.handle_incoming(now, from, None, data, response_buf);
                    send_responses(udp, &responses, from)?;
                } else if cid_len > 0 && n > cid_len {
                    let cid_key = cid_to_u64(&recv_buf[1..1 + cid_len]);
                    if connections.contains_key(&cid_key) {
                        let (slab, offsets) = decrypt_groups.entry(cid_key).or_default();
                        let offset = slab.len();
                        slab.extend_from_slice(&recv_buf[..n]);
                        offsets.push((offset, n));
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("UDP recv_from failed"),
        }
    }

    for (cid_key, (slab, offsets)) in decrypt_groups {
        submit_decrypt_batch(connections, cid_key, slab, offsets, job_tx, in_flight);
    }

    Ok(())
}

fn submit_decrypt_batch(
    connections: &FxHashMap<u64, PipelineConnEntry>,
    cid_key: u64,
    slab: Vec<u8>,
    offsets: Vec<(usize, usize)>,
    job_tx: &Sender<CryptoJob>,
    in_flight: &mut usize,
) {
    let entry = match connections.get(&cid_key) {
        Some(e) => e,
        None => return,
    };

    let packets_count = offsets.len();
    let batch = Box::new(DecryptBatch {
        slab,
        offsets,
        rx_header_key: entry.rx.header_key(),
        rx_packet_key: entry.rx.packet_key(),
        largest_rx_pn: entry.rx.largest_rx_pn(),
        cid_len: entry.rx.local_cid_len(),
        tag_len: entry.tx.tag_len(),
        cid_key,
        peer_key_phase: entry.rx.peer_key_phase(),
        results: Vec::new(),
    });

    if job_tx.try_send(CryptoJob::Decrypt(batch)).is_ok() {
        *in_flight += 1;
        debug!(cid = %hex::encode(cid_key.to_ne_bytes()), packets = packets_count, "queued decrypt batch");
    } else {
        debug!("decrypt batch dropped (channel full)");
    }
}

// ── TUN RX: read and create encrypt batches ──────────────────────────────

fn pipeline_tun_rx(
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    routing_table: &RoutingTable,
    job_tx: &Sender<CryptoJob>,
    in_flight: &mut usize,
) -> Result<()> {
    // Collect packets grouped by CID.
    let mut groups: FxHashMap<u64, Vec<Vec<u8>>> = FxHashMap::default();

    loop {
        let mut packet = [0u8; 1500];
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 {
                    continue;
                }
                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                let cid = match routing_table.lookup(dest_ip) {
                    RouteAction::ForwardToPeer(cid) => cid,
                    _ if connections.len() == 1 => {
                        match connections.keys().next() {
                            Some(&cid) => cid,
                            None => continue,
                        }
                    }
                    _ => {
                        debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                        continue;
                    }
                };
                if !connections.contains_key(&cid) {
                    continue;
                }
                groups.entry(cid).or_default().push(packet[..n].to_vec());
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv failed"),
        }
    }

    for (cid_key, payloads) in groups {
        submit_encrypt_batch(connections, cid_key, payloads, job_tx, in_flight);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn pipeline_tun_rx_offload(
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    routing_table: &RoutingTable,
    job_tx: &Sender<CryptoJob>,
    in_flight: &mut usize,
    original_buf: &mut [u8],
    split_bufs: &mut [Vec<u8>],
    split_sizes: &mut [usize],
) -> Result<()> {
    let mut groups: FxHashMap<u64, Vec<Vec<u8>>> = FxHashMap::default();

    loop {
        let n_pkts = match tun.recv_multiple(original_buf, split_bufs, split_sizes, 0) {
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("TUN recv_multiple failed"),
        };

        for i in 0..n_pkts {
            let pkt_len = split_sizes[i];
            if pkt_len < 20 {
                continue;
            }
            let packet = &split_bufs[i][..pkt_len];
            let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

            let cid = match routing_table.lookup(dest_ip) {
                RouteAction::ForwardToPeer(cid) => cid,
                _ if connections.len() == 1 => {
                    *connections.keys().next().expect("single connection")
                }
                _ => {
                    debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                    continue;
                }
            };
            if !connections.contains_key(&cid) {
                continue;
            }
            groups.entry(cid).or_default().push(packet.to_vec());
        }
    }

    for (cid_key, payloads) in groups {
        submit_encrypt_batch(connections, cid_key, payloads, job_tx, in_flight);
    }

    Ok(())
}

fn submit_encrypt_batch(
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    cid_key: u64,
    payloads: Vec<Vec<u8>>,
    job_tx: &Sender<CryptoJob>,
    in_flight: &mut usize,
) {
    let entry = match connections.get_mut(&cid_key) {
        Some(e) => e,
        None => return,
    };

    let count = payloads.len() as u64;

    // Check key update threshold BEFORE PN assignment.
    entry
        .key_update
        .maybe_initiate_key_update(count, &entry.tx, &mut entry.rx);

    // Assign PNs atomically.
    let pn_start = entry.tx.next_pn_batch(count);

    // Snapshot key state.
    let key_guard = entry.tx.load_packet_key();
    let packet_key = Arc::clone(&*key_guard);
    drop(key_guard);

    let gso_buf_size = payloads.len() * MAX_PACKET;

    let batch = Box::new(EncryptBatch {
        payloads,
        pn_start,
        key_phase: entry.tx.key_phase(),
        largest_acked: entry.tx.largest_acked(),
        tag_len: entry.tx.tag_len(),
        remote_cid: entry.tx.remote_cid().clone(),
        packet_key,
        header_key: entry.tx.header_key_arc(),
        remote_addr: entry.remote_addr,
        cid_key,
        gso_buf: vec![0u8; gso_buf_size],
        packet_lens: Vec::with_capacity(count as usize),
        encrypt_count: 0,
    });

    if job_tx.try_send(CryptoJob::Encrypt(batch)).is_ok() {
        *in_flight += 1;
        debug!(cid = %hex::encode(cid_key.to_ne_bytes()), count, pn_start, "queued encrypt batch");
    } else {
        debug!("encrypt batch dropped (channel full)");
    }
}

// ── Timeouts ─────────────────────────────────────────────────────────────

fn pipeline_timeouts(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    routing_table: &mut RoutingTable,
    multi_state: &mut MultiQuicState,
    idle_timeout: Duration,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    // Remove idle or key-exhausted connections.
    let expired: Vec<(u64, &'static str)> = connections
        .iter()
        .filter_map(|(&cid, e)| {
            if e.key_update.is_key_exhausted() {
                Some((cid, "key exhausted"))
            } else if e.last_rx.elapsed() >= idle_timeout {
                Some((cid, "idle timeout"))
            } else {
                None
            }
        })
        .collect();

    for (cid, reason) in expired {
        if let Some(entry) = connections.remove(&cid) {
            routing_table.remove_peer_routes(cid);
            info!(
                tunnel_ip = %entry.tunnel_ip,
                cid = %hex::encode(cid.to_ne_bytes()),
                reason,
                "connection removed"
            );
        }
    }

    // Keepalives (single-packet, done on I/O thread directly).
    for entry in connections.values_mut() {
        if entry.last_tx.elapsed() >= entry.keepalive_interval {
            match entry.tx.encrypt_datagram(&[], encrypt_buf) {
                Ok(result) => {
                    let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                    entry.last_tx = Instant::now();
                    debug!(pn = result.pn, remote = %entry.remote_addr, "sent keepalive");
                }
                Err(e) => {
                    warn!(error = %e, "keepalive encrypt failed");
                }
            }
        }
    }

    // Handshake timeouts.
    let now = Instant::now();
    for hs in multi_state.handshakes.values_mut() {
        hs.connection.handle_timeout(now);
    }

    Ok(())
}

// ── ACK timer ────────────────────────────────────────────────────────────

fn pipeline_send_acks(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    encrypt_buf: &mut [u8],
) {
    for entry in connections.values_mut() {
        if entry.rx.needs_ack() {
            let ack_ranges = entry.rx.generate_ack_ranges();
            let pn = entry.tx.next_pn();
            let key_guard = entry.tx.load_packet_key();
            match quictun_proto::encrypt_ack_packet(
                &ack_ranges,
                entry.tx.remote_cid(),
                pn,
                entry.tx.largest_acked(),
                entry.tx.key_phase(),
                &***key_guard,
                entry.tx.header_key(),
                entry.tx.tag_len(),
                encrypt_buf,
            ) {
                Ok(result) => {
                    let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                }
                Err(e) => {
                    warn!(error = %e, "ACK encrypt failed");
                }
            }
        }
    }
}

// ── Handshake driving ────────────────────────────────────────────────────

fn pipeline_drive_handshakes(
    udp: &std::net::UdpSocket,
    multi_state: &mut MultiQuicState,
    connections: &mut FxHashMap<u64, PipelineConnEntry>,
    routing_table: &mut RoutingTable,
    peers: &[PeerConfig],
    max_peers: usize,
) -> Result<()> {
    if multi_state.handshakes.is_empty() {
        return Ok(());
    }

    drain_transmits(udp, multi_state)?;
    let result = multi_state.poll_handshakes();
    drain_transmits(udp, multi_state)?;

    for ch in result.completed {
        let Some((hs, mut conn_state)) = multi_state.extract_connection(ch) else {
            continue;
        };

        // 1. Always identify peer (no single-peer skip — X.509 needs CN check).
        let matched_peer = match peer::identify_peer(&hs.connection, peers) {
            Some(p) => p,
            None => {
                warn!(remote = %hs.remote_addr, "could not identify peer, rejecting");
                let mut close_buf = vec![0u8; 128];
                if let Ok(result) = conn_state.encrypt_connection_close(&mut close_buf) {
                    if let Err(e) = udp.send_to(&close_buf[..result.len], hs.remote_addr) {
                        warn!(error = %e, "failed to send CONNECTION_CLOSE for rejected peer");
                    }
                }
                continue;
            }
        };
        let tunnel_ip = matched_peer.tunnel_ip;
        let allowed_ips = matched_peer.allowed_ips.clone();
        let keepalive_interval = matched_peer.keepalive.unwrap_or(Duration::from_secs(25));

        // 2. Reconnect: if this peer already has a connection, evict the old one.
        let old_cid = connections
            .iter()
            .find(|(_, e)| e.tunnel_ip == tunnel_ip)
            .map(|(&cid, _)| cid);
        if let Some(old) = old_cid {
            if let Some(entry) = connections.remove(&old) {
                routing_table.remove_peer_routes(old);
                info!(
                    tunnel_ip = %entry.tunnel_ip,
                    old_cid = %hex::encode(old.to_ne_bytes()),
                    "evicted stale connection (peer reconnected)"
                );
            }
        }

        // 3. Check max_peers (after eviction, so reconnects don't count double).
        if connections.len() >= max_peers {
            warn!(max_peers, remote = %hs.remote_addr, "max_peers reached, rejecting");
            let mut close_buf = vec![0u8; 128];
            if let Ok(result) = conn_state.encrypt_connection_close(&mut close_buf) {
                if let Err(e) = udp.send_to(&close_buf[..result.len], hs.remote_addr) {
                    warn!(error = %e, "failed to send CONNECTION_CLOSE for max_peers rejection");
                }
            }
            continue;
        }
        let cid_bytes: Vec<u8> = conn_state.local_cid()[..].to_vec();
        let cid_key = cid_to_u64(&cid_bytes);
        let now_inst = Instant::now();

        let split = conn_state.into_split();

        let remote_cid_bytes: Vec<u8> = split.tx.remote_cid()[..].to_vec();
        info!(
            remote = %hs.remote_addr,
            tunnel_ip = %tunnel_ip,
            local_cid = %hex::encode(&cid_bytes),
            remote_cid = %hex::encode(&remote_cid_bytes),
            "connection established (pipeline)"
        );

        routing_table.add_peer_routes(cid_key, &allowed_ips);
        connections.insert(
            cid_key,
            PipelineConnEntry {
                tx: split.tx,
                rx: split.rx,
                key_update: split.key_update,
                tunnel_ip,
                allowed_ips,
                remote_addr: hs.remote_addr,
                keepalive_interval,
                last_tx: now_inst,
                last_rx: now_inst,
            },
        );
    }

    Ok(())
}
