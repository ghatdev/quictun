//! Container pipeline engine with parallel decrypt via SharedConnectionState.
//!
//! Architecture:
//!   Thread 0 (Dispatcher/Writer):
//!     READ:  recvmmsg → fill containers → push to decrypt queue
//!            recv_multiple → fill containers → push to encrypt queue
//!     WRITE: poll completed containers → GRO flush to TUN / GSO send to UDP
//!     TIMER: periodic ACK (reads atomic largest_rx_pn), keepalives
//!
//!   Threads 1..N (Crypto Workers):
//!     Loop: recv container → decrypt/encrypt each packet → return completed
//!
//! Selected via `container = true` + `threads >= 2` in `[engine]`.

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
use quictun_quic::cid_to_u64;
use quictun_quic::encrypt_packet;
use quictun_quic::frame::AckFrame;
use quictun_quic::shared::SharedConnectionState;
use quinn_proto::crypto::{HeaderKey, PacketKey};

use crate::engine::{
    EndpointSetup, HANDSHAKE_BUF_SIZE, MAX_PACKET, NetConfig, RunResult, TOKEN_SIGNAL, TOKEN_TUN,
    TOKEN_UDP, create_signal_pipe, create_udp_socket, drain_signal_pipe, drain_transmits,
    install_signal_handler, send_responses, set_nonblocking,
};
#[cfg(target_os = "linux")]
use crate::engine::flush_gso_sync;
use quictun_tun::TunOptions;

// ── Container types ──────────────────────────────────────────────────────

/// Direction of a container batch.
enum Direction {
    Decrypt,
    Encrypt {
        pn_start: u64,
        key_phase: bool,
        largest_acked: u64,
        tag_len: usize,
        remote_cid: ConnectionId,
        packet_key: Arc<Box<dyn PacketKey>>,
        header_key: Arc<Box<dyn HeaderKey>>,
        remote_addr: SocketAddr,
    },
}

// SAFETY: PacketKey and HeaderKey are Send+Sync (confirmed in quinn-proto).
unsafe impl Send for Direction {}

/// Per-packet result from decrypt worker.
enum DecryptOutcome {
    Ok {
        datagrams: SmallVec<[Range<usize>; 4]>,
        ack: Option<AckFrame>,
        close_received: bool,
    },
    Failed,
}

/// A container of packets for batch crypto processing.
struct Container {
    /// Raw packet data (owned, worker decrypts/encrypts in place).
    packets: Vec<Vec<u8>>,
    /// Decrypt results per packet (filled by worker).
    decrypt_results: Vec<DecryptOutcome>,
    /// Encrypt output buffer (contiguous GSO buffer).
    encrypt_buf: Vec<u8>,
    /// Per-packet lengths in encrypt_buf.
    encrypt_lens: Vec<usize>,
    encrypt_count: usize,
    /// Connection key for routing results back.
    cid_key: u64,
    /// Direction (decrypt or encrypt).
    direction: Direction,
    /// Connection reference (for decrypt workers).
    conn: Option<Arc<SharedConnectionState>>,
}

// SAFETY: SharedConnectionState is Send+Sync. All other fields are owned.
unsafe impl Send for Container {}

// ── Per-connection state ─────────────────────────────────────────────────

struct ContainerConnEntry {
    shared: Arc<SharedConnectionState>,
    tunnel_ip: Ipv4Addr,
    allowed_ips: Vec<ipnet::Ipv4Net>,
    remote_addr: SocketAddr,
    keepalive_interval: Duration,
    last_tx: Instant,
    last_rx: Instant,
}

// ── Crypto worker ────────────────────────────────────────────────────────

fn container_worker(
    id: usize,
    job_rx: Receiver<Box<Container>>,
    done_tx: Sender<Box<Container>>,
) {
    debug!(worker = id, "container worker started");

    while let Ok(mut container) = job_rx.recv() {
        match &container.direction {
            Direction::Decrypt => {
                let conn = container.conn.as_ref().expect("decrypt container must have conn");
                container.decrypt_results.clear();

                for packet in &mut container.packets {
                    match conn.decrypt_in_place(packet) {
                        Ok(result) => {
                            container.decrypt_results.push(DecryptOutcome::Ok {
                                datagrams: result.datagrams,
                                ack: result.ack,
                                close_received: result.close_received,
                            });
                        }
                        Err(_) => {
                            container.decrypt_results.push(DecryptOutcome::Failed);
                        }
                    }
                }
            }
            Direction::Encrypt {
                pn_start,
                key_phase,
                largest_acked,
                tag_len,
                remote_cid,
                packet_key,
                header_key,
                ..
            } => {
                let mut gso_pos = 0usize;
                container.encrypt_lens.clear();
                container.encrypt_count = 0;

                for (i, payload) in container.packets.iter().enumerate() {
                    let pn = pn_start + i as u64;
                    match encrypt_packet(
                        payload,
                        remote_cid,
                        pn,
                        *largest_acked,
                        *key_phase,
                        &***packet_key,
                        &***header_key,
                        *tag_len,
                        &mut container.encrypt_buf[gso_pos..],
                    ) {
                        Ok(result) => {
                            container.encrypt_lens.push(result.len);
                            gso_pos += result.len;
                            container.encrypt_count += 1;
                        }
                        Err(e) => {
                            warn!(worker = id, error = %e, "encrypt failed in container");
                            break;
                        }
                    }
                }
            }
        }

        let _ = done_tx.send(container);
    }

    debug!(worker = id, "container worker exiting");
}

// ── Container pipeline entry point ───────────────────────────────────────

pub fn run_container(
    local_addr: SocketAddr,
    setup: EndpointSetup,
    config: NetConfig,
) -> Result<RunResult> {
    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });
    let n_workers = config.threads - 1;
    info!(
        threads = config.threads,
        workers = n_workers,
        "starting container pipeline engine"
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
        multi_state.connect(client_config, remote_addr)?;
        drain_transmits(&udp_socket, &mut multi_state)?;
    }

    // 4. Worker channels.
    let channel_cap = config.channel_capacity;
    let (job_tx, job_rx) = crossbeam_channel::bounded::<Box<Container>>(channel_cap);
    let (done_tx, done_rx) = crossbeam_channel::bounded::<Box<Container>>(channel_cap);

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

    // 6. Connection table.
    let mut connections: FxHashMap<u64, ContainerConnEntry> = FxHashMap::default();
    let mut ip_to_cid: FxHashMap<Ipv4Addr, u64> = FxHashMap::default();
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

    // Linux: GRO TUN write support.
    #[cfg(target_os = "linux")]
    let offload_enabled = config.offload;
    #[cfg(target_os = "linux")]
    let mut gro_table = if offload_enabled {
        Some(quictun_tun::GROTable::default())
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let mut gro_tx_pool = GroTxPool::new();

    // Linux: TUN offload buffers for recv_multiple.
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

    // Track in-flight containers.
    let mut in_flight: usize = 0;

    // 7. Spawn workers.
    let shutdown = Arc::new(AtomicBool::new(false));

    let result = std::thread::scope(|s| {
        let mut worker_handles = Vec::with_capacity(n_workers);
        for i in 0..n_workers {
            let rx = job_rx.clone();
            let tx = done_tx.clone();
            let handle = s.spawn(move || container_worker(i, rx, tx));
            worker_handles.push(handle);
        }
        drop(job_rx);
        drop(done_tx);

        // 8. Main I/O loop.
        let io_result = container_io_loop(
            &udp_socket,
            &tun,
            sig_read_fd,
            &mut poll,
            &mut events,
            &mut multi_state,
            &mut connections,
            &mut ip_to_cid,
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
            offload_enabled,
            #[cfg(target_os = "linux")]
            &mut gro_table,
            #[cfg(target_os = "linux")]
            &mut gro_tx_pool,
            #[cfg(target_os = "linux")]
            &mut tun_original_buf,
            #[cfg(target_os = "linux")]
            &mut tun_split_bufs,
            #[cfg(target_os = "linux")]
            &mut tun_split_sizes,
            &mut next_ack_deadline,
            ack_timer_interval,
            &mut in_flight,
        );

        drop(job_tx);
        shutdown.store(true, Ordering::Release);

        for (i, handle) in worker_handles.into_iter().enumerate() {
            match handle.join() {
                Ok(()) => debug!(worker = i, "container worker exited"),
                Err(_) => warn!(worker = i, "container worker panicked"),
            }
        }

        io_result
    });

    result
}

// ── GRO TX Pool (same as engine.rs) ──────────────────────────────────────

#[cfg(target_os = "linux")]
struct GroTxPool {
    bufs: Vec<Vec<u8>>,
    active: usize,
}

#[cfg(target_os = "linux")]
impl GroTxPool {
    fn new() -> Self {
        Self {
            bufs: Vec::new(),
            active: 0,
        }
    }

    fn push_datagram(&mut self, datagram: &[u8]) {
        let hdr_len = quictun_tun::VIRTIO_NET_HDR_LEN;
        let total = hdr_len + datagram.len();
        if self.active < self.bufs.len() {
            let buf = &mut self.bufs[self.active];
            buf.resize(total, 0);
            buf[..hdr_len].fill(0);
            buf[hdr_len..].copy_from_slice(datagram);
        } else {
            let mut buf = vec![0u8; total];
            buf[hdr_len..].copy_from_slice(datagram);
            self.bufs.push(buf);
        }
        self.active += 1;
    }

    fn as_mut_slice(&mut self) -> &mut [Vec<u8>] {
        &mut self.bufs[..self.active]
    }

    fn iter(&self) -> impl Iterator<Item = &Vec<u8>> {
        self.bufs[..self.active].iter()
    }

    fn is_empty(&self) -> bool {
        self.active == 0
    }

    fn reset(&mut self) {
        self.active = 0;
    }
}

// ── Main I/O loop ────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn container_io_loop(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    sig_read_fd: i32,
    poll: &mut Poll,
    events: &mut Events,
    multi_state: &mut MultiQuicState,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    ip_to_cid: &mut FxHashMap<Ipv4Addr, u64>,
    had_connection: &mut bool,
    config: &NetConfig,
    is_connector: bool,
    job_tx: &Sender<Box<Container>>,
    done_rx: &Receiver<Box<Container>>,
    response_buf: &mut Vec<u8>,
    encrypt_buf: &mut [u8],
    tun_write_pending: &mut std::collections::VecDeque<Vec<u8>>,
    #[cfg(target_os = "linux")] recv_bufs: &mut [Vec<u8>],
    #[cfg(target_os = "linux")] recv_lens: &mut [usize],
    #[cfg(target_os = "linux")] recv_addrs: &mut [SocketAddr],
    #[cfg(target_os = "linux")] recv_work: &mut quictun_core::batch_io::RecvMmsgWork,
    #[cfg(not(target_os = "linux"))] recv_buf: &mut [u8],
    #[cfg(target_os = "linux")] offload: bool,
    #[cfg(target_os = "linux")] gro_table: &mut Option<quictun_tun::GROTable>,
    #[cfg(target_os = "linux")] gro_tx_pool: &mut GroTxPool,
    #[cfg(target_os = "linux")] tun_original_buf: &mut [u8],
    #[cfg(target_os = "linux")] tun_split_bufs: &mut [Vec<u8>],
    #[cfg(target_os = "linux")] tun_split_sizes: &mut [usize],
    next_ack_deadline: &mut Instant,
    ack_timer_interval: Duration,
    in_flight: &mut usize,
) -> Result<RunResult> {
    loop {
        // Compute timeout.
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

        // Busy-poll when containers are in flight.
        if *in_flight > 0 {
            timeout = Duration::ZERO;
        }

        poll.poll(events, Some(timeout))?;

        let mut signal_received = false;
        let mut udp_readable = false;
        let mut tun_readable = false;

        for event in events.iter() {
            match event.token() {
                TOKEN_SIGNAL => signal_received = true,
                TOKEN_UDP => udp_readable = true,
                TOKEN_TUN => tun_readable = true,
                _ => {}
            }
        }

        if signal_received {
            drain_signal_pipe(sig_read_fd);
            info!("received signal, shutting down container engine");
            for entry in connections.values() {
                let mut close_buf = vec![0u8; MAX_PACKET];
                if let Ok(result) = entry.shared.tx.encrypt_datagram(&[], &mut close_buf) {
                    let _ = udp.send_to(&close_buf[..result.len], entry.remote_addr);
                }
            }
            return Ok(RunResult::Shutdown);
        }

        // ── Drain completed containers ───────────────────────────────
        drain_completions(
            udp, tun, connections, done_rx, tun_write_pending, in_flight,
            #[cfg(target_os = "linux")] offload,
            #[cfg(target_os = "linux")] gro_table,
            #[cfg(target_os = "linux")] gro_tx_pool,
        )?;

        // ── Drain buffered TUN writes ────────────────────────────────
        drain_tun_write_buf(tun, tun_write_pending);

        // ── UDP RX → decrypt containers ──────────────────────────────
        if udp_readable {
            #[cfg(target_os = "linux")]
            {
                udp_rx_linux(
                    udp, connections, config.cid_len, multi_state,
                    recv_bufs, recv_lens, recv_addrs, recv_work,
                    response_buf, job_tx, in_flight,
                )?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                udp_rx(
                    udp, connections, config.cid_len, multi_state,
                    recv_buf, response_buf, job_tx, in_flight,
                )?;
            }
        }

        // ── Drain completions again ──────────────────────────────────
        drain_completions(
            udp, tun, connections, done_rx, tun_write_pending, in_flight,
            #[cfg(target_os = "linux")] offload,
            #[cfg(target_os = "linux")] gro_table,
            #[cfg(target_os = "linux")] gro_tx_pool,
        )?;
        drain_tun_write_buf(tun, tun_write_pending);

        // ── TUN RX → encrypt containers ──────────────────────────────
        if tun_readable {
            #[cfg(target_os = "linux")]
            {
                if config.offload {
                    tun_rx_offload(
                        tun, connections, ip_to_cid, job_tx, in_flight,
                        tun_original_buf, tun_split_bufs, tun_split_sizes,
                    )?;
                } else {
                    tun_rx(tun, connections, ip_to_cid, job_tx, in_flight)?;
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                tun_rx(tun, connections, ip_to_cid, job_tx, in_flight)?;
            }
        }

        // ── Drain completions once more ──────────────────────────────
        drain_completions(
            udp, tun, connections, done_rx, tun_write_pending, in_flight,
            #[cfg(target_os = "linux")] offload,
            #[cfg(target_os = "linux")] gro_table,
            #[cfg(target_os = "linux")] gro_tx_pool,
        )?;

        // ── Timeouts + keepalives ────────────────────────────────────
        handle_timeouts(udp, connections, ip_to_cid, multi_state, config.idle_timeout, encrypt_buf)?;

        // ── ACK timer ────────────────────────────────────────────────
        if Instant::now() >= *next_ack_deadline {
            send_acks(udp, connections, encrypt_buf);
            *next_ack_deadline = Instant::now() + ack_timer_interval;
        }

        // ── Drive handshakes ─────────────────────────────────────────
        drive_handshakes(udp, multi_state, connections, ip_to_cid, &config.peers)?;

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
    }
}

// ── Drain completions ────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn drain_completions(
    udp: &std::net::UdpSocket,
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    done_rx: &Receiver<Box<Container>>,
    tun_write_pending: &mut std::collections::VecDeque<Vec<u8>>,
    in_flight: &mut usize,
    #[cfg(target_os = "linux")] offload: bool,
    #[cfg(target_os = "linux")] gro_table: &mut Option<quictun_tun::GROTable>,
    #[cfg(target_os = "linux")] gro_tx_pool: &mut GroTxPool,
) -> Result<()> {
    while let Ok(container) = done_rx.try_recv() {
        *in_flight = in_flight.saturating_sub(1);
        match &container.direction {
            Direction::Decrypt => {
                handle_decrypt_completion(
                    tun, connections, &container, tun_write_pending,
                    #[cfg(target_os = "linux")] offload,
                    #[cfg(target_os = "linux")] gro_table,
                    #[cfg(target_os = "linux")] gro_tx_pool,
                );
            }
            Direction::Encrypt { remote_addr, .. } => {
                handle_encrypt_completion(udp, connections, &container, *remote_addr)?;
            }
        }
    }
    Ok(())
}

fn handle_encrypt_completion(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    container: &Container,
    remote_addr: SocketAddr,
) -> Result<()> {
    if container.encrypt_count == 0 {
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let max_segs = quictun_core::batch_io::GSO_MAX_SEGMENTS;
        let mut pos = 0usize;
        let mut seg_start = 0usize;
        let mut seg_size = 0usize;
        let mut seg_count = 0usize;

        for i in 0..container.encrypt_count {
            let len = container.encrypt_lens[i];
            if seg_count == 0 {
                seg_size = len;
                seg_count = 1;
            } else if len == seg_size && seg_count < max_segs {
                seg_count += 1;
            } else {
                flush_gso_sync(
                    udp,
                    &container.encrypt_buf[seg_start..],
                    pos - seg_start,
                    seg_size,
                    remote_addr,
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
                &container.encrypt_buf[seg_start..],
                pos - seg_start,
                seg_size,
                remote_addr,
            )?;
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut pos = 0usize;
        for i in 0..container.encrypt_count {
            let len = container.encrypt_lens[i];
            let _ = udp.send_to(&container.encrypt_buf[pos..pos + len], remote_addr);
            pos += len;
        }
    }

    if let Some(entry) = connections.get_mut(&container.cid_key) {
        entry.last_tx = Instant::now();
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_decrypt_completion(
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    container: &Container,
    tun_write_pending: &mut std::collections::VecDeque<Vec<u8>>,
    #[cfg(target_os = "linux")] offload: bool,
    #[cfg(target_os = "linux")] gro_table: &mut Option<quictun_tun::GROTable>,
    #[cfg(target_os = "linux")] gro_tx_pool: &mut GroTxPool,
) {
    let entry = match connections.get_mut(&container.cid_key) {
        Some(e) => e,
        None => return,
    };

    let mut close_received = false;

    // With SharedConnectionState, replay check already happened in the worker.
    // We just need to process ACKs and write datagrams to TUN.
    for (i, result) in container.decrypt_results.iter().enumerate() {
        match result {
            DecryptOutcome::Ok {
                datagrams,
                ack,
                close_received: pkt_close,
                ..
            } => {
                entry.last_rx = Instant::now();

                // Process ACK.
                if let Some(ack_frame) = ack {
                    entry.shared.tx.update_largest_acked(ack_frame.largest_acked);
                }

                if *pkt_close {
                    close_received = true;
                }

                // Write datagrams to TUN.
                for range in datagrams {
                    let datagram = &container.packets[i][range.clone()];
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
                    {
                        if offload {
                            gro_tx_pool.push_datagram(datagram);
                        } else {
                            write_to_tun_simple(tun, datagram, tun_write_pending);
                        }
                    }
                    #[cfg(not(target_os = "linux"))]
                    {
                        write_to_tun_simple(tun, datagram, tun_write_pending);
                    }
                }
            }
            DecryptOutcome::Failed => {}
        }
    }

    // Flush GRO batch.
    #[cfg(target_os = "linux")]
    if offload && !gro_tx_pool.is_empty() {
        if let Some(gro) = gro_table {
            match tun.send_multiple(gro, gro_tx_pool.as_mut_slice(), quictun_tun::VIRTIO_NET_HDR_LEN) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    for buf in gro_tx_pool.iter() {
                        if tun_write_pending.len() < tun_write_pending.capacity().max(256) {
                            tun_write_pending.push_back(buf.clone());
                        }
                    }
                }
                Err(e) => {
                    debug!(error = %e, "TUN send_multiple failed");
                }
            }
            gro_tx_pool.reset();
        }
    }

    if close_received {
        let cid_key = container.cid_key;
        if let Some(removed) = connections.remove(&cid_key) {
            info!(
                tunnel_ip = %removed.tunnel_ip,
                cid = %hex::encode(cid_key.to_ne_bytes()),
                "peer sent CONNECTION_CLOSE, removed"
            );
        }
    }
}

fn write_to_tun_simple(
    tun: &tun_rs::SyncDevice,
    datagram: &[u8],
    pending: &mut std::collections::VecDeque<Vec<u8>>,
) {
    #[cfg(target_os = "linux")]
    let data = datagram.to_vec();
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

// ── UDP RX ───────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn udp_rx_linux(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    recv_bufs: &mut [Vec<u8>],
    recv_lens: &mut [usize],
    recv_addrs: &mut [SocketAddr],
    recv_work: &mut quictun_core::batch_io::RecvMmsgWork,
    response_buf: &mut Vec<u8>,
    job_tx: &Sender<Box<Container>>,
    in_flight: &mut usize,
) -> Result<()> {
    loop {
        let max_batch = recv_bufs.len();
        let n_msgs = match quictun_core::batch_io::recvmmsg_batch(
            udp, recv_bufs, recv_lens, recv_addrs, max_batch, recv_work,
        ) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(e) => return Err(e).context("recvmmsg failed"),
        };

        let mut decrypt_groups: FxHashMap<u64, Vec<Vec<u8>>> = FxHashMap::default();

        for i in 0..n_msgs {
            let n = recv_lens[i];
            if n == 0 {
                continue;
            }

            if recv_bufs[i][0] & 0x80 != 0 {
                let from = recv_addrs[i];
                let mut data = BytesMut::with_capacity(n);
                data.extend_from_slice(&recv_bufs[i][..n]);
                let now = Instant::now();
                let responses =
                    multi_state.handle_incoming(now, from, None, data, response_buf);
                send_responses(udp, &responses, from)?;
                continue;
            }

            if cid_len == 0 || n < 1 + cid_len {
                continue;
            }
            let cid_key = cid_to_u64(&recv_bufs[i][1..1 + cid_len]);

            if connections.contains_key(&cid_key) {
                decrypt_groups
                    .entry(cid_key)
                    .or_default()
                    .push(recv_bufs[i][..n].to_vec());
            }
        }

        for (cid_key, packets) in decrypt_groups {
            submit_decrypt_container(connections, cid_key, packets, job_tx, in_flight);
        }

        if n_msgs < max_batch {
            return Ok(());
        }
    }
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn udp_rx(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    cid_len: usize,
    multi_state: &mut MultiQuicState,
    recv_buf: &mut [u8],
    response_buf: &mut Vec<u8>,
    job_tx: &Sender<Box<Container>>,
    in_flight: &mut usize,
) -> Result<()> {
    let mut decrypt_groups: FxHashMap<u64, Vec<Vec<u8>>> = FxHashMap::default();

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
                        decrypt_groups
                            .entry(cid_key)
                            .or_default()
                            .push(recv_buf[..n].to_vec());
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(e) => return Err(e).context("UDP recv_from failed"),
        }
    }

    for (cid_key, packets) in decrypt_groups {
        submit_decrypt_container(connections, cid_key, packets, job_tx, in_flight);
    }

    Ok(())
}

fn submit_decrypt_container(
    connections: &FxHashMap<u64, ContainerConnEntry>,
    cid_key: u64,
    packets: Vec<Vec<u8>>,
    job_tx: &Sender<Box<Container>>,
    in_flight: &mut usize,
) {
    let entry = match connections.get(&cid_key) {
        Some(e) => e,
        None => return,
    };

    let container = Box::new(Container {
        packets,
        decrypt_results: Vec::new(),
        encrypt_buf: Vec::new(),
        encrypt_lens: Vec::new(),
        encrypt_count: 0,
        cid_key,
        direction: Direction::Decrypt,
        conn: Some(Arc::clone(&entry.shared)),
    });

    if job_tx.try_send(container).is_ok() {
        *in_flight += 1;
    } else {
        debug!("decrypt container dropped (channel full)");
    }
}

// ── TUN RX ───────────────────────────────────────────────────────────────

fn tun_rx(
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    ip_to_cid: &FxHashMap<Ipv4Addr, u64>,
    job_tx: &Sender<Box<Container>>,
    in_flight: &mut usize,
) -> Result<()> {
    let mut groups: FxHashMap<u64, Vec<Vec<u8>>> = FxHashMap::default();

    loop {
        let mut packet = [0u8; 1500];
        match tun.recv(&mut packet) {
            Ok(n) => {
                if n < 20 {
                    continue;
                }
                let dest_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
                let cid = if let Some(&cid) = ip_to_cid.get(&dest_ip) {
                    cid
                } else if connections.len() == 1 {
                    *connections.keys().next().expect("single connection")
                } else {
                    debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                    continue;
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
        submit_encrypt_container(connections, cid_key, payloads, job_tx, in_flight);
    }

    Ok(())
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn tun_rx_offload(
    tun: &tun_rs::SyncDevice,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    ip_to_cid: &FxHashMap<Ipv4Addr, u64>,
    job_tx: &Sender<Box<Container>>,
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

            let cid = if let Some(&cid) = ip_to_cid.get(&dest_ip) {
                cid
            } else if connections.len() == 1 {
                *connections.keys().next().expect("single connection")
            } else {
                debug!(dest = %dest_ip, "no route for dest IP, dropping TUN packet");
                continue;
            };
            if !connections.contains_key(&cid) {
                continue;
            }
            groups.entry(cid).or_default().push(packet.to_vec());
        }
    }

    for (cid_key, payloads) in groups {
        submit_encrypt_container(connections, cid_key, payloads, job_tx, in_flight);
    }

    Ok(())
}

fn submit_encrypt_container(
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    cid_key: u64,
    payloads: Vec<Vec<u8>>,
    job_tx: &Sender<Box<Container>>,
    in_flight: &mut usize,
) {
    let entry = match connections.get_mut(&cid_key) {
        Some(e) => e,
        None => return,
    };

    let tx = &entry.shared.tx;
    let count = payloads.len() as u64;

    // Assign PNs atomically.
    let pn_start = tx.next_pn_batch(count);

    // Snapshot key state.
    let key_guard = tx.load_packet_key();
    let packet_key = Arc::clone(&*key_guard);
    drop(key_guard);

    let gso_buf_size = payloads.len() * MAX_PACKET;

    let container = Box::new(Container {
        packets: payloads,
        decrypt_results: Vec::new(),
        encrypt_buf: vec![0u8; gso_buf_size],
        encrypt_lens: Vec::with_capacity(count as usize),
        encrypt_count: 0,
        cid_key,
        direction: Direction::Encrypt {
            pn_start,
            key_phase: tx.key_phase(),
            largest_acked: tx.largest_acked(),
            tag_len: tx.tag_len(),
            remote_cid: tx.remote_cid().clone(),
            packet_key,
            header_key: tx.header_key_arc(),
            remote_addr: entry.remote_addr,
        },
        conn: None,
    });

    if job_tx.try_send(container).is_ok() {
        *in_flight += 1;
    } else {
        debug!("encrypt container dropped (channel full)");
    }
}

// ── Timeouts ─────────────────────────────────────────────────────────────

fn handle_timeouts(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    ip_to_cid: &mut FxHashMap<Ipv4Addr, u64>,
    multi_state: &mut MultiQuicState,
    idle_timeout: Duration,
    encrypt_buf: &mut [u8],
) -> Result<()> {
    let expired: Vec<u64> = connections
        .iter()
        .filter(|(_, e)| e.last_rx.elapsed() >= idle_timeout)
        .map(|(&cid, _)| cid)
        .collect();

    for cid in expired {
        if let Some(entry) = connections.remove(&cid) {
            ip_to_cid.remove(&entry.tunnel_ip);
            info!(
                tunnel_ip = %entry.tunnel_ip,
                cid = %hex::encode(cid.to_ne_bytes()),
                "connection idle timeout, removed"
            );
        }
    }

    for entry in connections.values_mut() {
        if entry.last_tx.elapsed() >= entry.keepalive_interval {
            match entry.shared.tx.encrypt_datagram(&[], encrypt_buf) {
                Ok(result) => {
                    let _ = udp.send_to(&encrypt_buf[..result.len], entry.remote_addr);
                    entry.last_tx = Instant::now();
                }
                Err(e) => {
                    warn!(error = %e, "keepalive encrypt failed");
                }
            }
        }
    }

    let now = Instant::now();
    for hs in multi_state.handshakes.values_mut() {
        hs.connection.handle_timeout(now);
    }

    Ok(())
}

// ── ACK timer ────────────────────────────────────────────────────────────

fn send_acks(
    udp: &std::net::UdpSocket,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    encrypt_buf: &mut [u8],
) {
    for entry in connections.values() {
        if entry.shared.replay.needs_ack() {
            let ack_ranges = entry.shared.replay.generate_ack_ranges();
            let tx = &entry.shared.tx;
            let pn = tx.next_pn();
            let key_guard = tx.load_packet_key();
            match quictun_quic::encrypt_ack_packet(
                &ack_ranges,
                tx.remote_cid(),
                pn,
                tx.largest_acked(),
                tx.key_phase(),
                &***key_guard,
                tx.header_key(),
                tx.tag_len(),
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

fn drive_handshakes(
    udp: &std::net::UdpSocket,
    multi_state: &mut MultiQuicState,
    connections: &mut FxHashMap<u64, ContainerConnEntry>,
    ip_to_cid: &mut FxHashMap<Ipv4Addr, u64>,
    peers: &[PeerConfig],
) -> Result<()> {
    if multi_state.handshakes.is_empty() {
        return Ok(());
    }

    drain_transmits(udp, multi_state)?;
    let result = multi_state.poll_handshakes();
    drain_transmits(udp, multi_state)?;

    for ch in result.completed {
        let Some((hs, conn_state)) = multi_state.extract_connection(ch) else {
            continue;
        };

        let matched_peer = if peers.len() == 1 {
            &peers[0]
        } else {
            match peer::identify_peer(&hs.connection, peers) {
                Some(p) => p,
                None => {
                    warn!(remote = %hs.remote_addr, "could not identify peer, rejecting");
                    continue;
                }
            }
        };

        let tunnel_ip = matched_peer.tunnel_ip;
        let allowed_ips = matched_peer.allowed_ips.clone();
        let keepalive_interval = matched_peer.keepalive.unwrap_or(Duration::from_secs(25));
        let cid_bytes: Vec<u8> = hs.local_cid[..].to_vec();
        let cid_key = cid_to_u64(&cid_bytes);
        let now_inst = Instant::now();

        // Convert to SharedConnectionState for parallel decrypt.
        let shared = Arc::new(conn_state.into_shared());

        info!(
            remote = %hs.remote_addr,
            tunnel_ip = %tunnel_ip,
            cid = %hex::encode(&cid_bytes),
            "connection established (container pipeline)"
        );

        ip_to_cid.insert(tunnel_ip, cid_key);
        connections.insert(
            cid_key,
            ContainerConnEntry {
                shared,
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
