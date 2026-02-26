use std::net::{Ipv4Addr, SocketAddr};
use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::eal::Eal;
use crate::engine;
use crate::ffi;
use crate::mbuf;
use crate::net::{self, ArpTable, NetIdentity};
use crate::port;
use crate::reader;
use crate::shared::QuicState;

/// QUIC endpoint setup (connector or listener), same pattern as quictun-uring.
pub enum EndpointSetup {
    Connector {
        remote_addr: SocketAddr,
        client_config: quinn_proto::ClientConfig,
    },
    Listener {
        server_config: Arc<quinn_proto::ServerConfig>,
    },
}

/// DPDK-specific configuration from CLI flags.
pub struct DpdkConfig {
    /// EAL arguments (e.g., ["-l", "0", "-n", "4"]).
    pub eal_args: Vec<String>,
    /// DPDK port ID (default: 0).
    pub port_id: u16,
    /// IP address assigned to this DPDK port.
    pub local_ip: Ipv4Addr,
    /// Peer's IP address on the DPDK network.
    pub remote_ip: Ipv4Addr,
    /// Override local UDP port (otherwise use listen_port from config).
    pub local_port: Option<u16>,
    /// Static peer MAC address (skip ARP if provided).
    pub gateway_mac: Option<[u8; 6]>,
}

/// Run the DPDK data plane.
///
/// Initializes EAL, configures the port, resolves ARP, and runs the
/// engine polling loop.  Returns when the connection is lost or SIGINT.
pub fn run(
    tun_fd: RawFd,
    local_addr: SocketAddr,
    setup: EndpointSetup,
    dpdk_config: DpdkConfig,
) -> Result<()> {
    // ── 1. Initialize DPDK EAL ───────────────────────────────────

    let _eal = Eal::init(&dpdk_config.eal_args)?;

    // ── 2. Create mempool and configure port ─────────────────────

    let mempool =
        mbuf::create_mempool("quictun_dpdk", ffi::DEFAULT_NUM_MBUFS, ffi::MEMPOOL_CACHE_SIZE)?;

    let local_mac = port::configure_port(dpdk_config.port_id, mempool)?;

    // ── 3. Build network identity ────────────────────────────────

    // DPDK has no kernel to assign ephemeral ports, so we need a concrete port.
    // Use: CLI override > config listen_port > default 40000 (for connectors).
    let local_port = match dpdk_config.local_port {
        Some(p) => p,
        None if local_addr.port() != 0 => local_addr.port(),
        None => 40000, // Default ephemeral port for connector
    };
    let remote_port = match &setup {
        EndpointSetup::Connector { remote_addr, .. } => remote_addr.port(),
        EndpointSetup::Listener { .. } => 0, // learned from first packet
    };

    let mut identity = NetIdentity {
        local_mac,
        remote_mac: dpdk_config.gateway_mac,
        local_ip: dpdk_config.local_ip,
        remote_ip: dpdk_config.remote_ip,
        local_port,
        remote_port,
    };

    let mut arp_table = ArpTable::new();
    if let Some(mac) = dpdk_config.gateway_mac {
        arp_table.insert(dpdk_config.remote_ip, mac);
    }

    // ── 4. Build QUIC state ──────────────────────────────────────

    // For DPDK, the QUIC endpoint uses our DPDK IP:port, not the kernel socket.
    let _quic_local_addr = SocketAddr::new(dpdk_config.local_ip.into(), local_port);
    let quic_remote_addr = match &setup {
        EndpointSetup::Connector { remote_addr, .. } => *remote_addr,
        // Listener: unknown until first packet.
        EndpointSetup::Listener { .. } => SocketAddr::new(dpdk_config.remote_ip.into(), 0),
    };

    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });

    let server_config = match &setup {
        EndpointSetup::Listener { server_config } => Some(server_config.clone()),
        EndpointSetup::Connector { .. } => None,
    };
    let mut quic_state = QuicState::new(quic_remote_addr, server_config);

    // For connector: initiate QUIC connection.
    if let EndpointSetup::Connector {
        remote_addr,
        client_config,
    } = setup
    {
        let (ch, conn) = quic_state
            .endpoint
            .connect(Instant::now(), client_config, remote_addr, "quictun")
            .context("failed to initiate QUIC connection")?;
        quic_state.ch = Some(ch);
        quic_state.connection = Some(conn);
        tracing::info!(remote = %remote_addr, "QUIC connection initiated");
    }

    tracing::info!(
        local_mac = %format_mac(&local_mac),
        local_ip = %dpdk_config.local_ip,
        local_port,
        remote_ip = %dpdk_config.remote_ip,
        remote_port,
        "DPDK network identity"
    );

    // ── 5. ARP resolution (connector only) ─────────────────────
    //
    // The connector needs the peer's MAC to send the initial QUIC handshake.
    // The listener learns the peer MAC from the first incoming packet.

    if is_connector && identity.remote_mac.is_none() {
        tracing::info!(target_ip = %dpdk_config.remote_ip, "resolving peer MAC via ARP");
        resolve_arp(
            dpdk_config.port_id,
            mempool,
            &identity,
            &mut arp_table,
            dpdk_config.remote_ip,
        )?;
        identity.remote_mac = arp_table.lookup(dpdk_config.remote_ip);
        if let Some(mac) = identity.remote_mac {
            tracing::info!(mac = %format_mac(&mac), "ARP resolved peer MAC");
        } else {
            bail!("ARP resolution failed: no reply from {}", dpdk_config.remote_ip);
        }
    }

    // ── 6. Spawn TUN reader thread ───────────────────────────────

    let shutdown = Arc::new(AtomicBool::new(false));
    let (tun_tx, tun_rx) = crossbeam_channel::bounded(512);

    let reader_shutdown = shutdown.clone();
    let reader_handle = std::thread::Builder::new()
        .name("dpdk-reader".into())
        .spawn(move || reader::run(tun_fd, tun_tx, reader_shutdown))
        .context("failed to spawn reader thread")?;

    // ── 7. Set up SIGINT handler ─────────────────────────────────

    let sig_shutdown = shutdown.clone();
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as libc::sighandler_t);
    }
    // Store the shutdown flag for the signal handler.
    SHUTDOWN_FLAG.store(
        Arc::into_raw(sig_shutdown) as usize,
        Ordering::Release,
    );

    // ── 8. Run engine ────────────────────────────────────────────

    let result = engine::run(
        dpdk_config.port_id,
        mempool,
        &mut quic_state,
        &mut identity,
        &mut arp_table,
        tun_fd,
        tun_rx,
        shutdown.clone(),
    );

    // ── 9. Cleanup ───────────────────────────────────────────────

    shutdown.store(true, Ordering::Release);
    let _ = reader_handle.join();
    port::close_port(dpdk_config.port_id);

    result
}

// ── ARP resolution ──────────────────────────────────────────────────

/// Send ARP requests and wait for a reply, polling with timeout.
fn resolve_arp(
    port_id: u16,
    mempool: *mut ffi::rte_mempool,
    identity: &NetIdentity,
    arp_table: &mut ArpTable,
    target_ip: Ipv4Addr,
) -> Result<()> {
    let request = net::build_arp_request(identity.local_mac, identity.local_ip, target_ip);

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut attempt = 0;

    while Instant::now() < deadline {
        // Send ARP request.
        let mut mbuf = crate::mbuf::Mbuf::alloc(mempool)?;
        mbuf.write_packet(&request)?;
        let raw = mbuf.into_raw();
        let mut tx = [raw];
        let sent = port::tx_burst(port_id, 0, &mut tx, 1);
        if sent == 0 {
            unsafe { ffi::shim_rte_pktmbuf_free(raw) };
        }
        attempt += 1;

        // Poll for ARP reply (100ms per attempt).
        let poll_until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < poll_until {
            let mut rx_mbufs: [*mut ffi::rte_mbuf; 32] = [std::ptr::null_mut(); 32];
            let nb_rx = port::rx_burst(port_id, 0, &mut rx_mbufs, 32);
            for i in 0..nb_rx as usize {
                let mbuf = unsafe { crate::mbuf::Mbuf::from_raw(rx_mbufs[i]) };
                if let Some(ParsedPacket::Arp(arp)) = net::parse_packet(mbuf.data()) {
                    arp_table.learn(arp.sender_ip, arp.sender_mac);
                    if arp.sender_ip == target_ip {
                        tracing::info!(
                            attempt,
                            mac = %format_mac(&arp.sender_mac),
                            "ARP reply received"
                        );
                        return Ok(());
                    }
                }
            }
        }
    }

    bail!("ARP resolution timed out after {attempt} attempts");
}

use crate::net::ParsedPacket;

// ── Signal handling ─────────────────────────────────────────────────

/// Atomic pointer to the shutdown flag (set by SIGINT handler).
static SHUTDOWN_FLAG: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

extern "C" fn sigint_handler(_sig: libc::c_int) {
    let ptr = SHUTDOWN_FLAG.load(Ordering::Acquire);
    if ptr != 0 {
        // Safety: we stored an Arc<AtomicBool> raw pointer in `run()`.
        // We don't free it here (intentional leak to keep signal handler safe).
        let flag = unsafe { &*(ptr as *const AtomicBool) };
        flag.store(true, Ordering::Release);
    }
}

fn format_mac(mac: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}
