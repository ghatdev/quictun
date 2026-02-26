use std::ffi::CString;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};

use crate::eal::Eal;
use crate::engine::{self, InnerEthHeader, InnerPort};
use crate::ffi;
use crate::mbuf;
use crate::net::{self, ArpTable, NetIdentity};
use crate::port;
use crate::shared::QuicState;
use crate::veth::VethPair;

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
    /// Inner interface mode: "tap" (default) or "xdp".
    pub mode: String,
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
    /// Tunnel IP for the inner interface (e.g., 10.0.0.1).
    pub tunnel_ip: Ipv4Addr,
    /// Tunnel subnet prefix length (e.g., 24).
    pub tunnel_prefix: u8,
    /// Tunnel MTU from config.
    pub tunnel_mtu: u16,
    /// Tunnel interface name (e.g., "quictun0").
    pub tunnel_iface: String,
}

/// Run the DPDK data plane.
///
/// Initializes EAL, configures the port, resolves ARP, and runs the
/// engine polling loop.  Returns when the connection is lost or SIGINT.
///
/// - mode "tap" → TAP PMD (default, DPDK built-in TAP virtual device)
/// - mode "xdp" → AF_XDP (veth pair + DPDK AF_XDP PMD)
pub fn run(
    local_addr: SocketAddr,
    setup: EndpointSetup,
    dpdk_config: DpdkConfig,
) -> Result<()> {
    // ── 1. Initialize DPDK EAL ───────────────────────────────────

    // For TAP mode, inject the TAP vdev into EAL args before init.
    let mut eal_args = dpdk_config.eal_args.clone();
    if dpdk_config.mode == "tap" {
        eal_args.push(format!(
            "--vdev=net_tap0,iface={}",
            dpdk_config.tunnel_iface
        ));
    }

    let _eal = Eal::init(&eal_args)?;

    // ── 2. Create mempool and configure outer port ────────────────

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

    // ── 6. Build inner interface ─────────────────────────────────

    let shutdown = Arc::new(AtomicBool::new(false));

    // Holds veth pair ownership for AF_XDP mode (dropped on cleanup).
    let mut _veth_pair: Option<VethPair> = None;

    let inner = if dpdk_config.mode == "tap" {
        // TAP PMD mode: DPDK created the TAP device via --vdev in EAL args.
        let total_ports = unsafe { ffi::rte_eth_dev_count_avail() };
        if total_ports < 2 {
            bail!("TAP vdev not found: only {total_ports} port(s) available (expected ≥ 2)");
        }
        let inner_port_id = total_ports as u16 - 1;

        let tap_mac = port::configure_port(inner_port_id, mempool)?;

        // Fabricate a locally-administered peer MAC for ARP replies.
        // The kernel uses tap_mac for the TAP interface; the engine
        // presents itself as peer_mac when replying to ARP.
        let peer_mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

        tracing::info!(
            inner_port = inner_port_id,
            tap_mac = %format_mac(&tap_mac),
            peer_mac = %format_mac(&peer_mac),
            iface = %dpdk_config.tunnel_iface,
            "TAP PMD inner port configured"
        );

        configure_tap_interface(
            &dpdk_config.tunnel_iface,
            dpdk_config.tunnel_ip,
            dpdk_config.tunnel_prefix,
            dpdk_config.tunnel_mtu,
        )?;

        let eth_hdr = InnerEthHeader::new(peer_mac, tap_mac);
        tracing::info!("inner interface: TAP PMD");

        InnerPort { port_id: inner_port_id, eth_hdr }
    } else {
        // AF_XDP mode: create veth pair, init DPDK AF_XDP PMD.
        let veth = VethPair::create(
            &dpdk_config.tunnel_iface,
            dpdk_config.tunnel_ip,
            dpdk_config.tunnel_prefix,
            dpdk_config.tunnel_mtu,
        )?;

        let vdev_name = CString::new("net_af_xdp0")
            .expect("CString::new failed");
        let vdev_args = CString::new(format!("iface={}", veth.xdp_iface))
            .expect("CString::new failed");

        let ret = unsafe {
            ffi::rte_vdev_init(vdev_name.as_ptr(), vdev_args.as_ptr())
        };
        if ret != 0 {
            bail!("rte_vdev_init(net_af_xdp0, iface={}) failed: error {ret}", veth.xdp_iface);
        }

        let total_ports = unsafe { ffi::rte_eth_dev_count_avail() };
        if total_ports < 2 {
            bail!("AF_XDP vdev created but only {total_ports} port(s) available (expected ≥ 2)");
        }
        let inner_port_id = total_ports as u16 - 1;

        let inner_mac = port::configure_port(inner_port_id, mempool)?;

        tracing::info!(
            inner_port = inner_port_id,
            inner_mac = %format_mac(&inner_mac),
            xdp_iface = %veth.xdp_iface,
            "AF_XDP inner port configured"
        );

        let eth_hdr = InnerEthHeader::new(inner_mac, veth.app_mac);
        _veth_pair = Some(veth);
        tracing::info!("inner interface: AF_XDP (veth pair)");

        InnerPort { port_id: inner_port_id, eth_hdr }
    };

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
        inner,
        shutdown.clone(),
    );

    // ── 9. Cleanup ───────────────────────────────────────────────

    shutdown.store(true, Ordering::Release);
    port::close_port(dpdk_config.port_id);
    // _veth_pair dropped here → deletes veth pair (AF_XDP mode only).

    result
}

// ── TAP interface configuration ─────────────────────────────────────

/// Assign IP address, set MTU, and bring up a TAP interface created by DPDK.
fn configure_tap_interface(
    iface: &str,
    ip: Ipv4Addr,
    prefix: u8,
    mtu: u16,
) -> Result<()> {
    let mtu_str = mtu.to_string();
    let addr = format!("{ip}/{prefix}");

    run_cmd("ip", &["link", "set", iface, "mtu", &mtu_str])
        .context("failed to set TAP MTU")?;
    run_cmd("ip", &["addr", "add", &addr, "dev", iface])
        .context("failed to assign IP to TAP")?;
    run_cmd("ip", &["link", "set", iface, "up"])
        .context("failed to bring TAP up")?;

    tracing::info!(
        iface,
        ip = %ip,
        prefix,
        mtu,
        "TAP interface configured"
    );
    Ok(())
}

fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute: {program} {}", args.join(" ")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "{program} {} failed: {}",
            args.join(" "),
            stderr.trim()
        );
    }
    Ok(())
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
