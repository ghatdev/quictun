use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use crate::dispatch::{DpdkDispatchTable, WorkerRings};
use crate::eal::Eal;
use crate::engine::{self, InnerEthHeader, InnerPort};
use crate::ffi;
use crate::mbuf;
use crate::net::{self, ArpTable, ChecksumMode, NetIdentity};
use crate::port;
use crate::shared::MultiQuicState;
use crate::veth::VethPair;
use quictun_core::peer::PeerConfig;

/// QUIC endpoint setup (connector or listener).
pub enum EndpointSetup {
    Connector {
        remote_addr: SocketAddr,
        client_config: quinn_proto::ClientConfig,
    },
    Listener {
        server_config: Arc<quinn_proto::ServerConfig>,
    },
}

/// Wrapper around `*mut T` that implements `Send`.
///
/// SAFETY: The caller must ensure that the pointee is safe to access from another
/// thread. DPDK mempools (`rte_mempool`) are thread-safe by design.
#[derive(Clone, Copy)]
struct SendPtr<T>(*mut T);
unsafe impl<T> Send for SendPtr<T> {}

impl<T> SendPtr<T> {
    fn as_ptr(self) -> *mut T {
        self.0
    }
}

/// DPDK-specific configuration from CLI flags.
pub struct DpdkConfig {
    /// Inner interface mode: "tap" (default), "xdp", or "virtio".
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
    /// Enable adaptive polling (exponential backoff on empty polls).
    /// Default: true. Disable with --no-adaptive-poll for benchmarking.
    pub adaptive_poll: bool,
    /// Number of engine cores (1 = single-threaded, N = multi-queue RSS).
    pub n_cores: usize,
    /// Skip UDP checksum entirely (write 0x0000). Valid for IPv4, useful for benchmarking.
    pub no_udp_checksum: bool,
    /// Peer configurations for peer identification (listener with >1 peer).
    pub peers: Vec<PeerConfig>,
}

/// Run the DPDK data plane.
///
/// Initializes EAL, configures the port, resolves ARP, and runs the
/// engine polling loop.  Returns when the connection is lost or SIGINT.
///
/// - mode "tap" → TAP PMD (default, DPDK built-in TAP virtual device)
/// - mode "xdp" → AF_XDP (veth pair + DPDK AF_XDP PMD)
/// - mode "virtio" → virtio-user + vhost-net (kernel TAP with offload support)
pub fn run(local_addr: SocketAddr, setup: EndpointSetup, dpdk_config: DpdkConfig) -> Result<()> {
    // ── 1. Initialize DPDK EAL ───────────────────────────────────

    // Inject inner vdev(s) into EAL args before init.
    // Multi-core: N vdevs (quictun0, quictun1, ...).
    let n_cores = dpdk_config.n_cores.max(1);
    let mut eal_args = dpdk_config.eal_args.clone();

    // AF_XDP: create veth pair BEFORE EAL init so the interface exists
    // when the PMD binds to it.
    let mut _veth_pair: Option<VethPair> = None;
    if dpdk_config.mode == "xdp" {
        if n_cores > 1 {
            bail!("multi-core (--dpdk-cores > 1) is only supported with TAP PMD mode (--dpdk tap)");
        }
        let veth = VethPair::create(
            &dpdk_config.tunnel_iface,
            dpdk_config.tunnel_ip,
            dpdk_config.tunnel_prefix,
            dpdk_config.tunnel_mtu,
        )?;
        eal_args.push(format!(
            "--vdev=net_af_xdp0,iface={},start_queue=0,queue_count=1,busy_budget=64",
            veth.xdp_iface
        ));
        _veth_pair = Some(veth);
    }

    if dpdk_config.mode == "tap" {
        for i in 0..n_cores {
            let iface = if n_cores == 1 {
                dpdk_config.tunnel_iface.clone()
            } else {
                format!("{}{i}", dpdk_config.tunnel_iface)
            };
            eal_args.push(format!("--vdev=net_tap{i},iface={iface}"));
        }
    } else if dpdk_config.mode == "virtio" {
        if n_cores > 1 {
            bail!("multi-core (--dpdk-cores > 1) is not yet supported with virtio-user mode");
        }
        let iface = dpdk_config.tunnel_iface.clone();
        // Packed virtqueue (virtio 1.1) + in-order + non-mergeable + vectorized:
        // enables the AVX-512 packed vectorized RX/TX path in the virtio PMD.
        // ~10-20% faster than default split mergeable path.
        eal_args.push(format!(
            "--vdev=net_virtio_user0,path=/dev/vhost-net,iface={iface},\
             queues=1,queue_size=1024,\
             packed_vq=1,in_order=1,mrg_rxbuf=0,vectorized=1"
        ));
        // Enable AVX-512 SIMD for virtio descriptor batch processing.
        eal_args.push("--force-max-simd-bitwidth=512".to_string());
    }

    // Enable AVX-512 SIMD for AF_XDP ring operations too.
    if dpdk_config.mode == "xdp" {
        eal_args.push("--force-max-simd-bitwidth=512".to_string());
    }

    let _eal = Eal::init(&eal_args)?;

    // ── 2. Create mempool and configure outer port ────────────────

    let mempool = mbuf::create_mempool(
        "quictun_dpdk",
        ffi::DEFAULT_NUM_MBUFS,
        ffi::MEMPOOL_CACHE_SIZE,
    )?;

    let (local_mac, hw_udp_cksum, hw_ip_cksum) = if n_cores > 1 {
        port::configure_port_multiqueue(dpdk_config.port_id, n_cores as u16, mempool)?
    } else {
        port::configure_port(dpdk_config.port_id, mempool)?
    };

    // Determine checksum mode: CLI flag > HW offload > software.
    let checksum_mode = if dpdk_config.no_udp_checksum {
        tracing::info!("UDP checksum disabled (--no-udp-checksum)");
        ChecksumMode::None
    } else if hw_udp_cksum && hw_ip_cksum {
        tracing::info!("using hardware TX checksum offload (UDP + IP)");
        ChecksumMode::HardwareFull
    } else if hw_udp_cksum {
        tracing::info!("using hardware TX UDP checksum offload (IP in software)");
        ChecksumMode::HardwareUdpOnly
    } else {
        tracing::info!("using optimized software UDP checksum");
        ChecksumMode::Software
    };

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

    let is_connector = matches!(&setup, EndpointSetup::Connector { .. });

    // Build MultiQuicState for both listener and connector.
    let mut multi_state = match &setup {
        EndpointSetup::Listener { server_config } => MultiQuicState::new(server_config.clone()),
        EndpointSetup::Connector { .. } => MultiQuicState::new_connector(),
    };

    // For connector: initiate QUIC connection.
    if let EndpointSetup::Connector {
        remote_addr,
        client_config,
    } = setup
    {
        multi_state
            .connect(client_config, remote_addr)
            .context("failed to initiate QUIC connection")?;
    }

    // Keep server_config clone for multi-core dispatcher path.
    let server_config_clone = multi_state.server_config.clone();

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
            bail!(
                "ARP resolution failed: no reply from {}",
                dpdk_config.remote_ip
            );
        }
    }

    // ── 6. Build inner interface ─────────────────────────────────

    let shutdown = Arc::new(AtomicBool::new(false));

    let mut inner_ports: Vec<InnerPort> = Vec::with_capacity(n_cores);

    // All modes now use --vdev in EAL args. Inner port(s) are the last N ports.
    // SAFETY: EAL is initialized; returns the count of available DPDK ports.
    let total_ports = unsafe { ffi::rte_eth_dev_count_avail() } as u16;
    let expected = 1 + n_cores as u16; // outer + N inner ports
    if total_ports < expected {
        bail!(
            "inner vdev not found: only {total_ports} port(s) available (expected ≥ {expected})"
        );
    }

    if dpdk_config.mode == "xdp" {
        // AF_XDP mode: veth pair already created, PMD bound via --vdev.
        let veth = _veth_pair.as_ref().expect("veth pair must exist for xdp mode");
        let inner_port_id = total_ports - 1;
        let (inner_mac, _inner_hw_udp, _inner_hw_ip) =
            port::configure_port(inner_port_id, mempool)?;

        tracing::info!(
            inner_port = inner_port_id,
            inner_mac = %format_mac(&inner_mac),
            xdp_iface = %veth.xdp_iface,
            "AF_XDP inner port configured"
        );

        let eth_hdr = InnerEthHeader::new(inner_mac, veth.app_mac);
        inner_ports.push(InnerPort {
            port_id: inner_port_id,
            eth_hdr,
        });
        tracing::info!("inner interface: AF_XDP (veth pair)");
    } else {
        // TAP PMD or virtio-user mode: DPDK created device(s) via --vdev in EAL args.
        // Both create kernel-visible TAP interfaces that need IP configuration.

        // Fabricate a locally-administered peer MAC for ARP replies.
        let peer_mac: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

        for i in 0..n_cores {
            let inner_port_id = (total_ports - n_cores as u16) + i as u16;
            let (inner_mac, _inner_hw_udp, _inner_hw_ip) =
                port::configure_port(inner_port_id, mempool)?;

            let iface = if n_cores == 1 {
                dpdk_config.tunnel_iface.clone()
            } else {
                format!("{}{i}", dpdk_config.tunnel_iface)
            };

            tracing::info!(
                inner_port = inner_port_id,
                inner_mac = %format_mac(&inner_mac),
                hw_udp = _inner_hw_udp,
                hw_ip = _inner_hw_ip,
                iface = %iface,
                mode = %dpdk_config.mode,
                "inner port configured"
            );

            // Each inner port gets its own tunnel IP for multi-core.
            // Core 0 gets the base IP; additional cores get base+i.
            let tunnel_ip = if n_cores == 1 {
                dpdk_config.tunnel_ip
            } else {
                let octets = dpdk_config.tunnel_ip.octets();
                Ipv4Addr::new(
                    octets[0],
                    octets[1],
                    octets[2],
                    octets[3].wrapping_add(i as u8),
                )
            };

            configure_tap_interface(
                &iface,
                tunnel_ip,
                dpdk_config.tunnel_prefix,
                dpdk_config.tunnel_mtu,
                dpdk_config.mode == "virtio",
            )?;

            let eth_hdr = InnerEthHeader::new(peer_mac, inner_mac);
            inner_ports.push(InnerPort {
                port_id: inner_port_id,
                eth_hdr,
            });
        }

        tracing::info!(n_cores, mode = %dpdk_config.mode, "inner interface ready");
    }

    // ── 7. Set up SIGINT handler ─────────────────────────────────

    let sig_shutdown = shutdown.clone();
    // SAFETY: sigint_handler is an extern "C" fn with correct signature for signal().
    // We intentionally leak the Arc via into_raw to make it accessible from the
    // async-signal-safe handler. The handler only performs an atomic store, which is
    // async-signal-safe. The leaked Arc is never freed (acceptable: one-time setup).
    unsafe {
        libc::signal(libc::SIGINT, sigint_handler as libc::sighandler_t);
    }
    SHUTDOWN_FLAG.store(Arc::into_raw(sig_shutdown) as usize, Ordering::Release);

    // ── 7b. Pin vhost kernel threads to non-DPDK cores ────────────
    //
    // vhost-net spawns kernel threads (vhost-<pid>) that service the
    // virtio rings. Pinning them away from the DPDK polling core(s)
    // reduces cache thrashing.
    if dpdk_config.mode == "virtio" {
        pin_vhost_threads(n_cores);
    }

    // ── 8. Run engine(s) ──────────────────────────────────────────

    let result = if n_cores == 1 {
        // Single-core: run directly on this thread.
        // Handles 1..N connections via connection table (no multi-client flag needed).
        let inner = inner_ports
            .into_iter()
            .next()
            .expect("exactly 1 inner port");

        engine::run(
            dpdk_config.port_id,
            0, // queue_id
            mempool,
            &mut multi_state,
            &mut identity,
            &mut arp_table,
            inner,
            shutdown.clone(),
            dpdk_config.adaptive_poll,
            checksum_mode,
            &dpdk_config.peers,
        )
    } else {
        // Multi-core: dispatcher + worker architecture.
        let n_workers = n_cores - 1; // core 0 = dispatcher

        // Configure outer port: 1 RX queue, n_cores TX queues.
        // Close and reconfigure for dispatcher mode.
        port::close_port(dpdk_config.port_id);
        let (new_mac, hw_udp, hw_ip) =
            port::configure_port_dispatcher(dpdk_config.port_id, n_cores as u16, mempool)?;
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

        // Build multi-client QUIC state (listener only for multi-core).
        let multi_server_config = server_config_clone
            .ok_or_else(|| anyhow::anyhow!("multi-core DPDK requires listener mode"))?;
        let mut multi_state = MultiQuicState::new(multi_server_config);

        // Create per-worker ring bundles.
        let mut worker_rings: Vec<WorkerRings> = Vec::with_capacity(n_workers);
        for i in 0..n_workers {
            worker_rings.push(WorkerRings::new(i)?);
        }

        // Build dispatch table.
        let mut dispatch_table = DpdkDispatchTable::new(n_workers);

        // Single inner port on core 0.
        let inner = inner_ports
            .into_iter()
            .next()
            .expect("at least 1 inner port");

        let adaptive_poll = dpdk_config.adaptive_poll;
        let outer_port_id = dpdk_config.port_id;

        // Spawn worker threads (pinned to cores 1..N).
        std::thread::scope(|s| {
            let mut handles = Vec::with_capacity(n_workers);

            for (idx, rings) in worker_rings.iter().enumerate() {
                let shutdown = shutdown.clone();
                let worker_identity = identity.clone();
                let inner_eth_hdr = &inner.eth_hdr;
                let mempool = SendPtr(mempool);

                handles.push(s.spawn(move || -> Result<()> {
                    let mempool = mempool.as_ptr();
                    let core_idx = idx + 1; // core 0 is dispatcher
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
                            tracing::info!(core = core_idx, "pinned worker thread to CPU");
                        } else {
                            tracing::warn!(core = core_idx, "failed to pin worker thread to CPU");
                        }
                    }

                    engine::run_worker(
                        outer_port_id,
                        tx_queue,
                        mempool,
                        rings,
                        inner_eth_hdr,
                        &worker_identity,
                        &shutdown,
                        adaptive_poll,
                        checksum_mode,
                        core_idx,
                    )
                }));
            }

            // Run dispatcher on core 0 (this thread).
            let disp_result = engine::run_dispatcher(
                outer_port_id,
                mempool,
                &mut multi_state,
                &mut dispatch_table,
                &worker_rings,
                &mut identity,
                &mut arp_table,
                &inner,
                &dpdk_config.peers,
                &shutdown,
                adaptive_poll,
                checksum_mode,
            );

            // Signal shutdown and wait for workers.
            shutdown.store(true, Ordering::Release);
            let mut result = disp_result;
            for handle in handles {
                if let Err(e) = handle.join().expect("worker thread panicked") {
                    if result.is_ok() {
                        result = Err(e);
                    }
                }
            }
            result
        })
    };

    // ── 9. Cleanup ───────────────────────────────────────────────

    shutdown.store(true, Ordering::Release);
    port::close_port(dpdk_config.port_id);
    // _veth_pair dropped here → deletes veth pair (AF_XDP mode only).

    result
}

// ── TAP interface configuration ─────────────────────────────────────

/// Assign IP address, set MTU, and bring up a TAP interface created by DPDK.
///
/// When `disable_offload` is true (virtio-user mode), also disable kernel
/// checksum/segmentation offload on the TAP device. This eliminates redundant
/// `csum_partial` overhead in the vhost-net kernel threads since DPDK handles
/// checksums directly.
fn configure_tap_interface(
    iface: &str,
    ip: Ipv4Addr,
    prefix: u8,
    mtu: u16,
    disable_offload: bool,
) -> Result<()> {
    let mtu_str = mtu.to_string();
    let addr = format!("{ip}/{prefix}");

    run_cmd("ip", &["link", "set", iface, "mtu", &mtu_str]).context("failed to set TAP MTU")?;
    run_cmd("ip", &["addr", "add", &addr, "dev", iface]).context("failed to assign IP to TAP")?;
    run_cmd("ip", &["link", "set", iface, "up"]).context("failed to bring TAP up")?;

    if disable_offload {
        // Disable kernel checksum/segmentation offload on the TAP device.
        // DPDK handles checksums, so kernel computation is redundant overhead.
        if let Err(e) = run_cmd(
            "ethtool",
            &[
                "-K", iface, "tx", "off", "rx", "off", "sg", "off", "tso", "off", "gso", "off",
                "gro", "off",
            ],
        ) {
            tracing::warn!(%e, iface, "failed to disable TAP offload (non-fatal)");
        } else {
            tracing::info!(iface, "disabled kernel checksum/offload on TAP");
        }
    }

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
        anyhow::bail!("{program} {} failed: {}", args.join(" "), stderr.trim());
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
            // SAFETY: tx_burst didn't send; we still own this mbuf.
            unsafe { ffi::shim_rte_pktmbuf_free(raw) };
        }
        attempt += 1;

        // Poll for ARP reply (100ms per attempt).
        let poll_until = Instant::now() + Duration::from_millis(100);
        while Instant::now() < poll_until {
            let mut rx_mbufs: [*mut ffi::rte_mbuf; 32] = [std::ptr::null_mut(); 32];
            let nb_rx = port::rx_burst(port_id, 0, &mut rx_mbufs, 32);
            for i in 0..nb_rx as usize {
                // SAFETY: rx_burst wrote a valid mbuf pointer; exclusive ownership taken.
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
static SHUTDOWN_FLAG: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

extern "C" fn sigint_handler(_sig: libc::c_int) {
    let ptr = SHUTDOWN_FLAG.load(Ordering::Acquire);
    if ptr != 0 {
        // SAFETY: ptr was stored via Arc::into_raw in run(), so it points to a valid
        // AtomicBool. We only read/store atomically (async-signal-safe). The Arc is
        // intentionally leaked so this pointer remains valid for the process lifetime.
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

// ── vhost thread pinning ────────────────────────────────────────────

/// Pin vhost-net kernel threads to CPU cores not used by DPDK engines.
///
/// vhost-net creates kernel threads named `vhost-<pid>` that service the
/// virtio rings. By default they can run on any core, causing cache thrashing
/// with the DPDK polling thread(s). Pinning them to separate cores improves
/// cache locality.
fn pin_vhost_threads(n_dpdk_cores: usize) {
    let pid = std::process::id();

    // Read /proc/<pid>/task/ to find all threads, then filter by name.
    let task_dir = format!("/proc/{pid}/task");
    let Ok(entries) = std::fs::read_dir(&task_dir) else {
        tracing::warn!("cannot read {task_dir}, skipping vhost pinning");
        return;
    };

    // Build CPU mask that excludes DPDK cores (0..n_dpdk_cores).
    // Pin vhost threads to the remaining cores.
    let n_cpus = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) } as usize;
    if n_cpus <= n_dpdk_cores {
        tracing::warn!(
            n_cpus,
            n_dpdk_cores,
            "not enough CPUs to pin vhost threads separately"
        );
        return;
    }

    let mut cpuset: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    for cpu in n_dpdk_cores..n_cpus {
        unsafe { libc::CPU_SET(cpu, &mut cpuset) };
    }

    for entry in entries.flatten() {
        let tid_str = entry.file_name();
        let tid_str = tid_str.to_string_lossy();
        let Ok(tid) = tid_str.parse::<i32>() else {
            continue;
        };

        // Read thread name from /proc/<pid>/task/<tid>/comm
        let comm_path = format!("/proc/{pid}/task/{tid_str}/comm");
        let Ok(comm) = std::fs::read_to_string(&comm_path) else {
            continue;
        };
        let comm = comm.trim();

        if comm.starts_with("vhost-") {
            let ret = unsafe {
                libc::sched_setaffinity(tid, std::mem::size_of::<libc::cpu_set_t>(), &cpuset)
            };
            if ret == 0 {
                tracing::info!(tid, comm, cores = ?(n_dpdk_cores..n_cpus), "pinned vhost thread");
            } else {
                tracing::warn!(tid, comm, "failed to pin vhost thread");
            }
        }
    }
}
