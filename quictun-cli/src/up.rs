use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result};
use quictun_core::config::{Config, Role};
use quictun_core::connection::{CongestionControl, TransportTuning};
use quictun_core::proto_config;
use quictun_crypto::{PrivateKey, PublicKey};

use crate::state;

#[allow(clippy::too_many_arguments)]
pub fn run(
    config_path: &str,
    cc: &str,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    iouring: bool,
    sqpoll: bool,
    sqpoll_cpu: Option<u32>,
    iouring_cores: usize,
    pool_size: usize,
    zero_copy: bool,
    initial_rtt: u64,
    pin_mtu: bool,
    dpdk: Option<String>,
    dpdk_local_ip: Option<String>,
    dpdk_remote_ip: Option<String>,
    dpdk_local_port: Option<u16>,
    dpdk_gateway_mac: Option<String>,
    dpdk_eal_args: String,
    dpdk_port: u16,
    no_adaptive_poll: bool,
    dpdk_cores: usize,
    no_udp_checksum: bool,
    offload: bool,
    threads: usize,
) -> Result<()> {
    let cc: CongestionControl = cc.parse().map_err(|e: String| anyhow::anyhow!(e))?;

    if let Some(dpdk_mode) = dpdk {
        return run_dpdk(
            config_path,
            cc,
            recv_buf,
            send_buf,
            send_window,
            &dpdk_mode,
            dpdk_local_ip,
            dpdk_remote_ip,
            dpdk_local_port,
            dpdk_gateway_mac,
            dpdk_eal_args,
            dpdk_port,
            no_adaptive_poll,
            dpdk_cores,
            no_udp_checksum,
        );
    }

    if iouring {
        return run_iouring(
            config_path,
            cc,
            recv_buf,
            send_buf,
            send_window,
            sqpoll,
            sqpoll_cpu,
            iouring_cores,
            pool_size,
            zero_copy,
        );
    }

    run_net(
        config_path,
        cc,
        recv_buf,
        send_buf,
        send_window,
        initial_rtt,
        pin_mtu,
        threads,
        offload,
    )
}

/// Run the synchronous blocking engine (quictun-net, default path).
#[allow(clippy::too_many_arguments)]
fn run_net(
    config_path: &str,
    cc: CongestionControl,
    recv_buf: usize,
    send_buf: usize,
    _send_window: u64,
    _initial_rtt: u64,
    _pin_mtu: bool,
    threads: usize,
    offload: bool,
) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(Path::new(config_path)).context("failed to load config")?;
    let role = config.role();
    let addr = config.parse_address()?;

    let private_key = PrivateKey::from_base64(&config.interface.private_key)
        .context("invalid interface private_key")?;

    // Parse all peer public keys.
    let peer_pubkeys: Vec<PublicKey> = config
        .peer
        .iter()
        .enumerate()
        .map(|(i, p)| {
            PublicKey::from_base64(&p.public_key)
                .with_context(|| format!("invalid public_key for peer[{i}]"))
        })
        .collect::<Result<_>>()?;

    let tuning = TransportTuning {
        datagram_recv_buffer: recv_buf,
        datagram_send_buffer: send_buf,
        send_window: _send_window,
        cc,
        max_idle_timeout_ms: config.interface.max_idle_timeout_ms,
        initial_rtt_ms: _initial_rtt,
        pin_mtu: _pin_mtu,
        ..Default::default()
    };

    tracing::info!(
        role = ?role,
        address = %addr,
        mtu = config.mtu(),
        peers = config.peer.len(),
        cc = %cc,
        "starting quictun (net engine)"
    );

    // Resolve interface name from config.
    let iface_name = config.interface_name(Path::new(config_path));

    // Write PID file.
    state::write_pid_file(&iface_name)?;
    let _pid_guard = state::PidFileGuard::new(iface_name.clone());

    // Idle timeout.
    let idle_timeout = if config.interface.max_idle_timeout_ms > 0 {
        Duration::from_millis(config.interface.max_idle_timeout_ms)
    } else {
        Duration::from_secs(30)
    };

    let cid_len = config.interface.cid_length as usize;

    // Build peer configs for identity matching.
    let resolved_peers: Vec<quictun_core::peer::PeerConfig> = config
        .peer
        .iter()
        .zip(peer_pubkeys.iter())
        .map(|(peer_cfg, pubkey)| {
            let tunnel_ip: std::net::Ipv4Addr = peer_cfg
                .allowed_ips
                .first()
                .and_then(|s| s.parse::<ipnet::Ipv4Net>().ok())
                .map(|net| net.addr())
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

            let allowed_ips: Vec<ipnet::Ipv4Net> = peer_cfg
                .allowed_ips
                .iter()
                .filter_map(|s| s.parse::<ipnet::Ipv4Net>().ok())
                .collect();

            quictun_core::peer::PeerConfig {
                spki_der: pubkey.spki_der().to_vec(),
                tunnel_ip,
                allowed_ips,
                keepalive: peer_cfg.keepalive.map(Duration::from_secs),
            }
        })
        .collect();

    let reconnect = config.peer[0].reconnect_interval.is_some();

    // Build UDP bind address.
    let listen_port = config.interface.listen_port.unwrap_or(0);
    let local_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

    // Build endpoint setup.
    let first_keepalive = config.peer[0].keepalive.map(Duration::from_secs);

    let net_config = quictun_net::engine::NetConfig {
        tunnel_ip: addr.addr(),
        tunnel_prefix: addr.prefix_len(),
        tunnel_mtu: config.mtu(),
        tunnel_name: Some(iface_name),
        idle_timeout,
        cid_len,
        peers: resolved_peers,
        reconnect,
        recv_buf,
        send_buf,
        threads,
        offload,
    };

    // Backoff state for reconnection.
    let mut backoff_secs: u64 = 1;
    const MAX_BACKOFF_SECS: u64 = 60;

    loop {
        let setup = match role {
            Role::Listener => {
                let server_config = proto_config::build_proto_server_config(
                    &private_key,
                    &peer_pubkeys,
                    first_keepalive,
                    &tuning,
                )?;
                quictun_net::engine::EndpointSetup::Listener { server_config }
            }
            Role::Connector => {
                let peer = &config.peer[0];
                let peer_pubkey = &peer_pubkeys[0];
                let keepalive = peer.keepalive.map(Duration::from_secs);
                let client_config = proto_config::build_proto_client_config(
                    &private_key,
                    peer_pubkey,
                    keepalive,
                    &tuning,
                )?;
                let remote_addr = peer.endpoint.context("connector requires peer endpoint")?;
                quictun_net::engine::EndpointSetup::Connector {
                    remote_addr,
                    client_config,
                }
            }
        };

        match quictun_net::engine::run(local_addr, setup, net_config.clone())? {
            quictun_net::engine::RunResult::Shutdown => {
                tracing::info!("tunnel closed (shutdown)");
                break;
            }
            quictun_net::engine::RunResult::ConnectionLost => {
                if reconnect {
                    let jitter_ms = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos()
                        % 1000) as u64;
                    let delay = Duration::from_millis(backoff_secs * 1000 + jitter_ms);
                    tracing::info!(delay_ms = delay.as_millis(), "reconnecting after backoff");
                    std::thread::sleep(delay);
                    backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
                    continue;
                }
                tracing::info!("connection lost, exiting (no reconnect configured)");
                break;
            }
        }
    }

    tracing::info!("tunnel closed");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn run_dpdk(
    _config_path: &str,
    _cc: CongestionControl,
    _recv_buf: usize,
    _send_buf: usize,
    _send_window: u64,
    _dpdk_mode: &str,
    _dpdk_local_ip: Option<String>,
    _dpdk_remote_ip: Option<String>,
    _dpdk_local_port: Option<u16>,
    _dpdk_gateway_mac: Option<String>,
    _dpdk_eal_args: String,
    _dpdk_port: u16,
    _no_adaptive_poll: bool,
    _dpdk_cores: usize,
    _no_udp_checksum: bool,
) -> Result<()> {
    bail!("--dpdk requires Linux");
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn run_dpdk(
    config_path: &str,
    cc: CongestionControl,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    dpdk_mode: &str,
    dpdk_local_ip: Option<String>,
    dpdk_remote_ip: Option<String>,
    dpdk_local_port: Option<u16>,
    dpdk_gateway_mac: Option<String>,
    dpdk_eal_args: String,
    dpdk_port: u16,
    no_adaptive_poll: bool,
    dpdk_cores: usize,
    no_udp_checksum: bool,
) -> Result<()> {
    // Validate mode.
    if dpdk_mode != "tap" && dpdk_mode != "xdp" && dpdk_mode != "virtio" {
        anyhow::bail!("--dpdk mode must be 'tap', 'xdp', or 'virtio', got '{dpdk_mode}'");
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(Path::new(config_path)).context("failed to load config")?;
    let role = config.role();
    let addr = config.parse_address()?;

    let private_key = PrivateKey::from_base64(&config.interface.private_key)
        .context("invalid interface private_key")?;

    let peer = &config.peer[0];
    let peer_pubkey =
        PublicKey::from_base64(&peer.public_key).context("invalid peer public_key")?;

    let keepalive = peer.keepalive.map(Duration::from_secs);

    let tuning = TransportTuning {
        datagram_recv_buffer: recv_buf,
        datagram_send_buffer: send_buf,
        send_window,
        cc,
        ..Default::default()
    };

    // Parse DPDK-specific IPs.
    let dpdk_local_ip: std::net::Ipv4Addr = dpdk_local_ip
        .context("--dpdk-local-ip is required with --dpdk")?
        .parse()
        .context("invalid --dpdk-local-ip")?;

    let dpdk_remote_ip: std::net::Ipv4Addr = dpdk_remote_ip
        .context("--dpdk-remote-ip is required with --dpdk")?
        .parse()
        .context("invalid --dpdk-remote-ip")?;

    // Parse optional gateway MAC (e.g., "bc:24:11:ab:cd:ef").
    let gateway_mac = dpdk_gateway_mac
        .map(|s| parse_mac(&s))
        .transpose()
        .context("invalid --dpdk-gateway-mac (expected xx:xx:xx:xx:xx:xx)")?;

    let eal_args: Vec<String> = dpdk_eal_args.split(';').map(|s| s.to_string()).collect();

    // Resolve interface name from config.
    let iface_name = config.interface_name(Path::new(config_path));

    tracing::info!(
        role = ?role,
        address = %addr,
        mtu = config.mtu(),
        dpdk_local_ip = %dpdk_local_ip,
        dpdk_remote_ip = %dpdk_remote_ip,
        dpdk_port,
        dpdk_mode,
        cc = %cc,
        "starting quictun (DPDK)"
    );

    let tunnel_ip = addr.addr();
    let tunnel_prefix = addr.prefix_len();
    let tunnel_mtu = config.mtu();

    // Write PID file.
    state::write_pid_file(&iface_name)?;
    let _pid_guard = state::PidFileGuard::new(iface_name.clone());

    // Build quinn-proto configs.
    let listen_port = config.interface.listen_port.unwrap_or(0);
    let local_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

    // Parse all peer public keys for server config and peer identification.
    let all_peer_pubkeys: Vec<PublicKey> = config
        .peer
        .iter()
        .map(|p| {
            PublicKey::from_base64(&p.public_key)
                .with_context(|| format!("invalid peer public_key: {}", &p.public_key))
        })
        .collect::<Result<Vec<_>>>()?;

    let setup = match role {
        Role::Connector => {
            let cc = quictun_dpdk::quic::build_proto_client_config(
                &private_key,
                &peer_pubkey,
                keepalive,
                &tuning,
            )?;
            let remote_addr = peer.endpoint.context("connector requires peer endpoint")?;
            // Override remote_addr IP with DPDK IP, keep the port.
            let dpdk_remote_addr = SocketAddr::new(dpdk_remote_ip.into(), remote_addr.port());
            quictun_dpdk::event_loop::EndpointSetup::Connector {
                remote_addr: dpdk_remote_addr,
                client_config: cc,
            }
        }
        Role::Listener => {
            // Always pass ALL peer public keys (not just peer[0]).
            let sc = quictun_dpdk::quic::build_proto_server_config(
                &private_key,
                &all_peer_pubkeys,
                keepalive,
                &tuning,
            )?;
            quictun_dpdk::event_loop::EndpointSetup::Listener { server_config: sc }
        }
    };

    // Always build peer configs for identification (listener and connector).
    let dpdk_peers: Vec<quictun_core::peer::PeerConfig> = config
        .peer
        .iter()
        .zip(all_peer_pubkeys.iter())
        .map(|(p, pubkey)| {
            let tunnel_ip: std::net::Ipv4Addr = p
                .allowed_ips
                .first()
                .and_then(|cidr| cidr.split('/').next())
                .and_then(|ip| ip.parse().ok())
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
            let allowed_ips: Vec<ipnet::Ipv4Net> = p
                .allowed_ips
                .iter()
                .filter_map(|s| s.parse::<ipnet::Ipv4Net>().ok())
                .collect();

            quictun_core::peer::PeerConfig {
                spki_der: pubkey.spki_der().to_vec(),
                tunnel_ip,
                allowed_ips,
                keepalive: None,
            }
        })
        .collect();

    let dpdk_config = quictun_dpdk::event_loop::DpdkConfig {
        mode: dpdk_mode.to_string(),
        eal_args,
        port_id: dpdk_port,
        local_ip: dpdk_local_ip,
        remote_ip: dpdk_remote_ip,
        local_port: dpdk_local_port,
        gateway_mac,
        tunnel_ip,
        tunnel_prefix,
        tunnel_mtu,
        tunnel_iface: iface_name,
        adaptive_poll: !no_adaptive_poll,
        n_cores: dpdk_cores,
        no_udp_checksum,
        peers: dpdk_peers,
    };

    quictun_dpdk::event_loop::run(local_addr, setup, dpdk_config)
}

/// Parse a MAC address string like "bc:24:11:ab:cd:ef" into [u8; 6].
#[cfg(target_os = "linux")]
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        anyhow::bail!("MAC must have 6 octets separated by ':'");
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] =
            u8::from_str_radix(part, 16).with_context(|| format!("invalid MAC octet: {part}"))?;
    }
    Ok(mac)
}

#[cfg(not(target_os = "linux"))]
#[allow(clippy::too_many_arguments)]
fn run_iouring(
    _config_path: &str,
    _cc: CongestionControl,
    _recv_buf: usize,
    _send_buf: usize,
    _send_window: u64,
    _sqpoll: bool,
    _sqpoll_cpu: Option<u32>,
    _iouring_cores: usize,
    _pool_size: usize,
    _zero_copy: bool,
) -> Result<()> {
    bail!("--iouring requires Linux");
}

#[cfg(target_os = "linux")]
fn run_iouring(
    config_path: &str,
    cc: CongestionControl,
    recv_buf: usize,
    send_buf: usize,
    send_window: u64,
    sqpoll: bool,
    sqpoll_cpu: Option<u32>,
    iouring_cores: usize,
    pool_size: usize,
    zero_copy: bool,
) -> Result<()> {
    use quictun_tun::TunOptions;
    use std::os::fd::{AsRawFd, RawFd};

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let config = Config::load(Path::new(config_path)).context("failed to load config")?;
    let role = config.role();
    let addr = config.parse_address()?;

    let private_key = PrivateKey::from_base64(&config.interface.private_key)
        .context("invalid interface private_key")?;

    let peer = &config.peer[0];
    let peer_pubkey =
        PublicKey::from_base64(&peer.public_key).context("invalid peer public_key")?;

    let keepalive = peer.keepalive.map(Duration::from_secs);

    let tuning = TransportTuning {
        datagram_recv_buffer: recv_buf,
        datagram_send_buffer: send_buf,
        send_window,
        cc,
        ..Default::default()
    };

    let cores = iouring_cores;

    // Parse all peer public keys.
    let all_peer_pubkeys: Vec<PublicKey> = config
        .peer
        .iter()
        .enumerate()
        .map(|(i, p)| {
            PublicKey::from_base64(&p.public_key)
                .with_context(|| format!("invalid public_key for peer[{i}]"))
        })
        .collect::<Result<_>>()?;

    tracing::info!(
        role = ?role,
        address = %addr,
        mtu = config.mtu(),
        peer_fingerprint = %peer_pubkey.fingerprint(),
        cc = %cc,
        recv_buf,
        send_buf,
        send_window,
        sqpoll,
        zero_copy,
        cores,
        "starting quictun (io_uring)"
    );

    // Resolve interface name from config.
    let iface_name = config.interface_name(Path::new(config_path));

    // Create sync TUN device(s).
    let mut tun_opts = TunOptions::new(addr.addr(), addr.prefix_len(), config.mtu());
    tun_opts.name = Some(iface_name.clone());
    tun_opts.multi_queue = cores > 1;

    let tun_primary =
        quictun_tun::create_sync(&tun_opts).context("failed to create sync TUN device")?;

    let mut tun_devices = vec![tun_primary];
    for i in 1..cores {
        let clone = tun_devices[0]
            .try_clone()
            .with_context(|| format!("failed to clone TUN queue {i}"))?;
        tun_devices.push(clone);
    }
    let tun_fds: Vec<RawFd> = tun_devices.iter().map(|d| d.as_raw_fd()).collect();

    if cores > 1 {
        tracing::info!(cores, "multi-queue TUN ready ({} queues)", tun_fds.len());
    }

    // Write PID file.
    state::write_pid_file(&iface_name)?;
    let _pid_guard = state::PidFileGuard::new(iface_name);

    // Idle timeout.
    let idle_timeout = if config.interface.max_idle_timeout_ms > 0 {
        Duration::from_millis(config.interface.max_idle_timeout_ms)
    } else {
        Duration::from_secs(30)
    };

    let cid_len = config.interface.cid_length as usize;

    // Build peer configs for identity matching.
    let resolved_peers: Vec<quictun_core::peer::PeerConfig> = config
        .peer
        .iter()
        .zip(all_peer_pubkeys.iter())
        .map(|(peer_cfg, pubkey)| {
            let tunnel_ip: std::net::Ipv4Addr = peer_cfg
                .allowed_ips
                .first()
                .and_then(|s| s.parse::<ipnet::Ipv4Net>().ok())
                .map(|net| net.addr())
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

            let allowed_ips: Vec<ipnet::Ipv4Net> = peer_cfg
                .allowed_ips
                .iter()
                .filter_map(|s| s.parse::<ipnet::Ipv4Net>().ok())
                .collect();

            quictun_core::peer::PeerConfig {
                spki_der: pubkey.spki_der().to_vec(),
                tunnel_ip,
                allowed_ips,
                keepalive: peer_cfg.keepalive.map(Duration::from_secs),
            }
        })
        .collect();

    // Build quinn-proto configs.
    let first_keepalive = config.peer[0].keepalive.map(Duration::from_secs);

    let listen_port = config.interface.listen_port.unwrap_or(0);
    let local_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

    let setup = match role {
        Role::Connector => {
            let client_config = proto_config::build_proto_client_config(
                &private_key,
                &peer_pubkey,
                keepalive,
                &tuning,
            )?;
            let remote_addr = peer.endpoint.context("connector requires peer endpoint")?;
            quictun_uring::event_loop::EndpointSetup::Connector {
                remote_addr,
                client_config,
            }
        }
        Role::Listener => {
            let server_config = proto_config::build_proto_server_config(
                &private_key,
                &all_peer_pubkeys,
                first_keepalive,
                &tuning,
            )?;
            quictun_uring::event_loop::EndpointSetup::Listener { server_config }
        }
    };

    let uring_config = quictun_uring::event_loop::UringConfig {
        cid_len,
        peers: resolved_peers,
        idle_timeout,
    };

    // Run the io_uring event loop (no tokio).
    // tun_devices must outlive the event loop (they own the fds).
    quictun_uring::event_loop::run(
        tun_fds, local_addr, setup, uring_config, sqpoll, sqpoll_cpu, pool_size, zero_copy,
    )
}
