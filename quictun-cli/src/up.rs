use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

#[cfg(not(target_os = "linux"))]
use anyhow::bail;
use anyhow::{Context, Result};
use quictun_core::config::{Backend, Config, Mode};
use quictun_core::connection::{CongestionControl, TransportTuning};
use quictun_core::proto_config;
use quictun_crypto::{PrivateKey, PublicKey};

use crate::state;

pub fn run(config_path: &str) -> Result<()> {
    let config = Config::load(Path::new(config_path)).context("failed to load config")?;

    match config.engine.backend {
        Backend::Kernel => run_net(config_path, &config),
        Backend::DpdkVirtio | Backend::DpdkRouter => run_dpdk(config_path, &config),
    }
}

/// Run the synchronous blocking engine (quictun-net, default path).
fn run_net(config_path: &str, config: &Config) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mode = config.mode();
    let addr = config.parse_address()?;

    let private_key = PrivateKey::from_base64(&config.interface.private_key)
        .context("invalid interface private_key")?;

    let peers = config.all_peers();
    let peer_pubkeys: Vec<PublicKey> = peers
        .iter()
        .enumerate()
        .map(|(i, p)| {
            PublicKey::from_base64(&p.public_key)
                .with_context(|| format!("invalid public_key for peer[{i}]"))
        })
        .collect::<Result<_>>()?;

    let cc: CongestionControl = config
        .engine
        .cc
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let tuning = TransportTuning {
        datagram_recv_buffer: config.engine.recv_buf,
        datagram_send_buffer: config.engine.send_buf,
        send_window: config.engine.send_window,
        cc,
        max_idle_timeout_ms: config.interface.max_idle_timeout_ms,
        initial_rtt_ms: config.engine.initial_rtt_ms,
        pin_mtu: config.engine.pin_mtu,
        ..Default::default()
    };

    tracing::info!(
        mode = %mode,
        address = %addr,
        mtu = config.mtu(),
        peers = peers.len(),
        cc = %cc,
        "starting quictun (net engine)"
    );

    let iface_name = config.interface_name(Path::new(config_path));

    state::write_pid_file(&iface_name)?;
    let _pid_guard = state::PidFileGuard::new(iface_name.clone());

    let idle_timeout = if config.interface.max_idle_timeout_ms > 0 {
        Duration::from_millis(config.interface.max_idle_timeout_ms)
    } else {
        Duration::from_secs(30)
    };

    let cid_len = config.interface.cid_length as usize;

    let resolved_peers: Vec<quictun_core::peer::PeerConfig> = peers
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

    let reconnect = peers[0].reconnect_interval.is_some();

    let listen_port = config.interface.listen_port.unwrap_or(0);
    let local_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

    let first_keepalive = peers[0].keepalive.map(Duration::from_secs);

    let net_config = quictun_net::engine::NetConfig {
        tunnel_ip: addr.addr(),
        tunnel_prefix: addr.prefix_len(),
        tunnel_mtu: config.mtu(),
        tunnel_name: Some(iface_name),
        idle_timeout,
        cid_len,
        peers: resolved_peers,
        reconnect,
        recv_buf: config.engine.recv_buf,
        send_buf: config.engine.send_buf,
        threads: config.engine.threads,
        offload: config.engine.offload,
        batch_size: config.engine.batch_size,
        gso_max_segments: config.engine.gso_max_segments,
        ack_interval: config.engine.ack_interval,
        ack_timer_ms: config.engine.ack_timer_ms,
        tun_write_buf_capacity: config.engine.tun_write_buf,
        channel_capacity: config.engine.channel_capacity,
        poll_events: config.engine.poll_events,
        pipeline: config.engine.pipeline,
        container: config.engine.container,
    };

    // Resolve cipher suites.
    let server_ciphers = config.server_cipher_suites()?;
    let client_ciphers = config.client_cipher_suites()?;

    let mut backoff_secs: u64 = 1;
    const MAX_BACKOFF_SECS: u64 = 60;

    loop {
        let setup = match mode {
            Mode::Listener => {
                let server_config = proto_config::build_proto_server_config(
                    &private_key,
                    &peer_pubkeys,
                    first_keepalive,
                    &tuning,
                    &server_ciphers,
                )?;
                quictun_net::engine::EndpointSetup::Listener { server_config }
            }
            Mode::Connector => {
                let peer = &peers[0];
                let peer_pubkey = &peer_pubkeys[0];
                let keepalive = peer.keepalive.map(Duration::from_secs);
                let client_config = proto_config::build_proto_client_config(
                    &private_key,
                    peer_pubkey,
                    keepalive,
                    &tuning,
                    &client_ciphers,
                    config.interface.zero_rtt,
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
fn run_dpdk(_config_path: &str, _config: &Config) -> Result<()> {
    bail!("DPDK backends require Linux");
}

#[cfg(target_os = "linux")]
fn run_dpdk(config_path: &str, config: &Config) -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let mode = config.mode();
    let addr = config.parse_address()?;

    let private_key = PrivateKey::from_base64(&config.interface.private_key)
        .context("invalid interface private_key")?;

    let peers = config.all_peers();
    let peer = &peers[0];
    let peer_pubkey =
        PublicKey::from_base64(&peer.public_key).context("invalid peer public_key")?;

    let keepalive = peer.keepalive.map(Duration::from_secs);

    let cc: CongestionControl = config
        .engine
        .cc
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    let tuning = TransportTuning {
        datagram_recv_buffer: config.engine.recv_buf,
        datagram_send_buffer: config.engine.send_buf,
        send_window: config.engine.send_window,
        cc,
        ..Default::default()
    };

    // Parse DPDK-specific IPs.
    let dpdk_local_ip: std::net::Ipv4Addr = config
        .engine
        .dpdk_local_ip
        .as_ref()
        .context("dpdk_local_ip is required for DPDK backends")?
        .parse()
        .context("invalid dpdk_local_ip")?;

    // Derive remote IP from peer endpoint (connector) or None (listener learns from packets).
    let dpdk_remote_ip: Option<std::net::Ipv4Addr> = if mode == Mode::Connector {
        let endpoint = peers[0]
            .endpoint
            .context("connector requires peer endpoint")?;
        match endpoint.ip() {
            std::net::IpAddr::V4(ip) => Some(ip),
            _ => anyhow::bail!("DPDK requires IPv4 endpoint"),
        }
    } else {
        None
    };

    let eal_args: Vec<String> = config
        .engine
        .dpdk_eal_args
        .split(';')
        .map(|s| s.to_string())
        .collect();

    let iface_name = config.interface_name(Path::new(config_path));

    let dpdk_mode = match config.engine.backend {
        Backend::DpdkVirtio => "virtio",
        Backend::DpdkRouter => "router",
        _ => unreachable!(),
    };

    tracing::info!(
        mode = %mode,
        address = %addr,
        mtu = config.mtu(),
        dpdk_local_ip = %dpdk_local_ip,
        dpdk_port = config.engine.dpdk_port,
        dpdk_mode,
        cc = %cc,
        "starting quictun (DPDK)"
    );

    let tunnel_ip = addr.addr();
    let tunnel_prefix = addr.prefix_len();
    let tunnel_mtu = config.mtu();

    state::write_pid_file(&iface_name)?;
    let _pid_guard = state::PidFileGuard::new(iface_name.clone());

    let listen_port = config.interface.listen_port.unwrap_or(0);
    let local_addr: SocketAddr = format!("0.0.0.0:{listen_port}").parse()?;

    // Resolve cipher suites.
    let server_ciphers = config.server_cipher_suites()?;
    let client_ciphers = config.client_cipher_suites()?;

    // Parse all peer public keys.
    let all_peer_pubkeys: Vec<PublicKey> = peers
        .iter()
        .map(|p| {
            PublicKey::from_base64(&p.public_key)
                .with_context(|| format!("invalid peer public_key: {}", &p.public_key))
        })
        .collect::<Result<Vec<_>>>()?;

    let setup = match mode {
        Mode::Connector => {
            let cc = quictun_dpdk::quic::build_proto_client_config(
                &private_key,
                &peer_pubkey,
                keepalive,
                &tuning,
                &client_ciphers,
                config.interface.zero_rtt,
            )?;
            let remote_addr = peer.endpoint.context("connector requires peer endpoint")?;
            let dpdk_remote_ip_v4 =
                dpdk_remote_ip.context("connector must have a remote IP")?;
            let dpdk_remote_addr = SocketAddr::new(dpdk_remote_ip_v4.into(), remote_addr.port());
            quictun_dpdk::event_loop::EndpointSetup::Connector {
                remote_addr: dpdk_remote_addr,
                client_config: cc,
            }
        }
        Mode::Listener => {
            let sc = quictun_dpdk::quic::build_proto_server_config(
                &private_key,
                &all_peer_pubkeys,
                keepalive,
                &tuning,
                &server_ciphers,
            )?;
            quictun_dpdk::event_loop::EndpointSetup::Listener { server_config: sc }
        }
    };

    let dpdk_peers: Vec<quictun_core::peer::PeerConfig> = peers
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

    let is_router = config.engine.backend == Backend::DpdkRouter;
    let routing = config.routing.as_ref();
    let enable_nat = routing.map(|r| r.nat).unwrap_or(true);
    let mss_clamp = routing.map(|r| r.mss_clamp).unwrap_or(0);

    let dpdk_config = quictun_dpdk::event_loop::DpdkConfig {
        mode: dpdk_mode.to_string(),
        eal_args,
        port_id: config.engine.dpdk_port,
        local_ip: dpdk_local_ip,
        remote_ip: dpdk_remote_ip,
        local_port: config.engine.dpdk_local_port,
        tunnel_ip,
        tunnel_prefix,
        tunnel_mtu,
        tunnel_iface: iface_name,
        adaptive_poll: config.engine.adaptive_poll,
        n_cores: config.engine.dpdk_cores,
        no_udp_checksum: config.engine.no_udp_checksum,
        peers: dpdk_peers,
        router: is_router,
        enable_nat,
        mss_clamp,
    };

    quictun_dpdk::event_loop::run(local_addr, setup, dpdk_config)
}

