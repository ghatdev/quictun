mod down;
mod genkey;
mod pubkey;
mod state;
mod up;

use clap::{Parser, Subcommand};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Parser)]
#[command(name = "quictun", about = "WireGuard-like tunnel over QUIC")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Generate a new private key and print it to stdout (base64)
    Genkey,
    /// Read a private key from stdin and print the corresponding public key to stdout (base64)
    Pubkey,
    /// Bring up a tunnel using the specified config file
    Up {
        /// Path to the TOML config file
        config: String,
        /// Congestion control algorithm: bbr, cubic, newreno, none
        #[arg(long, default_value = "bbr")]
        cc: String,
        /// Datagram receive buffer size in bytes
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        recv_buf: usize,
        /// Datagram send buffer size in bytes
        #[arg(long, default_value_t = 8 * 1024 * 1024)]
        send_buf: usize,
        /// QUIC send window in bytes (0 = default)
        #[arg(long, default_value = "0")]
        send_window: u64,
        /// Initial RTT estimate in ms (default: 333). Set lower for LAN (e.g. 5).
        #[arg(long, default_value = "0")]
        initial_rtt: u64,
        /// Pin min_mtu = initial_mtu and disable DPLPMTUD (use when path MTU is known)
        #[arg(long)]
        pin_mtu: bool,
        /// Use DPDK kernel-bypass data plane. MODE: tap (default), xdp, or virtio
        #[arg(long, value_name = "MODE", default_missing_value = "tap", num_args = 0..=1)]
        dpdk: Option<String>,
        /// IP address for the DPDK port (e.g., 192.168.100.10)
        #[arg(long)]
        dpdk_local_ip: Option<String>,
        /// Peer IP address on the DPDK network
        #[arg(long)]
        dpdk_remote_ip: Option<String>,
        /// Override local UDP port for DPDK (default: listen_port from config)
        #[arg(long)]
        dpdk_local_port: Option<u16>,
        /// Static peer MAC address (e.g., "bc:24:11:ab:cd:ef"); skips ARP resolution
        #[arg(long)]
        dpdk_gateway_mac: Option<String>,
        /// DPDK EAL arguments, semicolon-separated (default: "-l;0;-n;4")
        #[arg(long, default_value = "-l;0;-n;4")]
        dpdk_eal_args: String,
        /// DPDK port ID (default: 0)
        #[arg(long, default_value = "0")]
        dpdk_port: u16,
        /// Disable adaptive polling (keep pure busy-poll for benchmarking)
        #[arg(long)]
        no_adaptive_poll: bool,
        /// Number of DPDK engine cores (default: 1, multi-queue RSS for N > 1)
        #[arg(long, default_value = "1")]
        dpdk_cores: usize,
        /// Skip UDP checksum (write 0x0000; valid for IPv4, for benchmarking)
        #[arg(long)]
        no_udp_checksum: bool,
        /// Enable TUN GSO/GRO offload for batched I/O (Linux only, kernel 6.2+)
        #[arg(long)]
        offload: bool,
        /// Number of threads for the net engine (1 = single-thread, N = dispatcher + N-1 workers)
        #[arg(long, default_value = "1")]
        threads: usize,
    },
    /// Bring down a running tunnel by config file
    Down {
        /// Path to the TOML config file
        config: String,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Genkey => genkey::run(),
        Command::Pubkey => pubkey::run(),
        Command::Up {
            config,
            cc,
            recv_buf,
            send_buf,
            send_window,
            initial_rtt,
            pin_mtu,
            dpdk,
            dpdk_local_ip,
            dpdk_remote_ip,
            dpdk_local_port,
            dpdk_gateway_mac,
            dpdk_eal_args,
            dpdk_port,
            no_adaptive_poll,
            dpdk_cores,
            no_udp_checksum,
            offload,
            threads,
        } => up::run(
            &config,
            &cc,
            recv_buf,
            send_buf,
            send_window,
            initial_rtt,
            pin_mtu,
            dpdk,
            dpdk_local_ip,
            dpdk_remote_ip,
            dpdk_local_port,
            dpdk_gateway_mac,
            dpdk_eal_args,
            dpdk_port,
            no_adaptive_poll,
            dpdk_cores,
            no_udp_checksum,
            offload,
            threads,
        ),
        Command::Down { config } => down::run(&config),
    }
}
