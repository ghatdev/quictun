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
enum Command {
    /// Generate a new private key and print it to stdout (base64)
    Genkey,
    /// Read a private key from stdin and print the corresponding public key to stdout (base64)
    Pubkey,
    /// Bring up a tunnel using the specified config file
    Up {
        /// Path to the TOML config file
        config: String,
        /// Use serial forwarding (single select loop) instead of parallel
        #[arg(long)]
        serial: bool,
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
        /// Number of TUN queues (Linux multi-queue; requires --queues > 1)
        #[arg(long, default_value = "1")]
        queues: usize,
        /// Use io_uring data plane (Linux only)
        #[arg(long)]
        iouring: bool,
        /// Enable SQPOLL for kernel-side SQ polling (kernel 5.13+ supports unprivileged)
        #[arg(long)]
        sqpoll: bool,
        /// Starting CPU for SQPOLL kernel threads (core i → CPU sqpoll_cpu+i; default: iouring_cores)
        #[arg(long)]
        sqpoll_cpu: Option<u32>,
        /// Number of io_uring cores (each gets own TUN queue + QUIC connection)
        #[arg(long, default_value = "1")]
        iouring_cores: usize,
        /// Buffer pool size per thread (max 1024, io_uring only)
        #[arg(long, default_value = "1024")]
        pool_size: usize,
        /// Use SendZc for zero-copy UDP sends (kernel 6.0+, io_uring only)
        #[arg(long)]
        zero_copy: bool,
        /// Initial RTT estimate in ms (default: 333). Set lower for LAN (e.g. 5).
        #[arg(long, default_value = "0")]
        initial_rtt: u64,
        /// Pin min_mtu = initial_mtu and disable DPLPMTUD (use when path MTU is known)
        #[arg(long)]
        pin_mtu: bool,
        /// Use DPDK kernel-bypass data plane. MODE: tap (default) or xdp
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
            serial,
            cc,
            recv_buf,
            send_buf,
            send_window,
            queues,
            iouring,
            sqpoll,
            sqpoll_cpu,
            iouring_cores,
            pool_size,
            zero_copy,
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
        } => up::run(
            &config, serial, &cc, recv_buf, send_buf, send_window, queues, iouring, sqpoll,
            sqpoll_cpu, iouring_cores, pool_size, zero_copy, initial_rtt, pin_mtu,
            dpdk, dpdk_local_ip, dpdk_remote_ip, dpdk_local_port, dpdk_gateway_mac,
            dpdk_eal_args, dpdk_port, no_adaptive_poll, dpdk_cores, no_udp_checksum,
        ),
        Command::Down { config } => down::run(&config),
    }
}
