mod genkey;
mod pubkey;
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
        /// Use NewReno congestion control instead of BBR
        #[arg(long)]
        newreno: bool,
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
            newreno,
            recv_buf,
            send_buf,
            send_window,
            queues,
            iouring,
        } => up::run(
            &config, serial, newreno, recv_buf, send_buf, send_window, queues, iouring,
        ),
    }
}
