mod genkey;
mod pubkey;
mod up;

use clap::{Parser, Subcommand};

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
        /// Use parallel forwarding (separate tasks for TUN→QUIC and QUIC→TUN)
        #[arg(long)]
        parallel: bool,
        /// Use BBR congestion control instead of NewReno
        #[arg(long)]
        bbr: bool,
        /// Datagram receive buffer size in bytes
        #[arg(long, default_value = "65535")]
        recv_buf: usize,
        /// Datagram send buffer size in bytes
        #[arg(long, default_value = "1048576")]
        send_buf: usize,
        /// QUIC send window in bytes (0 = default)
        #[arg(long, default_value = "0")]
        send_window: u64,
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Genkey => genkey::run(),
        Command::Pubkey => pubkey::run(),
        Command::Up {
            config,
            parallel,
            bbr,
            recv_buf,
            send_buf,
            send_window,
        } => up::run(&config, parallel, bbr, recv_buf, send_buf, send_window),
    }
}
