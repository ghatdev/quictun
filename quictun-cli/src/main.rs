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
    },
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Genkey => genkey::run(),
        Command::Pubkey => pubkey::run(),
        Command::Up { config } => up::run(&config),
    }
}
