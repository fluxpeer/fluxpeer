//! fluxpeer `fp` CLI binary.

use clap::Parser;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fluxpeer_cli::run(fluxpeer_cli::Cli::parse()).await
}
