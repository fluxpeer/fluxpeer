//! The unified `fluxpeer` binary (wg-style): one executable with subcommands for
//! every open-source role — coordination/control plane, relay, mesh node, and
//! management — so a self-host deploys ONE binary. Each subcommand dispatches to
//! the role's library (`fluxpeer_{control_server,relay_server,node,cli}`); the
//! standalone `control-server` / `relay-server` / `fp-node` / `fp` bins remain as
//! thin wrappers over the same libs.

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "fluxpeer", version, about = "fluxpeer — self-hosted mesh VPN, one binary")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the coordination/control-server (env: FLUXPEER_CONTROL_ADDR, DATABASE_URL).
    Control,
    /// Run a relay-server (env: FLUXPEER_RELAY_ADDR + optional _STUN/_ANYTLS/_BOND/_NODE_ID).
    Relay,
    /// Run or key a mesh node.
    Node {
        #[command(subcommand)]
        cmd: NodeCmd,
    },
    /// Manage networks / devices / invites / relays (the `fp` CLI; pass its args here).
    Ctl {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Run the daemon: bring up EVERY network this device has joined + a local
    /// control API (127.0.0.1) the desktop GUI drives (status/join/connect).
    Up {
        /// Config directory (default: /etc/fluxpeer).
        #[arg(long)]
        config_dir: Option<String>,
        /// Control-API bind address (default: 127.0.0.1:41999).
        #[arg(long)]
        addr: Option<String>,
    },
    /// List the networks this device has joined (from the config dir) + up/down.
    Networks {
        #[arg(long)]
        config_dir: Option<String>,
    },
    /// Show live status of a running node (fluxpeer's `wg show`): per-peer
    /// transport, endpoint, latest handshake, transfer (rx/tx), rtt.
    Show {
        /// Interface name (e.g. fp0); omit to auto-detect the running node.
        iface: Option<String>,
        /// Emit raw JSON instead of the human-readable table.
        #[arg(long)]
        json: bool,
    },
    /// Join a mesh from an invite token (`fp://join/…` from admin-lite): keygen +
    /// enroll + write config + bring the tunnel up. One command to onboard a node.
    Join {
        /// The `fp://join/<base64>` token (or bare base64) from the admin UI.
        token: String,
        /// Device label shown in the admin UI (default: this host's name).
        #[arg(long)]
        name: Option<String>,
        /// Where to write the node config (default: /etc/fluxpeer/node.json).
        #[arg(long)]
        out: Option<String>,
        /// Write the config but don't bring the tunnel up.
        #[arg(long)]
        no_run: bool,
    },
}

#[derive(Subcommand)]
enum NodeCmd {
    /// Bring up the tunnels from a config file (needs root for the TUN device).
    Run { config: String },
    /// Print a fresh hex keypair.
    Keygen,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ANSI colour only when stderr is a real terminal — when the daemon redirects a
    // node's stderr to `<iface>.log`, the file (and the GUI diagnostics tail) stays
    // free of `\x1b[..m` escape noise.
    use std::io::IsTerminal;
    tracing_subscriber::fmt()
        .with_ansi(std::io::stderr().is_terminal())
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    match Cli::parse().cmd {
        Cmd::Control => fluxpeer_control_server::serve_from_env()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        Cmd::Relay => fluxpeer_relay_server::serve_from_env()
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        Cmd::Node { cmd } => match cmd {
            NodeCmd::Run { config } => fluxpeer_node::run(&config).await?,
            NodeCmd::Keygen => fluxpeer_node::keygen(),
        },
        Cmd::Ctl { args } => {
            let cli = fluxpeer_cli::Cli::parse_from(std::iter::once("fluxpeer-ctl".to_string()).chain(args));
            fluxpeer_cli::run(cli).await?;
        }
        Cmd::Join {
            token,
            name,
            out,
            no_run,
        } => fluxpeer_node::join(&token, name, out, no_run).await?,
        Cmd::Show { iface, json } => fluxpeer_node::show(iface, json).await?,
        Cmd::Up { config_dir, addr } => {
            fluxpeer_node::daemon(config_dir.unwrap_or_else(fluxpeer_node::config_dir), addr).await?
        }
        Cmd::Networks { config_dir } => {
            fluxpeer_node::list_networks(&config_dir.unwrap_or_else(fluxpeer_node::config_dir))?
        }
    }
    Ok(())
}
