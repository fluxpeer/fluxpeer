//! fluxpeer management CLI (`fp`)
//!
//! Thin HTTP client over the control-server `/api/v1` surface. Logic lives in
//! [`Client`] so it can be integration-tested against a live server.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
pub use fluxpeer_sdk::{Client, DEFAULT_SERVER, build_import_devices, wgconf};
use serde_json::Value;

#[derive(Parser, Debug)]
#[command(name = "fp", about = "fluxpeer control-server CLI")]
pub struct Cli {
    /// Control-server base URL.
    #[arg(long, env = "FLUXPEER_CONTROL_URL", default_value = DEFAULT_SERVER, global = true)]
    pub server: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Network operations.
    Network {
        #[command(subcommand)]
        command: NetworkCmd,
    },
    /// Invite operations.
    Invite {
        #[command(subcommand)]
        command: InviteCmd,
    },
    /// Device operations.
    Device {
        #[command(subcommand)]
        command: DeviceCmd,
    },
    /// Subnet route operations (Subnet Router).
    Route {
        #[command(subcommand)]
        command: RouteCmd,
    },
    /// Relay directory operations.
    Relay {
        #[command(subcommand)]
        command: RelayCmd,
    },
    /// MagicDNS: resolve a device name in a network.
    Resolve { network_id: String, name: String },
    /// Batch-import WireGuard `wg.conf` files (each: one `[Interface]` + N `[Peer]`):
    /// register every peer as a device, preserving its fixed address. The interface's
    /// PrivateKey stays local — only its derived public key is sent. Pass several
    /// files and/or directories; by default each file becomes its OWN new network
    /// (named after the `[Interface]` comment or the filename). Use `--network` to
    /// instead import everything into one existing network.
    Import {
        /// wg-quick config file(s) and/or directories (every `*.conf` inside).
        #[arg(required = true)]
        files: Vec<String>,
        /// Import into this EXISTING network instead of creating one per file.
        #[arg(long)]
        network: Option<String>,
        /// Parse + validate + print what would be created, without calling the server.
        #[arg(long)]
        dry_run: bool,
        /// Don't register the `[Interface]` itself as a device (peers only).
        #[arg(long)]
        skip_interface: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum NetworkCmd {
    /// Create a network.
    Create { name: String },
    /// List networks.
    List,
}

#[derive(Subcommand, Debug)]
pub enum InviteCmd {
    /// Create an invite for a network.
    Create {
        network_id: String,
        #[arg(long)]
        max_uses: Option<u32>,
        #[arg(long)]
        expires_at: Option<i64>,
    },
}

#[derive(Subcommand, Debug)]
pub enum DeviceCmd {
    /// List devices in a network.
    List { network_id: String },
    /// Show a device's pulled config (peers + allowed-ips).
    Config { device_id: String },
    /// Revoke a device.
    Revoke { device_id: String },
}

#[derive(Subcommand, Debug)]
pub enum RouteCmd {
    /// Advertise a subnet route from a device (e.g. 192.168.1.0/24).
    Add { device_id: String, prefix: String },
    /// Approve an advertised route.
    Approve { route_id: String },
}

#[derive(Subcommand, Debug)]
pub enum RelayCmd {
    /// Register a relay node (omit --network-id for a shared/official relay).
    Add {
        region: String,
        url: String,
        #[arg(long)]
        network_id: Option<String>,
        /// Clients connect over AnyTLS/443 instead of plain TCP.
        #[arg(long)]
        anytls: bool,
        /// UDP STUN address (defaults to `url`; the relay doubles as STUN).
        #[arg(long)]
        stun_url: Option<String>,
    },
    /// List relays usable by a network.
    List { network_id: String },
}

/// Execute a parsed CLI invocation, printing JSON results to stdout.
pub async fn run(cli: Cli) -> Result<()> {
    let client = Client::new(&cli.server);
    match cli.command {
        Command::Network { command } => match command {
            NetworkCmd::Create { name } => print_json(&client.create_network(&name).await?),
            NetworkCmd::List => print_json(&client.list_networks().await?),
        },
        Command::Invite { command } => match command {
            InviteCmd::Create {
                network_id,
                max_uses,
                expires_at,
            } => print_json(&client.create_invite(&network_id, max_uses, expires_at).await?),
        },
        Command::Device { command } => match command {
            DeviceCmd::List { network_id } => print_json(&client.list_devices(&network_id).await?),
            DeviceCmd::Config { device_id } => print_json(&client.device_config(&device_id).await?),
            DeviceCmd::Revoke { device_id } => {
                client.revoke_device(&device_id).await?;
                println!("revoked {device_id}");
            }
        },
        Command::Route { command } => match command {
            RouteCmd::Add { device_id, prefix } => print_json(&client.advertise_route(&device_id, &prefix).await?),
            RouteCmd::Approve { route_id } => {
                client.approve_route(&route_id).await?;
                println!("approved {route_id}");
            }
        },
        Command::Relay { command } => match command {
            RelayCmd::Add {
                region,
                url,
                network_id,
                anytls,
                stun_url,
            } => print_json(
                &client
                    .register_relay(&region, &url, network_id.as_deref(), anytls, stun_url.as_deref())
                    .await?,
            ),
            RelayCmd::List { network_id } => print_json(&client.list_relays(&network_id).await?),
        },
        Command::Resolve { network_id, name } => print_json(&client.resolve(&network_id, &name).await?),
        Command::Import {
            files,
            network,
            dry_run,
            skip_interface,
        } => import(&client, &files, network.as_deref(), dry_run, skip_interface).await?,
    }
    Ok(())
}

/// One wg.conf to import: a display/name hint plus its raw text. Sources come from
/// explicit files, every `*.conf` in a directory, or stdin (`-`).
struct Source {
    /// Fallback name for the auto-created network (the `[Interface]` comment wins).
    name: String,
    text: String,
}

/// Expand the `files` args into concrete sources: `-` reads stdin, a directory
/// contributes each `*.conf` it holds (sorted), everything else is a file.
fn collect_sources(files: &[String]) -> Result<Vec<Source>> {
    use std::io::Read;
    let mut out = Vec::new();
    for f in files {
        if f == "-" {
            let mut text = String::new();
            std::io::stdin().read_to_string(&mut text).context("reading wg.conf from stdin")?;
            out.push(Source { name: "imported".into(), text });
            continue;
        }
        let path = std::path::Path::new(f);
        if path.is_dir() {
            let mut confs: Vec<std::path::PathBuf> = std::fs::read_dir(path)
                .with_context(|| format!("reading directory {f}"))?
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "conf"))
                .collect();
            confs.sort();
            if confs.is_empty() {
                eprintln!("! no *.conf files in {f}");
            }
            for p in confs {
                let text = std::fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
                out.push(Source { name: stem(&p.to_string_lossy()), text });
            }
        } else {
            let text = std::fs::read_to_string(path).with_context(|| format!("reading {f}"))?;
            out.push(Source { name: stem(f), text });
        }
    }
    Ok(out)
}

async fn import(client: &Client, files: &[String], network: Option<&str>, dry_run: bool, skip_interface: bool) -> Result<()> {
    let sources = collect_sources(files)?;
    if sources.is_empty() {
        anyhow::bail!("no wg.conf input found (pass file(s), a directory, or `-` for stdin)");
    }

    let mut total_created = 0usize;
    let mut total_skipped = 0usize;
    let mut nets_created = 0usize;

    for src in &sources {
        let conf = wgconf::parse(&src.text).with_context(|| format!("parsing {}", src.name))?;
        let (devices, warnings) = build_import_devices(&conf, &src.name, skip_interface)?;
        // `[Interface]` comment names the network; else the file/stdin name.
        let net_name = conf.interface.name.clone().unwrap_or_else(|| src.name.clone());
        let target_desc = match network {
            Some(n) => format!("→ network {n}"),
            None => format!("→ new network \"{net_name}\""),
        };

        println!("{}: 1 interface, {} peers → {} device(s)  {target_desc}", src.name, conf.peers.len(), devices.len());
        for d in &devices {
            let addr = d["address_v4"].as_str().unwrap_or("(no addr)");
            let ep = d["endpoints"].as_array().and_then(|a| a.first()).and_then(|e| e.as_str());
            let ep = ep.map(|e| format!("  endpoint {e}")).unwrap_or_default();
            let key8: String = d["wg_public_key"].as_str().unwrap_or("?").chars().take(8).collect();
            println!("  + {:<20} {:<15} {key8}…{ep}", d["name"].as_str().unwrap_or("?"), addr);
        }
        for w in &warnings {
            eprintln!("! {w}");
        }
        if dry_run || devices.is_empty() {
            if devices.is_empty() && !dry_run {
                println!("  (nothing to import)");
            }
            continue;
        }

        // Resolve the target network: an explicit existing one, or a fresh one per file.
        let target = match network {
            Some(n) => n.to_string(),
            None => {
                let net = client.create_network(&net_name).await?;
                nets_created += 1;
                net["id"].as_str().context("create_network response missing id")?.to_string()
            }
        };
        let res = client.import_devices(&target, &Value::Array(devices)).await?;
        let created = res["created"].as_array().map(Vec::len).unwrap_or(0);
        let skipped = res["skipped"].as_array().map(Vec::len).unwrap_or(0);
        total_created += created;
        total_skipped += skipped;
        println!("  ✓ {created} device(s) into {target}{}", if skipped > 0 { format!("; {skipped} skipped (already enrolled)") } else { String::new() });
    }

    if dry_run {
        println!("(dry-run — nothing sent to the control-server)");
    } else {
        let nets = if network.is_none() { format!("{nets_created} network(s), ") } else { String::new() };
        let skip = if total_skipped > 0 { format!(", {total_skipped} skipped") } else { String::new() };
        println!("done: {nets}{total_created} device(s) registered (fixed addresses preserved){skip}");
    }
    Ok(())
}

/// File stem (without dir/extension) — a friendly default name for the interface.
fn stem(path: &str) -> String {
    std::path::Path::new(path)
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("interface")
        .to_string()
}

fn print_json(v: &Value) {
    println!("{}", serde_json::to_string_pretty(v).unwrap_or_else(|_| v.to_string()));
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parses_network_create() {
        let cli = Cli::try_parse_from(["fp", "network", "create", "home"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Network {
                command: NetworkCmd::Create { .. }
            }
        ));
        assert_eq!(cli.server, DEFAULT_SERVER);
    }

    #[test]
    fn parses_server_flag_and_invite_opts() {
        let cli = Cli::try_parse_from([
            "fp",
            "--server",
            "http://x:9",
            "invite",
            "create",
            "net-1",
            "--max-uses",
            "5",
        ])
        .unwrap();
        assert_eq!(cli.server, "http://x:9");
        match cli.command {
            Command::Invite {
                command: InviteCmd::Create {
                    network_id, max_uses, ..
                },
            } => {
                assert_eq!(network_id, "net-1");
                assert_eq!(max_uses, Some(5));
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn rejects_unknown_subcommand() {
        assert!(Cli::try_parse_from(["fp", "bogus"]).is_err());
    }

    #[test]
    fn parses_import_with_flags() {
        let cli = Cli::try_parse_from(["fp", "import", "wg0.conf", "--network", "net-1", "--dry-run", "--skip-interface"]).unwrap();
        match cli.command {
            Command::Import {
                files,
                network,
                dry_run,
                skip_interface,
            } => {
                assert_eq!(files, vec!["wg0.conf"]);
                assert_eq!(network.as_deref(), Some("net-1"));
                assert!(dry_run);
                assert!(skip_interface);
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn parses_import_multi_file_no_network() {
        // Several files + stdin, no --network → each becomes its own new network.
        let cli = Cli::try_parse_from(["fp", "import", "office.conf", "home.conf", "-"]).unwrap();
        match cli.command {
            Command::Import { files, network, .. } => {
                assert_eq!(files, vec!["office.conf", "home.conf", "-"]);
                assert!(network.is_none());
            }
            _ => panic!("wrong subcommand"),
        }
    }

    #[test]
    fn import_requires_at_least_one_file() {
        assert!(Cli::try_parse_from(["fp", "import", "--network", "net-1"]).is_err());
    }
}
