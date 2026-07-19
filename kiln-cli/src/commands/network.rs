//! `kiln network` - one Linux bridge plus an `iptables` MASQUERADE rule
//! per network, in the spirit of the project's own v1 scoping note: real
//! per-flow observability (`kiln network inspect` showing live traffic
//! without an external tool like `tcpdump`) is an eBPF-based v2 goal:
//! v1 is a classic bridge + NAT setup, same as this module.
//!
//! The actual bridge/veth mechanism lives in `kilnd_core::network` (see
//! its own module docs for why: `kiln-image`'s build-time `RUN` steps
//! need it too, and can't depend on this crate). This module is the CLI
//! surface on top of it - argument parsing, `Store`-based paths, and
//! `kiln run --network`'s port publishing (which has nothing to do with
//! bridge attachment itself, so it stays here rather than moving down).

use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
pub use kilnd_core::network::NetworkConfig;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    Create {
        name: String,
        #[arg(long, default_value = "172.30.0.0/24")]
        subnet: String,
    },
    Ls,
    Inspect {
        name: String,
    },
    Rm {
        name: String,
    },
    /// Remove every network not currently attached to any container
    Prune,
}

fn networks_dir(store: &Store) -> std::path::PathBuf {
    store.root().join("networks")
}

pub fn run(store: &Store, cmd: Command) -> CliResult {
    match cmd {
        Command::Create { name, subnet } => {
            if NetworkConfig::load(store.root(), &name).is_some() {
                return Err(CliError::msg(format!("network {name} already exists")));
            }
            kilnd_core::network::ensure_network(store.root(), &name, &subnet)?;
            println!("{name}");
        }
        Command::Ls => {
            println!("{:<16}{:<16}{:<18}GATEWAY", "NAME", "BRIDGE", "SUBNET");
            if let Ok(entries) = std::fs::read_dir(networks_dir(store)) {
                for entry in entries.flatten() {
                    let Some(stem) = entry.path().file_stem().map(|s| s.to_string_lossy().into_owned()) else {
                        continue;
                    };
                    if let Some(cfg) = NetworkConfig::load(store.root(), &stem) {
                        println!("{:<16}{:<16}{:<18}{}", cfg.name, cfg.bridge, cfg.subnet, cfg.gateway);
                    }
                }
            }
        }
        Command::Inspect { name } => {
            let cfg = NetworkConfig::load(store.root(), &name).ok_or_else(|| CliError::msg(format!("no such network: {name}")))?;
            println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
        }
        Command::Rm { name } => {
            kilnd_core::network::remove_network(store.root(), &name)?;
            println!("{name}");
        }
        Command::Prune => {
            let referenced: std::collections::HashSet<String> =
                crate::container::Container::list(store).iter().filter_map(|c| c.network.clone()).collect();
            let mut any = false;
            if let Ok(entries) = std::fs::read_dir(networks_dir(store)) {
                for entry in entries.flatten() {
                    let Some(stem) = entry.path().file_stem().map(|s| s.to_string_lossy().into_owned()) else { continue };
                    if !referenced.contains(&stem) && kilnd_core::network::remove_network(store.root(), &stem).is_ok() {
                        println!("{stem}");
                        any = true;
                    }
                }
            }
            if !any {
                println!("nothing to prune");
            }
        }
    }
    Ok(())
}

/// Attach the container at `pid` to `network` - see
/// `kilnd_core::network::attach_container` for the actual mechanism;
/// this is just that plus `Store`-based path resolution.
pub fn attach_container(store: &Store, network: &str, container_id: &str, pid: i32) -> CliResult<String> {
    Ok(kilnd_core::network::attach_container(store.root(), network, container_id, pid)?)
}

/// A parsed `-p`/`--publish` spec: `<host-port>:<container-port>[/tcp|udp]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub host_port: u16,
    pub container_port: u16,
    pub proto: String,
}

impl PortSpec {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (ports, proto) = match s.split_once('/') {
            Some((p, proto)) => (p, proto.to_string()),
            None => (s, "tcp".to_string()),
        };
        let (host, container) =
            ports.split_once(':').ok_or_else(|| format!("invalid port spec {s:?}: expected <host>:<container>[/tcp|udp]"))?;
        let host_port: u16 = host.parse().map_err(|_| format!("invalid host port in {s:?}"))?;
        let container_port: u16 = container.parse().map_err(|_| format!("invalid container port in {s:?}"))?;
        if proto != "tcp" && proto != "udp" {
            return Err(format!("invalid protocol in {s:?}: expected tcp or udp"));
        }
        Ok(PortSpec { host_port, container_port, proto })
    }
}

/// Publish `port` by relaying plain TCP: bind `0.0.0.0:<host_port>` and,
/// for each accepted connection, open a new connection to
/// `container_ip:<container_port>` and pump bytes both ways.
///
/// This is deliberately *not* `iptables` DNAT, despite that being the
/// obvious first approach (and the one this code originally shipped with).
/// DNAT-ing a *locally-originated* connection to `127.0.0.1:<host_port>`
/// back out to a different real interface needs `route_localnet` tuned
/// correctly, a second routing lookup via `ip_route_me_harder`, and still
/// wasn't reliably reachable in this exact environment even with all of
/// that - and a locally-originated loopback connection is precisely what
/// matters here, since WSL2's own Windows<->Linux localhost forwarding is
/// itself a connection made from inside the VM. A plain relay sidesteps
/// the whole class of hairpin-NAT edge cases and needs no extra binary
/// (no `socat`) - just `std::net`.
///
/// Runs for as long as the calling process does. The one caller
/// (`commands::run::start`'s `post_spawn` hook) always runs this from
/// *inside* the per-container supervisor process (see `supervisor.rs`),
/// which lives for exactly the container's lifetime and no longer - so
/// the relay's listener and any in-flight connections are cleaned up for
/// free when that process exits, no explicit unpublish step needed.
pub fn spawn_port_forwarder(port: &PortSpec, container_ip: String) -> CliResult<()> {
    if port.proto != "tcp" {
        return Err(CliError::msg(format!("publishing a {} port is not supported yet (tcp only)", port.proto)));
    }
    let listener = std::net::TcpListener::bind(("0.0.0.0", port.host_port))
        .map_err(|e| CliError::msg(format!("binding host port {}: {e}", port.host_port)))?;
    let target = format!("{container_ip}:{}", port.container_port);

    std::thread::spawn(move || {
        for incoming in listener.incoming() {
            let Ok(client) = incoming else { continue };
            let target = target.clone();
            std::thread::spawn(move || {
                let Ok(upstream) = std::net::TcpStream::connect(&target) else { return };
                let _ = client.set_nodelay(true);
                let _ = upstream.set_nodelay(true);
                let (Ok(mut c1), Ok(mut u1)) = (client.try_clone(), upstream.try_clone()) else { return };
                let pump_in = std::thread::spawn(move || {
                    let _ = std::io::copy(&mut c1, &mut u1);
                    // `u1` is a dup'd fd sharing the same socket as `u2`
                    // below (still in use for the other direction), so
                    // just dropping it here sends no FIN - the upstream
                    // (the container's own service) would never see the
                    // client go away, leaving its side of the connection
                    // stuck open forever. An explicit half-close is what
                    // actually propagates "no more data is coming from
                    // the client" to it.
                    let _ = u1.shutdown(std::net::Shutdown::Write);
                });
                let mut c2 = client;
                let mut u2 = upstream;
                let _ = std::io::copy(&mut u2, &mut c2);
                // Same reasoning in the other direction: once the
                // upstream has no more data to send, tell the original
                // client so, instead of leaving its read half hanging.
                let _ = c2.shutdown(std::net::Shutdown::Write);
                let _ = pump_in.join();
            });
        }
    });
    Ok(())
}
