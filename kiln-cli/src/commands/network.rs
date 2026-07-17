//! `kiln network` - one Linux bridge plus an `iptables` MASQUERADE rule
//! per network, in the spirit of the project's own v1 scoping note: real
//! per-flow observability (`kiln network inspect` showing live traffic
//! without an external tool like `tcpdump`) is an eBPF-based v2 goal:
//! v1 is a classic bridge + NAT setup, same as this module.
//!
//! Container attachment (creating a veth pair, moving one end into the
//! container's net namespace, assigning it an IP) happens in
//! `commands::run` via `--network <name>`, using [`NetworkConfig`] and
//! [`attach_container`] from this module.

use crate::error::{CliError, CliResult};
use kiln_image::store::Store;
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::process::Command as ProcessCommand;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub name: String,
    pub bridge: String,
    pub subnet: String,
    pub gateway: String,
    /// Next free host-part octet to hand out, e.g. `3` once `.1`
    /// (gateway) and `.2` are taken. A monotonic counter, not a reclaiming
    /// pool - simple, and fine for a /24's worth of containers.
    pub next_host: u8,
}

fn networks_dir(store: &Store) -> PathBuf {
    store.root().join("networks")
}

fn config_path(store: &Store, name: &str) -> PathBuf {
    networks_dir(store).join(format!("{name}.json"))
}

impl NetworkConfig {
    pub fn load(store: &Store, name: &str) -> Option<Self> {
        store.read_json(&config_path(store, name)).ok()
    }

    pub fn save(&self, store: &Store) -> CliResult {
        store.write_json(&config_path(store, &self.name), self)?;
        Ok(())
    }

    fn subnet_prefix(&self) -> String {
        let net = self.subnet.split('/').next().unwrap_or("172.30.0.0");
        net.rsplit_once('.').map(|(p, _)| p.to_string()).unwrap_or_else(|| "172.30.0".to_string())
    }

    pub fn allocate_ip(&mut self) -> String {
        let ip = format!("{}.{}", self.subnet_prefix(), self.next_host);
        self.next_host = self.next_host.saturating_add(1);
        ip
    }
}

/// Bridge (and veth) names must fit `IFNAMSIZ` (16 bytes including the
/// NUL terminator); user-chosen network/container names can be
/// arbitrarily long, so both are derived through a short deterministic
/// hash rather than truncated (truncation risks silent collisions between
/// two long names sharing a prefix).
fn short_tag(s: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}

fn bridge_name(network_name: &str) -> String {
    format!("kb{}", short_tag(network_name))
}

fn subnet_gateway(subnet: &str) -> CliResult<String> {
    let net = subnet.split('/').next().ok_or_else(|| CliError::msg(format!("invalid subnet {subnet:?}")))?;
    let mut parts: Vec<&str> = net.split('.').collect();
    if parts.len() != 4 {
        return Err(CliError::msg(format!("invalid subnet {subnet:?}, expected a.b.c.d/nn")));
    }
    parts[3] = "1";
    Ok(parts.join("."))
}

fn run_cmd(program: &str, args: &[&str]) -> CliResult {
    let status = ProcessCommand::new(program)
        .args(args)
        .status()
        .map_err(|e| CliError::msg(format!("running {program} {args:?}: {e}")))?;
    if !status.success() {
        return Err(CliError::msg(format!("{program} {args:?} exited with {status}")));
    }
    Ok(())
}

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

/// The teardown half of `Create`: delete the bridge, the MASQUERADE rule,
/// and the stored config. Shared by `Rm` and `Prune` so they can't drift.
fn remove_network(store: &Store, name: &str) -> CliResult {
    let cfg = NetworkConfig::load(store, name).ok_or_else(|| CliError::msg(format!("no such network: {name}")))?;
    let _ = run_cmd("ip", &["link", "del", &cfg.bridge]);
    let _ = ProcessCommand::new("iptables")
        .args(["-t", "nat", "-D", "POSTROUTING", "-s", &cfg.subnet, "!", "-o", &cfg.bridge, "-j", "MASQUERADE"])
        .status();
    std::fs::remove_file(config_path(store, name))?;
    Ok(())
}

pub fn run(store: &Store, cmd: Command) -> CliResult {
    match cmd {
        Command::Create { name, subnet } => {
            if NetworkConfig::load(store, &name).is_some() {
                return Err(CliError::msg(format!("network {name} already exists")));
            }
            let bridge = bridge_name(&name);
            let gateway = subnet_gateway(&subnet)?;

            run_cmd("ip", &["link", "add", &bridge, "type", "bridge"])?;
            run_cmd("ip", &["link", "set", &bridge, "up"])?;
            run_cmd("ip", &["addr", "add", &format!("{gateway}/24"), "dev", &bridge])?;
            let _ = run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
            let _ = ProcessCommand::new("iptables")
                .args(["-t", "nat", "-A", "POSTROUTING", "-s", &subnet, "!", "-o", &bridge, "-j", "MASQUERADE"])
                .status();

            let config = NetworkConfig { name: name.clone(), bridge, subnet, gateway, next_host: 2 };
            std::fs::create_dir_all(networks_dir(store))?;
            config.save(store)?;
            println!("{name}");
        }
        Command::Ls => {
            println!("{:<16}{:<16}{:<18}GATEWAY", "NAME", "BRIDGE", "SUBNET");
            if let Ok(entries) = std::fs::read_dir(networks_dir(store)) {
                for entry in entries.flatten() {
                    let Some(stem) = entry.path().file_stem().map(|s| s.to_string_lossy().into_owned()) else {
                        continue;
                    };
                    if let Some(cfg) = NetworkConfig::load(store, &stem) {
                        println!("{:<16}{:<16}{:<18}{}", cfg.name, cfg.bridge, cfg.subnet, cfg.gateway);
                    }
                }
            }
        }
        Command::Inspect { name } => {
            let cfg = NetworkConfig::load(store, &name).ok_or_else(|| CliError::msg(format!("no such network: {name}")))?;
            println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
        }
        Command::Rm { name } => {
            remove_network(store, &name)?;
            println!("{name}");
        }
        Command::Prune => {
            let referenced: std::collections::HashSet<String> =
                crate::container::Container::list(store).iter().filter_map(|c| c.network.clone()).collect();
            let mut any = false;
            if let Ok(entries) = std::fs::read_dir(networks_dir(store)) {
                for entry in entries.flatten() {
                    let Some(stem) = entry.path().file_stem().map(|s| s.to_string_lossy().into_owned()) else { continue };
                    if !referenced.contains(&stem) && remove_network(store, &stem).is_ok() {
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

/// Attach the container at `pid` to `network`: a veth pair with one end
/// on the host bridge and the other moved into the container's own
/// network namespace, renamed to `eth0`, given the next free IP in the
/// network's subnet, and pointed at the bridge as its default route.
///
/// Must be called after the container's network namespace exists (i.e.
/// after `spawn_paused`) but works equally whether the container process
/// itself is still paused or already running - namespace membership, not
/// process state, is what matters here.
pub fn attach_container(store: &Store, network: &str, container_id: &str, pid: i32) -> CliResult<String> {
    let mut cfg = NetworkConfig::load(store, network).ok_or_else(|| CliError::msg(format!("no such network: {network}")))?;
    let ip = cfg.allocate_ip();
    cfg.save(store)?;

    let tag = short_tag(container_id);
    let veth_host = format!("kv{tag}");
    let veth_peer = format!("kp{tag}");
    let pid_s = pid.to_string();

    run_cmd("ip", &["link", "add", &veth_host, "type", "veth", "peer", "name", &veth_peer])?;
    run_cmd("ip", &["link", "set", &veth_host, "master", &cfg.bridge])?;
    run_cmd("ip", &["link", "set", &veth_host, "up"])?;
    run_cmd("ip", &["link", "set", &veth_peer, "netns", &pid_s])?;

    run_cmd("nsenter", &["-t", &pid_s, "-n", "ip", "link", "set", &veth_peer, "name", "eth0"])?;
    run_cmd("nsenter", &["-t", &pid_s, "-n", "ip", "addr", "add", &format!("{ip}/24"), "dev", "eth0"])?;
    run_cmd("nsenter", &["-t", &pid_s, "-n", "ip", "link", "set", "eth0", "up"])?;
    run_cmd("nsenter", &["-t", &pid_s, "-n", "ip", "link", "set", "lo", "up"])?;
    run_cmd("nsenter", &["-t", &pid_s, "-n", "ip", "route", "add", "default", "via", &cfg.gateway])?;

    Ok(ip)
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
