//! Bridge network primitives: creating a Linux bridge + `iptables`
//! MASQUERADE rule, and attaching a container's network namespace to one
//! via a veth pair.
//!
//! Lives here rather than in `kiln-cli` (where `kiln network`/`kiln run
//! --network` actually surface) so that `kiln-image`'s build-time `RUN`
//! steps can use the exact same mechanism without a circular crate
//! dependency: `kiln-cli` already depends on `kiln-image` (for
//! `Image`/`Store`), so `kiln-image` can never depend back on
//! `kiln-cli`. `kilnd-core` has no dependency on either, which is
//! exactly why `namespaces`/`rootfs`/`cgroups` already live here too.
//!
//! Operates on a plain store-root `&Path` rather than `kiln-image`'s own
//! `Store` type, for the same reason - this crate can't depend on
//! `kiln-image` either. Callers that already hold a `Store` just pass
//! `store.root()`.

use crate::error::{self, Error, Result};
use serde::{Deserialize, Serialize};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
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

fn networks_dir(store_root: &Path) -> PathBuf {
    store_root.join("networks")
}

fn config_path(store_root: &Path, name: &str) -> PathBuf {
    networks_dir(store_root).join(format!("{name}.json"))
}

impl NetworkConfig {
    pub fn load(store_root: &Path, name: &str) -> Option<Self> {
        let bytes = std::fs::read(config_path(store_root, name)).ok()?;
        serde_json::from_slice(&bytes).ok()
    }

    pub fn save(&self, store_root: &Path) -> Result<()> {
        std::fs::create_dir_all(networks_dir(store_root)).map_err(error::io(networks_dir(store_root)))?;
        let path = config_path(store_root, &self.name);
        let json = serde_json::to_vec_pretty(self).expect("NetworkConfig serialization cannot fail");
        std::fs::write(&path, json).map_err(error::io(path))
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
pub fn short_tag(s: &str) -> String {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    s.hash(&mut hasher);
    format!("{:08x}", hasher.finish() as u32)
}

pub fn bridge_name(network_name: &str) -> String {
    format!("kb{}", short_tag(network_name))
}

pub fn subnet_gateway(subnet: &str) -> Result<String> {
    let net = subnet
        .split('/')
        .next()
        .ok_or_else(|| Error::InvalidArgument(format!("invalid subnet {subnet:?}")))?;
    let mut parts: Vec<&str> = net.split('.').collect();
    if parts.len() != 4 {
        return Err(Error::InvalidArgument(format!("invalid subnet {subnet:?}, expected a.b.c.d/nn")));
    }
    parts[3] = "1";
    Ok(parts.join("."))
}

fn run_cmd(program: &str, args: &[&str]) -> Result<()> {
    let status = ProcessCommand::new(program)
        .args(args)
        .status()
        .map_err(|e| Error::InvalidArgument(format!("running {program} {args:?}: {e}")))?;
    if !status.success() {
        return Err(Error::InvalidArgument(format!("{program} {args:?} exited with {status}")));
    }
    Ok(())
}

/// Creates the bridge + MASQUERADE rule described by `cfg` - the actual
/// kernel-level setup, shared by a fresh network creation and
/// `attach_container`'s self-healing repair (see its own doc comment).
pub fn setup_bridge(cfg: &NetworkConfig) -> Result<()> {
    run_cmd("ip", &["link", "add", &cfg.bridge, "type", "bridge"])?;
    run_cmd("ip", &["link", "set", &cfg.bridge, "up"])?;
    run_cmd("ip", &["addr", "add", &format!("{}/24", cfg.gateway), "dev", &cfg.bridge])?;
    let _ = run_cmd("sysctl", &["-w", "net.ipv4.ip_forward=1"]);
    let _ = ProcessCommand::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            &cfg.subnet,
            "!",
            "-o",
            &cfg.bridge,
            "-j",
            "MASQUERADE",
        ])
        .status();
    Ok(())
}

/// Every registered network interface (bridges included) shows up under
/// `/sys/class/net/<name>` - cheaper and simpler than shelling out to `ip
/// link show` just to check existence.
pub fn bridge_exists(bridge: &str) -> bool {
    Path::new(&format!("/sys/class/net/{bridge}")).exists()
}

/// The teardown half of network creation: delete the bridge, the
/// MASQUERADE rule, and the stored config.
pub fn remove_network(store_root: &Path, name: &str) -> Result<()> {
    let cfg = NetworkConfig::load(store_root, name).ok_or_else(|| Error::InvalidArgument(format!("no such network: {name}")))?;
    let _ = run_cmd("ip", &["link", "del", &cfg.bridge]);
    let _ = ProcessCommand::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            &cfg.subnet,
            "!",
            "-o",
            &cfg.bridge,
            "-j",
            "MASQUERADE",
        ])
        .status();
    std::fs::remove_file(config_path(store_root, name)).map_err(error::io(config_path(store_root, name)))
}

/// Create network `name` if `store_root` doesn't already have a config
/// for it (does nothing, successfully, if it does) - the create-if-missing
/// half every caller that just wants "make sure this network exists"
/// (as opposed to `kiln network create`'s own CLI, which errors on an
/// existing name) actually wants.
pub fn ensure_network(store_root: &Path, name: &str, subnet: &str) -> Result<NetworkConfig> {
    if let Some(cfg) = NetworkConfig::load(store_root, name) {
        return Ok(cfg);
    }
    let bridge = bridge_name(name);
    let gateway = subnet_gateway(subnet)?;
    let config = NetworkConfig {
        name: name.to_string(),
        bridge: bridge.clone(),
        subnet: subnet.to_string(),
        gateway,
        next_host: 2,
    };
    // The bridge name is a deterministic hash of `name`, a real kernel
    // resource with no notion of which store asked for it - but "does
    // this network already exist" was only ever checked via *this*
    // store's own config file. Two different stores (kiln-build is
    // deliberately the same shared name across every store, but even a
    // fresh temp store in a test hits this) asking for the same name
    // both see no local config and would otherwise both try to `ip link
    // add` the identical bridge, and the second one fails outright with
    // "File exists" instead of just adopting what's already there.
    if !bridge_exists(&bridge) {
        setup_bridge(&config)?;
    }
    config.save(store_root)?;
    Ok(config)
}

/// The host-side veth name for a container, derived the exact same way
/// `attach_container` names it - lets callers (e.g. stats collection)
/// find a container's network interface without needing anything stored
/// on the container itself.
pub fn veth_host_name(container_id: &str) -> String {
    format!("kv{}", short_tag(container_id))
}

/// Cumulative (rx_bytes, tx_bytes) for a container's network traffic, read
/// from its host-side veth's kernel counters. The host-side end mirrors
/// exactly what the container's own `eth0` sees, so this needs no access
/// to the container's network namespace at all. Returns `None` if the
/// container has no network attached (interface doesn't exist) or the
/// counters can't be read.
pub fn veth_stats(container_id: &str) -> Option<(u64, u64)> {
    let name = veth_host_name(container_id);
    let base = format!("/sys/class/net/{name}/statistics");
    let rx = std::fs::read_to_string(format!("{base}/rx_bytes")).ok()?.trim().parse().ok()?;
    let tx = std::fs::read_to_string(format!("{base}/tx_bytes")).ok()?.trim().parse().ok()?;
    Some((rx, tx))
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
pub fn attach_container(store_root: &Path, network: &str, container_id: &str, pid: i32) -> Result<String> {
    let mut cfg = NetworkConfig::load(store_root, network).ok_or_else(|| Error::InvalidArgument(format!("no such network: {network}")))?;
    if !bridge_exists(&cfg.bridge) {
        // The network's config on disk can outlive its actual kernel
        // bridge - e.g. WSL2 (or the VM/host generally) restarting wipes
        // network interfaces and iptables rules, but not files under the
        // store. Without this check, every attach against such a network
        // failed with a cryptic "ip link set ... master <bridge>: Device
        // does not exist" instead of just transparently repairing itself.
        setup_bridge(&cfg)?;
    }
    let ip = cfg.allocate_ip();
    cfg.save(store_root)?;

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
