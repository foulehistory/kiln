//! Userspace half of chantier 4's network observability MVP: loads the
//! `kiln-net-bpf` TC programs onto a container's host-side veth and reads
//! back the flow events they emit. Purely observational and strictly
//! opt-in - nothing here runs unless something explicitly asks to
//! observe a container (`kiln network inspect --live`, or a dashboard
//! WebSocket connection via `kilnd`), and `attach_container` in
//! `network.rs` never calls into this module. A bug here can make
//! observability fail; it can't break a container's actual networking.
//!
//! The compiled eBPF object is checked into `kiln-net-bpf/dist/` rather
//! than built as part of this crate: it targets `bpfel-unknown-none`
//! with `-Z build-std=core` on nightly, which the rest of this (stable,
//! std) workspace can't compile. Run `kiln-net-bpf/build.sh` and commit
//! the result after changing `kiln-net-bpf/src/main.rs`.

use crate::error::{Error, Result};
use crate::network::veth_host_name;
use aya::maps::RingBuf;
use aya::programs::tc;
use aya::programs::{SchedClassifier, TcAttachType};
use aya::Ebpf;
use std::net::Ipv4Addr;

static PROGRAM_BYTES: &[u8] = include_bytes!("../../kiln-net-bpf/dist/kiln-net-bpf.o");

/// One observed packet - a straight readback of `kiln-net-bpf`'s
/// `FlowEvent`, minus the raw-integer addresses (turned into `Ipv4Addr`
/// here since every consumer wants them printable, not the bit layout).
#[derive(Debug, Clone, Copy)]
pub struct FlowEvent {
    /// `false` = observed on the veth's ingress hook (traffic *from* the
    /// container), `true` = egress hook (traffic *to* the container).
    pub to_container: bool,
    /// `6` (TCP) or `17` (UDP) - `kiln-net-bpf` never emits anything else.
    pub protocol: u8,
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub len: u16,
}

// Mirrors kiln-net-bpf's `FlowEvent` byte-for-byte - this module owns
// converting the raw kernel-struct layout into the friendlier public
// `FlowEvent` above, so nothing outside this file needs to know the wire
// layout ever matched some other crate's repr(C) struct.
#[repr(C)]
struct RawFlowEvent {
    direction: u8,
    protocol: u8,
    _pad: [u8; 2],
    src_addr: u32,
    dst_addr: u32,
    src_port: u16,
    dst_port: u16,
    len: u16,
}

/// Attaches `kiln-net-bpf`'s TC programs to a container's host-side veth
/// for as long as the returned `FlowObserver` stays alive - dropping it
/// unloads the eBPF programs and detaches them, leaving the veth exactly
/// as `attach_container` set it up. Fails harmlessly (a plain `Error`,
/// nothing kernel-resident left behind) if the container has no network
/// attached, the eBPF object fails to verify, or the caller lacks the
/// (already-required-for-`kiln run`) root/CAP_NET_ADMIN it needs.
pub struct FlowObserver {
    ebpf: Ebpf,
}

impl FlowObserver {
    pub fn attach(container_id: &str) -> Result<Self> {
        let iface = veth_host_name(container_id);
        if !crate::network::bridge_exists(&iface) {
            return Err(Error::InvalidArgument(format!("no network attached to container {container_id}")));
        }

        // Idempotent: a container observed a second time (e.g. `kiln
        // network inspect --live` run twice) just finds the clsact qdisc
        // already there.
        let _ = tc::qdisc_add_clsact(&iface);

        let mut ebpf = Ebpf::load(PROGRAM_BYTES).map_err(|e| Error::InvalidArgument(format!("loading kiln-net-bpf: {e}")))?;

        attach_classifier(&mut ebpf, "flow_ingress", &iface, TcAttachType::Ingress)?;
        attach_classifier(&mut ebpf, "flow_egress", &iface, TcAttachType::Egress)?;

        Ok(FlowObserver { ebpf })
    }

    /// Non-blocking: returns whatever events have accumulated in the ring
    /// buffer since the last call (possibly none). Callers own their own
    /// polling cadence - `kiln network inspect --live` sleeps between
    /// calls in a loop, `kilnd`'s WebSocket handler does the same on its
    /// connection's own thread.
    pub fn drain(&mut self) -> Vec<FlowEvent> {
        let Ok(ring) = self.ebpf.map_mut("EVENTS").map(RingBuf::try_from).transpose() else {
            return Vec::new();
        };
        let Some(mut ring) = ring else { return Vec::new() };
        let mut out = Vec::new();
        while let Some(item) = ring.next() {
            if item.len() < std::mem::size_of::<RawFlowEvent>() {
                continue;
            }
            // SAFETY: `kiln-net-bpf` only ever submits exactly
            // `size_of::<RawFlowEvent>()` bytes built from a real
            // `RawFlowEvent` (see its own `FlowEvent`, byte-for-byte
            // identical layout) - the length check above guards against
            // a stale/mismatched .o being loaded by mistake.
            let raw = unsafe { item.as_ptr().cast::<RawFlowEvent>().read_unaligned() };
            out.push(FlowEvent {
                to_container: raw.direction != 0,
                protocol: raw.protocol,
                src_addr: Ipv4Addr::from(raw.src_addr),
                dst_addr: Ipv4Addr::from(raw.dst_addr),
                src_port: raw.src_port,
                dst_port: raw.dst_port,
                len: raw.len,
            });
        }
        out
    }
}

fn attach_classifier(ebpf: &mut Ebpf, name: &str, iface: &str, attach_type: TcAttachType) -> Result<()> {
    let program: &mut SchedClassifier = ebpf
        .program_mut(name)
        .ok_or_else(|| Error::InvalidArgument(format!("kiln-net-bpf object has no program named {name}")))?
        .try_into()
        .map_err(|e| Error::InvalidArgument(format!("{name} is not a TC classifier: {e}")))?;
    program.load().map_err(|e| Error::InvalidArgument(format!("loading {name}: {e}")))?;
    program
        .attach(iface, attach_type)
        .map_err(|e| Error::InvalidArgument(format!("attaching {name} to {iface}: {e}")))?;
    Ok(())
}
