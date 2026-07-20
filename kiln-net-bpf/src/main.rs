//! `kiln-net-bpf`: the eBPF half of chantier 4's network observability
//! MVP. Two TC classifier programs (`flow_ingress`, `flow_egress`),
//! attached by `kilnd-core`'s loader to a container's *host-side* veth -
//! never to the container's own `eth0`, so this only ever needs
//! permissions kiln already has as host root, no entry into the
//! container's network namespace required.
//!
//! Deliberately narrow for this first pass: IPv4 + TCP/UDP only (no IPv6,
//! no other protocols - those just aren't reported, never crash or drop
//! the packet). Every event is a single packet's headers, not an
//! aggregated flow - `kilnd`'s userspace side does any aggregation.
//!
//! Not compiled as part of the normal workspace build: this crate targets
//! `bpfel-unknown-none` with `-Z build-std=core` on nightly, which is
//! incompatible with the rest of the (stable, std) workspace - see
//! `kilnd-core/src/netbpf.rs` for how the compiled object gets loaded.
#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_PIPE, macros::{classifier, map}, maps::RingBuf, programs::TcContext};
use network_types::{eth::{EthHdr, EtherType}, ip::{IpProto, Ipv4Hdr}, tcp::TcpHdr, udp::UdpHdr};

/// One packet's worth of observed header fields. `#[repr(C)]` and plain
/// integers only - this is read back on the userspace side via
/// `bytemuck`-style reinterpretation of the raw ring buffer bytes, so its
/// layout has to be exactly predictable, no padding surprises.
#[repr(C)]
pub struct FlowEvent {
    /// 0 = observed on the veth's ingress hook (i.e. traffic *from* the
    /// container), 1 = egress hook (traffic *to* the container). Recorded
    /// raw rather than pre-labeled "rx"/"tx" so userspace - which already
    /// knows which container a given veth belongs to - decides the
    /// human-facing wording.
    pub direction: u8,
    /// `IpProto::Tcp` (6) or `IpProto::Udp` (17); anything else is never
    /// emitted at all (see `handle` below).
    pub protocol: u8,
    pub _pad: [u8; 2],
    pub src_addr: u32,
    pub dst_addr: u32,
    pub src_port: u16,
    pub dst_port: u16,
    /// Total IPv4 packet length (header + payload), straight from the IP
    /// header's own length field - not the skb's on-wire length, which
    /// can include link-layer padding this shouldn't count.
    pub len: u16,
}

#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[classifier]
pub fn flow_ingress(ctx: TcContext) -> i32 {
    handle(ctx, 0)
}

#[classifier]
pub fn flow_egress(ctx: TcContext) -> i32 {
    handle(ctx, 1)
}

fn handle(ctx: TcContext, direction: u8) -> i32 {
    let _ = try_handle(&ctx, direction);
    TC_ACT_PIPE
}

/// Every load in here goes through `TcContext::load` (bounds-checked
/// against the verifier's own knowledge of packet length) rather than raw
/// pointer arithmetic - the eBPF verifier rejects the whole program at
/// load time otherwise, this isn't an optional safety nicety.
fn try_handle(ctx: &TcContext, direction: u8) -> Result<(), ()> {
    let eth: EthHdr = ctx.load(0).map_err(|_| ())?;
    if { eth.ether_type } != EtherType::Ipv4 {
        return Ok(());
    }

    let ip: Ipv4Hdr = ctx.load(EthHdr::LEN).map_err(|_| ())?;
    let protocol = match ip.proto {
        IpProto::Tcp | IpProto::Udp => ip.proto as u8,
        _ => return Ok(()),
    };

    let ihl = (ip.ihl() as usize) * 4;
    let (src_port, dst_port) = if ip.proto == IpProto::Tcp {
        let tcp: TcpHdr = ctx.load(EthHdr::LEN + ihl).map_err(|_| ())?;
        (u16::from_be(tcp.source), u16::from_be(tcp.dest))
    } else {
        let udp: UdpHdr = ctx.load(EthHdr::LEN + ihl).map_err(|_| ())?;
        (u16::from_be_bytes(udp.source), u16::from_be_bytes(udp.dest))
    };

    let Some(mut entry) = EVENTS.reserve::<FlowEvent>(0) else { return Ok(()) };
    let event = FlowEvent {
        direction,
        protocol,
        _pad: [0; 2],
        src_addr: u32::from_be_bytes(ip.src_addr),
        dst_addr: u32::from_be_bytes(ip.dst_addr),
        src_port,
        dst_port,
        len: u16::from_be_bytes(ip.tot_len),
    };
    unsafe { core::ptr::write(entry.as_mut_ptr(), event) };
    entry.submit(0);
    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[link_section = "license"]
#[used]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
