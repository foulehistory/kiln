# Kiln — security posture

An honest, current snapshot of what Kiln actually isolates today versus
what it doesn't yet. This file is meant to be kept in sync with the code
as security work lands — if it ever contradicts the code, the code wins
and this file is out of date.

## User namespaces — implemented

Every container Kiln creates (`kiln run`, and Kilnfile `RUN` steps during
a build) is `clone(2)`'d with `CLONE_NEWUSER` by default
(`kilnd-core/src/namespaces.rs`, `Namespaces::all()`). The container
process sees itself as `uid 0` inside its own namespace, but the host
kernel enforces permissions against a real, dedicated, unprivileged
UID/GID — never against `0`.

Every container uses the same fixed subordinate range,
`kiln_image::identity::SUBORDINATE_UID_BASE`/`SUBORDINATE_GID_BASE`
(`100_000`, matching the conventional first `/etc/subuid`/`/etc/subgid`
block), spanning `SUBORDINATE_RANGE` (`65_536`) IDs. One shared range
rather than one per container is deliberate: layers are content-addressed
and shared across images and containers, and file ownership recorded in
a layer is container-relative — a single fixed host range is what lets
any container correctly interpret any layer's ownership without
re-`chown`ing shared blobs per container (see `kiln-image/src/identity.rs`
for the full reasoning).

Verified by two tests:
- `kilnd-core/tests/namespace_isolation.rs::child_is_isolated_and_uid_is_remapped` —
  the low-level `clone`/uid-map mechanism itself.
- `kiln-cli/tests/security_namespaces.rs::kiln_run_remaps_a_real_container_to_the_subordinate_id_range` —
  a real container started via `kiln_cli::commands::run::start` (the same
  path `kiln run` itself uses), inspected from the host: its real UID/GID
  must fall in the subordinate range and must never be `0`.

## Seccomp — not implemented

No seccomp filter is applied to container processes. Every syscall
available inside the container's own namespaces is reachable — nothing
narrows that down. This is the single biggest gap versus Docker/runc's
own default seccomp profile, which blocks a well-known set of
rarely-needed, higher-risk syscalls (`ptrace`, arbitrary `mount`,
`reboot`, `kexec_load`, kernel module manipulation, etc.) even for an
already-unprivileged process.

## Linux capabilities — no active restriction

Nothing drops or restricts the container process's capability set. What
protection exists comes entirely as a side effect of the user namespace
itself: capabilities a process holds inside a *non-initial* user
namespace only have effect on resources visible from within that
namespace (its own mounts, its own network namespace, etc.) — they don't
translate into privilege over the host. That's a real, meaningful
property, but it is not the same thing as an active allow-list of
capabilities the way Docker's default (`CAP_CHOWN`, `CAP_DAC_OVERRIDE`,
`CAP_NET_BIND_SERVICE`, and a short list of others, everything else
dropped) is. No capability-dropping code exists anywhere in this
workspace today.

## Other isolation already in place

- **Network**: each container gets its own network namespace
  (`CLONE_NEWNET`), starting with only a loopback interface. Reaching the
  outside world requires an explicit bridge attach
  (`kilnd-core/src/network.rs`) — nothing is shared with the host's own
  network stack by default.
- **Devices**: the kernel's own `MS_NODEV` rule (enforced on any mount
  performed by a process without `CAP_SYS_ADMIN` in the *initial* user
  namespace — which a rootless container process, by definition, never
  has) makes device nodes baked into an image layer permanently inert.
  Kiln bind-mounts a small fixed set of already-functional host devices
  (`null`, `zero`, `full`, `random`, `urandom`, `tty`) in explicitly
  rather than relying on in-image device nodes working
  (`kilnd_core::rootfs::bind_mount_host_devices`).
- **Mount namespace**: `CLONE_NEWNS` gives every container a private
  mount table — nothing mounted inside a container is visible on the
  host or in any other container, and vice versa.

## Remote `kilnd` (multi-host) — opt-in, token-authenticated

`kilnd` is loopback-only by default (see above) — nothing about that
changes. `kiln node`'s multi-host support (`kiln-compose`'s `node:`
field) needs *some* `kilnd` reachable from another machine, so it adds
one narrow, entirely opt-in exception: if `KILN_REMOTE_TOKEN` is set,
`kilnd` also binds a **second**, separate TCP port (`0.0.0.0`, default
`7868`, `KILN_REMOTE_PORT` to change it) — the existing loopback port
(`7867`) is completely unaffected, still no token required there.

Every request on the remote port must carry `Authorization: Bearer
<token>` matching `KILN_REMOTE_TOKEN` or gets a 401 before reaching any
handler. There's no per-request rate limiting or account system — one
shared token grants full access to that `kilnd`'s entire API (create
any container, read any container's logs, etc.), the same trust level
the loopback port already grants anyone reaching `127.0.0.1` on that
machine. Treat the token like a root credential: pass it out of band
(never in `kiln.yaml`, which is often checked into version control),
and run this over a network you already trust (a VPN, a private subnet)
rather than the open internet — there's no TLS here, so the token and
every request/response cross the wire in the clear.

`kiln-compose`'s own dispatch to a `node:`-tagged service reuses
exactly this same authenticated API — it does not add a second
transport or trust mechanism.

## Not yet done

- **Seccomp** — a default restrictive profile (Docker/runc-shaped:
  allow-list of syscalls needed for normal use, block the dangerous/
  rarely-needed rest), plus a way for a container to opt into a wider
  profile when it genuinely needs one. Needs a crate choice
  (`seccompiler` vs `libseccomp-rs` vs a hand-rolled BPF program) made
  deliberately, with trade-offs weighed, before implementation starts.
- **Capabilities** — a reduced default set (Docker-shaped baseline,
  adjusted to what Kiln's own real workloads need) plus a `--cap-add`
  escape hatch, informed by whatever the seccomp work above reveals
  about what containers actually call.
- **Visibility** — `kiln inspect --security` (or a section of the
  existing `kiln inspect`), the same data exposed over `kilnd`'s API,
  and a dashboard indicator — planned to land once seccomp and
  capabilities are real, so there's something true to show.
