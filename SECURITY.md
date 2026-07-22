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

## Seccomp — implemented (curated deny-list, not a full allow-list)

Every container Kiln creates (`kiln run`, and Kilfile `RUN` steps) gets a
seccomp-bpf filter by default (`kilnd_core::security::apply_seccomp`,
built with the [`seccompiler`](https://github.com/rust-vmm/seccompiler)
crate - chosen over `libseccomp-rs` specifically to avoid adding a C
system library dependency, and over hand-rolled BPF for the lower bug
surface on a security-critical mechanism). Installed as the very last
step before `execve`, after every mount/`pivot_root` operation Kiln's
own init code still needs (`kilnd_core::security`'s own module docs
explain why the ordering matters).

Blocked syscalls return `EPERM` (matching Docker's own default profile's
choice - most programs handle an error more gracefully than being killed
by `SIGSYS`). The current list (`kilnd_core::security::denied_syscalls`)
covers `ptrace`, `mount`/`umount2`/`pivot_root`, `reboot`,
`kexec_load[_file]`, kernel module syscalls, `swapon`/`swapoff`,
`iopl`/`ioperm`, the keyring syscalls, `perf_event_open`, `bpf`,
`clock_settime`/`settimeofday`/`adjtimex`, `open_by_handle_at`,
`userfaultfd`, `unshare`/`setns`, `quotactl`, `syslog`, and
`lookup_dcookie`.

**Deliberate scope trade-off**: this is a curated deny-list of specific
dangerous/rarely-needed syscalls, not a full Docker-style allow-list of
the ~300 syscalls a container might legitimately need. A full allow-list
is more thorough (default-deny is a stronger security posture than
default-allow-with-exceptions) but requires real confidence that nothing
legitimate breaks across arbitrary workloads - substantially more work
than this pass took on. Revisiting this as a real allow-list is the
natural next step here.

Opt-out: `kiln run --security-opt seccomp=unconfined`, or
`security_opt: [seccomp:unconfined]` per service in `kiln.yaml` - never
the default.

## Linux capabilities — implemented (Docker's own default baseline)

Every container's capability *bounding set* is narrowed to the same 14
capabilities Docker grants by default (`CAP_CHOWN`, `CAP_DAC_OVERRIDE`,
`CAP_FOWNER`, `CAP_FSETID`, `CAP_KILL`, `CAP_SETGID`, `CAP_SETUID`,
`CAP_SETPCAP`, `CAP_NET_BIND_SERVICE`, `CAP_NET_RAW`, `CAP_SYS_CHROOT`,
`CAP_MKNOD`, `CAP_AUDIT_WRITE`, `CAP_SETFCAP` -
`kilnd_core::security::BASELINE_CAPABILITIES`), built with the pure-Rust
[`caps`](https://docs.rs/caps) crate. Everything else (`CAP_SYS_ADMIN`,
`CAP_SYS_PTRACE`, `CAP_NET_ADMIN`, `CAP_SYS_MODULE`, ...) is dropped from
the bounding set before `execve` - since every Kiln container becomes
uid 0 (in its own namespace) via `setresuid`, POSIX's "uid 0 gets its
permitted set from the bounding set on `execve`" rule is what actually
makes this the real, enforced ceiling on the container's command, not
just bookkeeping.

This is on top of, not instead of, the user-namespace protection
described above: even a capability in the baseline (e.g. `CAP_CHOWN`)
only has effect on resources visible from within the container's own
namespaces, for the reason already described there.

Opt-out (widening, never on by default): `kiln run --cap-add`/
`--cap-drop`, or `cap_add`/`cap_drop` per service in `kiln.yaml`.

Verified end-to-end by `kiln-cli/tests/security_seccomp_caps.rs`: a real
container's capability bounding set (read from the host via
`/proc/<pid>/status`) excludes `CAP_SYS_ADMIN` and includes the baseline
by default, `--cap-add` demonstrably restores a dropped capability, and
a real `mount(2)` call from inside a container fails with a
permission-denied-shaped error.

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
transport or trust mechanism. That now also includes triggering an
image *pull* on the remote node (for `build:` + `node:` + `image:`
services) and *stopping* a container there (`kiln-compose reschedule`,
and Ctrl-C during a foreground `up`) — both already covered by "full
access to that `kilnd`'s entire API" above, not new capabilities the
token didn't already imply.

Cross-host service discovery (a `node:`-tagged dependency resolving to
its node's own host address via `/etc/hosts` - see `kiln-compose`'s own
module docs) means a container can see which real network address
another node lives at. Not a new disclosure in practice - reaching that
dependency at all already requires knowing that address - but worth
naming: an operator relying on nodes' addresses themselves being secret
(rather than just the remote token) shouldn't put `node:`-tagged
services under containers that shouldn't see that.

## `kiln-registry` — per-account roles, reads now require authentication

Every account has one of three roles (`kiln-registry user add --role`/
`user set-role`, server-CLI-only - there is no HTTP endpoint for account
or role management, and no self-registration):

- **`push`** (the default, including for every account that existed
  before roles did): push to and pull from `<own-username>/*` only -
  exactly what every account could already do.
- **`pull`**: pull any repository once authenticated, but can never
  obtain a push token for *any* repository, including their own.
- **`admin`**: push to any repository, not just their own namespace.

This is a real, deliberate widening of what "authenticated" means here,
not an incidental side effect: before this, `GET`/`HEAD` on blobs and
manifests were always public - no token checked at all. Every read now
requires a Bearer token from `/token`, and `/token` itself now requires
valid `Authorization: Basic` credentials for *any* scope, including a
bare `pull` - an anonymous request that used to succeed now gets a 401.
Operationally, this means `KILN_REGISTRY_USER`/`KILN_REGISTRY_PASS` (or
the equivalent for whatever's calling `kiln-image`'s registry client)
must be set wherever a pull against a self-hosted `kiln-registry`
happens, the same requirement chantier 3's remote-node pulls already
depended on.

`GET /users/:username/pubkey` (used during signature verification on
pull) is the one read endpoint that isn't keyed by an exact repository -
it accepts any unexpired pull token for *some* repository under that
username's namespace, which is exactly the one token the existing pull
client already reuses for this lookup, so no client-side changes were
needed to keep signature verification working under the new gate.

## Not yet done

- **Seccomp as a full allow-list** — the current deny-list (see above)
  blocks specific known-dangerous syscalls; a Docker-style default-deny
  allow-list of the ~300 syscalls ordinary containers actually need
  would be a strictly stronger posture, at the cost of real work
  enumerating one with confidence.
- **Visibility** — `kiln inspect --security` (or a section of the
  existing `kiln inspect`) showing the effective seccomp/capability
  profile a running container actually got, the same data exposed over
  `kilnd`'s API, and a dashboard indicator. Now that seccomp and
  capabilities are real, there's something true to show - this just
  hasn't been built yet.
