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

## Seccomp — implemented (default-deny allow-list)

Every container Kiln creates (`kiln run`, and Kilfile `RUN` steps) gets a
seccomp-bpf filter by default (`kilnd_core::security::apply_seccomp`,
built with the [`seccompiler`](https://github.com/rust-vmm/seccompiler)
crate - chosen over `libseccomp-rs` specifically to avoid adding a C
system library dependency, and over hand-rolled BPF for the lower bug
surface on a security-critical mechanism). Installed as the very last
step before `execve`, after every mount/`pivot_root` operation Kiln's
own init code still needs (`kilnd_core::security`'s own module docs
explain why the ordering matters).

This is a default-deny allow-list, not a curated deny-list: any syscall
not explicitly allowed returns `EPERM` (matching Docker's own default
profile's choice - most programs handle an error more gracefully than
being killed by `SIGSYS`). The allow-list itself
(`kilnd_core::security::unconditionally_allowed_syscalls`/
`conditionally_allowed_groups`) is sourced directly from Docker's own
default seccomp profile - fetched and translated rather than
hand-guessed - split into syscalls every container may always call, and
ones only allowed if the container's effective capability set (baseline
plus any `cap_add`) actually includes the capability Docker's own
profile gates them behind (so e.g. `--cap-add SYS_PTRACE` also unlocks
the syscalls that capability is actually for, not just the capability
bookkeeping). `clone`'s namespace-creation flags are masked out unless
`CAP_SYS_ADMIN` is present, and `clone3` is deliberately made to fail
with `ENOSYS` (not `EPERM`) without it, so glibc's own `clone3`-then-
legacy-`clone` fallback engages correctly instead of hard-failing -
found and fixed via a real regression: the mysql-demo reference stack's
`mysqld` failed to start ("Can't create thread") until this was in
place.

Opt-out: `kiln run --security-opt seccomp=unconfined`, or
`security_opt: [seccomp:unconfined]` per service in `kiln.yaml` - never
the default.

Verified by `kiln-cli/tests/security_seccomp_caps.rs`: the three
existing tests (mount blocked, `CAP_SYS_ADMIN` excluded/restorable) still
pass unchanged, plus a new test proving the allow-list doesn't
accidentally block ordinary file/process/network operations - and, in
practice, by restarting both reference stacks (mysql-demo,
palworld-test) fresh under the new profile and confirming they still
come up and pass their own functional checks.

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

## `kiln-registry` — native TLS (opt-in)

`kiln-registry serve --tls-cert <path> --tls-key <path>` (or
`$KILN_REGISTRY_TLS_CERT`/`$KILN_REGISTRY_TLS_KEY`) terminates TLS
itself, using [`rustls`](https://docs.rs/rustls) - pure Rust, no system
OpenSSL dependency, the same reasoning already applied to `seccompiler`
over `libseccomp-rs` elsewhere in this project. Both flags are required
together; omitting both is unchanged plain HTTP, still the default.
This is now an alternative to (not a replacement for) running behind a
TLS-terminating reverse proxy - either is fine; nothing requires native
TLS specifically.

The TLS-handling code (`kiln-registry/src/tls.rs`) is deliberately local
to this crate rather than a new variant on `kilnd_core::conn::Conn` -
that type is shared with `kilnd`, which has no need for TLS at all (see
its own loopback-only section above), so keeping the `rustls` dependency
and the connection-handling changes confined to `kiln-registry` avoids
pulling a TLS stack into a binary that has no use for one.

As before, `kiln-image`'s client already defaults to HTTPS for any
registry host that isn't `localhost`/`127.0.0.1`, so pointing it at a
`kiln-registry` instance with TLS enabled needs no client-side changes -
same as it always required a certificate a client actually trusts (a
real CA-issued one, or a private CA a client is separately configured to
trust); self-signed certificates are rejected by design, not a bug.

## `kiln-registry` — orphaned-blob garbage collection

`kiln-registry gc [--dry-run]` deletes blobs under `blobs/sha256/` no
longer referenced by any stored manifest's `config`/`layers` - the
registry-side equivalent of `kiln gc`'s local-store mark-and-sweep (see
`kiln-registry/src/gc.rs`'s own docs on how the two differ). Server-CLI-only,
like account/role management above - there is no HTTP endpoint for it,
so it can't be triggered remotely by any account regardless of role.
`--dry-run` reports exactly what a real run would remove without
deleting anything, worth having specifically because a shared,
multi-tenant registry's blobs are costlier to lose by mistake than a
single local dev store's.

## Security visibility — implemented

`kiln inspect <container> --security` shows a container's *effective*
capability set (baseline plus `cap_add`, minus `cap_drop`, resolved to
concrete names - not just the raw overrides `kiln inspect` alone already
showed) and its seccomp status, cross-checked against the real,
host-observed capability bounding set read live from
`/proc/<pid>/status` for a still-running container
(`kilnd_core::security::read_capability_bounding_set`/
`decode_capability_set`). The same report is exposed over `kilnd`'s API
(`GET /containers/:id/security`) and shown as a compact indicator in the
dashboard's container detail view.

## Resource limits (cgroups v2) — implemented

`--memory`/`--cpus`/`--memory-swap` (`kiln run`) and a `resources:` block
(`kiln.yaml`) apply real, kernel-enforced cgroups v2 limits per
container: `cpu.max` (CPU time), `memory.max` (a hard cap - once
exceeded with nothing left to reclaim, the kernel's OOM killer, not
Kiln, ends the offending process) and `memory.swap.max` (defaults to `0`
whenever a memory limit is set, so the limit can't be quietly evaded by
swapping cold anonymous pages instead of being enforced - see
`kilnd_core::cgroups::Limits::memory_swap_max_bytes`'s own docs). A
derived `memory.high` (~90% of `memory.max`) throttles/reclaims
aggressively as a soft warning before the hard cap is actually hit,
without invoking the OOM killer itself. None of this is opt-in-required
for isolation the way seccomp/capabilities are - a container given no
limits at all behaves exactly as before (unlimited), so this only
narrows what a container already inside the sandbox can do to the host,
it doesn't widen it.

An OOM-kill is told apart from any other reason a container's process
received `SIGKILL` (`kiln stop`'s fallback, `kiln rm -f`) via the
cgroup's own `memory.events`'s `oom_kill` counter, logged explicitly to
the container's own log (visible via `kiln logs`, not just `dmesg`) and
recorded on its persisted state. `kiln inspect --resources` (and
`kilnd`'s matching `GET /containers/:id/resources`, shown in the
dashboard's container detail view as a limit/usage bar) reports
configured limits against live cgroup usage - the same visibility
precedent as `--security` above.

## Not yet done

Nothing currently tracked here - the three items previously listed
(seccomp as an allow-list, security visibility, and cgroups resource
limits) are all done; see the sections above.
