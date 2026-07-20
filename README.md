# Kiln

A daemonless, rootless-by-default container runtime for Linux (via WSL2 on
Windows, or any Linux host). `kiln run` does its own `clone(2)`, cgroup,
and overlayfs work directly — no persistent background service required
to run a container, unlike Docker's dockerd.

> **Status**: pre-1.0, under active development. [SECURITY.md](SECURITY.md)
> is a living, honest account of what's actually isolated today versus
> what isn't yet — read it before relying on Kiln for anything
> multi-tenant or otherwise security-sensitive.

## Why

- **Rootless by default** — every container runs inside its own user
  namespace, mapped to an unprivileged UID/GID range on the host. A
  process that thinks it's root inside the container is never root on
  the host.
- **No daemon required** — `kiln run` is a single process that sets up
  namespaces/cgroups/mounts and execs your command directly. `kilnd`
  (a small HTTP daemon) exists only to back the [dashboard](#dashboard);
  the CLI never needs it.
- **Content-addressed images** — layers are deduplicated by content hash
  across every image in the store, not just within one image.

## Quickstart

Kiln targets Linux — on Windows, that means [WSL2](https://learn.microsoft.com/windows/wsl/install).

```sh
# Build from source (see "Building" below), or grab a release tarball
# from https://github.com/foulehistory/kiln/releases
tar -xzf kiln-linux-x86_64.tar.gz -C ~/.kiln
export PATH="$HOME/.kiln/bin:$PATH"

kiln run --rm busybox echo "hello from a rootless container"
```

Most people will find it easier to install the
[Kiln Dashboard](https://github.com/foulehistory/kiln-dashboard) instead —
an Electron app that detects/sets up WSL2 and Kiln for you, then gives you
a GUI on top of everything below (containers, images, volumes, networks,
secrets, an in-browser terminal, live network flow observability).

### Building from source

```sh
git clone https://github.com/foulehistory/kiln.git
cd kiln
cargo build --release -p kiln-cli -p kiln-compose -p kilnd
```

Requires a real Linux kernel (namespaces/cgroups v2/overlayfs) at
*runtime* — the build itself has no such requirement, but the resulting
binaries only work on Linux. `nix`, one of the workspace's core
dependencies, is Linux-only.

## What's here

This repository is a Cargo workspace:

| Crate | What it is |
|---|---|
| `kiln-cli` | The `kiln` CLI itself — `run`, `build`, `pull`/`push`, `exec`, `logs`, volumes, networks, secrets, image signing, vulnerability scanning. |
| `kiln-compose` | `kiln-compose`: multi-container orchestration from a `kiln.yaml` file, plus project-level `backup`/`restore`. |
| `kilnd` | An optional local HTTP daemon (loopback-only) that backs the dashboard — everything it does, the CLI can also do directly. |
| `kiln-image` | Image format, build engine, content-addressed layer store, registry client, signing, secrets, vulnerability scanning. |
| `kilnd-core` | Low-level primitives shared by the above: namespaces, cgroups v2, overlayfs, bridge networking, the hand-rolled HTTP server layer. |
| `kiln-registry` | A self-hosted OCI Distribution registry server, so you don't need a third-party registry account to `push`/`pull` between machines. |
| `kiln-net-bpf` | The eBPF half of live network flow observability (`kiln network inspect --live`) — a standalone, nightly-only crate; see its own `Cargo.toml` for why. |

## Features

- **Images**: build from a `Kilnfile` (a small, Dockerfile-shaped format),
  content-addressed storage with cross-image dedup, push/pull to any OCI
  Distribution registry or a self-hosted `kiln-registry`.
- **Signing**: `kiln key generate` + `kiln push` signs images (ed25519);
  `kiln pull` verifies by default against a registry-anchored public key.
- **Vulnerability scanning**: `kiln image scan` / `kiln push --scan`
  (Trivy-backed) — opt-in, never automatic.
- **Secrets**: `kiln secret create` — AES-256-GCM at rest, mounted into
  containers as tmpfs files, never exposed via `kiln inspect`.
- **Volumes & networks**: named persistent volumes with export/import;
  bridge networks with per-container IP allocation and port publishing.
- **Live network observability**: `kiln network inspect --live` streams
  real per-packet flow data (via `kiln-net-bpf`'s eBPF TC programs) —
  opt-in, attaches nothing to a container's normal lifecycle.
- **Backup/restore**: `kiln-compose backup`/`restore` archives a
  project's `kiln.yaml` and volume contents (never secret values — see
  `kiln-compose/src/backup.rs`'s own docs on why).

## Versioning

Pre-1.0: minor version bumps (`0.x.0`) may include breaking changes to
CLI flags, the `kilnd` HTTP API, or on-disk formats. Patch bumps
(`0.1.x`) never do. Once 1.0 ships, this project follows standard
[SemVer](https://semver.org/).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE)
