//! The Kilnfile build executor: turns a parsed Kilnfile plus a build
//! context directory into an [`Image`], reusing cached work wherever a
//! prior build already did the same thing.
//!
//! # The cache, precisely
//!
//! Every instruction advances a running **state hash**: a chain
//! `state[i] = H(state[i-1], instruction-kind, instruction-specific data)`,
//! seeded by `state[0] = H(FROM, resolved-base-image-id)`. After computing
//! `state[i]`, the builder checks whether `build-cache/<state[i]>.json`
//! already exists. If it does, the instruction is **skipped entirely** -
//! its recorded layer (if any) and resulting config are reused as-is. If
//! not, the instruction actually runs, and its result is recorded under
//! that key for next time.
//!
//! What counts as "instruction-specific data" - i.e. **exactly** what
//! invalidates a step and everything after it - is deliberately narrow and
//! is the whole point of documenting it here:
//!
//! - **`FROM <image>`**: the resolved base image's own content id. Any
//!   change to the base (a new build, a new pull) invalidates everything
//!   in this Kilnfile - unavoidable, since everything is built on top of it.
//! - **`ENV` / `WORKDIR` / `CMD` / `EXPOSE`**: the instruction's own
//!   literal text. These never touch the filesystem (no layer is
//!   produced), so caching them is just about skipping a config-mutation,
//!   but they still participate in the hash chain, so e.g. reordering two
//!   `ENV` lines *does* change every subsequent state hash - instruction
//!   order matters, exactly as it does for what config a later `RUN` sees.
//! - **`COPY <src> <dst>`**: `dst`, plus a hash of the **content** (not
//!   mtime, not permissions-of-the-containing-dir, just each copied file's
//!   bytes and its own mode) of everything under `<src>` in the build
//!   context. Touching a file *outside* `<src>` never invalidates a
//!   `COPY`, unlike naive mtime-based caching. This does **not** fix the
//!   classic Dockerfile trap of a single early `COPY . .` invalidating
//!   every layer after it whenever *anything* in the whole context
//!   changes - that trap is about instruction *ordering*, not the cache
//!   mechanism, and no cache implementation can fix an author copying
//!   everything before it's needed. Keep `COPY` instructions narrow
//!   (copy only the files a given step actually needs) and ordered from
//!   least- to most-frequently-changing to get real cache mileage.
//! - **`RUN <command>`**: the literal command string. Nothing about what
//!   the command actually *does* is inspected - if a `RUN` step is
//!   non-deterministic (fetches something that changes over time, embeds
//!   the current time, depends on host state), the cache will happily
//!   replay its old, stale result forever as long as the command text
//!   doesn't change. Kiln normalizes away the most common source of
//!   non-determinism itself (see `layer.rs`'s note on why `Entry` has no
//!   `mtime`), but it cannot make an inherently non-deterministic command
//!   deterministic. Bit-reproducibility across *machines* is only as good
//!   as the `RUN` commands in the Kilnfile.

use crate::error::{Error, Result};
use crate::identity;
use crate::image::{Image, ImageConfig};
use crate::kilnfile::{self, Instruction};
use crate::layer::{self, Entry, EntryKind, LayerManifest};
use crate::store::{Hash, Store};
use kilnd_core::namespaces::{spawn_paused, Spawn};
use kilnd_core::rootfs::{bind_mount_host_devices, bind_mount_host_resolv_conf, make_mounts_private, mount_overlay, mount_proc, pivot_root_into, OverlaySpec};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Every Kilnfile RUN step shares this one bridge network (created on
/// first use, reused after) rather than getting a per-build or
/// per-project one - build containers are transient and never need to be
/// reached *by* anything, only to reach *out*, so there's nothing a
/// dedicated network per build would buy that a single shared one
/// doesn't already provide more simply.
const BUILD_NETWORK_NAME: &str = "kiln-build";
const BUILD_NETWORK_SUBNET: &str = "172.31.0.0/24";

#[derive(Debug, Clone)]
pub struct StepResult {
    pub instruction: String,
    pub cached: bool,
}

#[derive(Debug, Clone)]
pub struct BuildOutput {
    pub image_id: Hash,
    pub steps: Vec<StepResult>,
}

pub fn build(store: &Store, context_dir: &Path, kilnfile_source: &str) -> Result<BuildOutput> {
    let mut instructions = kilnfile::parse(kilnfile_source)?.into_iter();

    let base_image = match instructions.next() {
        Some(Instruction::From { image }) => Image::resolve(store, &image)?,
        Some(_) => return Err(Error::Build("the first instruction of a Kilnfile must be FROM".into())),
        None => return Err(Error::Build("Kilnfile is empty".into())),
    };

    let mut layers = base_image.layers.clone();
    let mut config = base_image.config.clone();
    let mut state = chain(None, "FROM", base_image.id().to_hex().as_bytes());
    let mut steps = Vec::new();

    for instr in instructions {
        let label = describe(&instr);

        match instr {
            Instruction::From { .. } => {
                return Err(Error::Build("FROM may only appear as the first instruction".into()));
            }

            Instruction::Env { key, value } => {
                state = chain(Some(state), "ENV", format!("{key}\u{0}{value}").as_bytes());
                let cached = apply_cache_hit(store, &state, &mut layers, &mut config)?;
                if !cached {
                    config.env_set(key, value);
                    save_cache_entry(store, &state, None, &config)?;
                }
                steps.push(StepResult { instruction: label, cached });
            }

            Instruction::Workdir { path } => {
                state = chain(Some(state), "WORKDIR", path.as_bytes());
                let cached = apply_cache_hit(store, &state, &mut layers, &mut config)?;
                if !cached {
                    config.workdir = path;
                    save_cache_entry(store, &state, None, &config)?;
                }
                steps.push(StepResult { instruction: label, cached });
            }

            Instruction::Cmd { command } => {
                state = chain(Some(state), "CMD", command.as_bytes());
                let cached = apply_cache_hit(store, &state, &mut layers, &mut config)?;
                if !cached {
                    config.cmd = Some(command);
                    save_cache_entry(store, &state, None, &config)?;
                }
                steps.push(StepResult { instruction: label, cached });
            }

            Instruction::Expose { port, proto } => {
                state = chain(Some(state), "EXPOSE", format!("{port}/{proto}").as_bytes());
                let cached = apply_cache_hit(store, &state, &mut layers, &mut config)?;
                if !cached {
                    config.exposed_ports.push((port, proto));
                    save_cache_entry(store, &state, None, &config)?;
                }
                steps.push(StepResult { instruction: label, cached });
            }

            Instruction::Copy { src, dst } => {
                let content_hash = hash_context_paths(context_dir, &src)?;
                state = chain(Some(state), "COPY", format!("{dst}\u{0}{content_hash}").as_bytes());
                let cached = apply_cache_hit(store, &state, &mut layers, &mut config)?;
                if !cached {
                    let layer_id = execute_copy(store, context_dir, &src, &dst)?;
                    layers.push(layer_id);
                    save_cache_entry(store, &state, Some(layer_id), &config)?;
                }
                steps.push(StepResult { instruction: label, cached });
            }

            Instruction::Run { command } => {
                state = chain(Some(state), "RUN", command.as_bytes());
                let cached = apply_cache_hit(store, &state, &mut layers, &mut config)?;
                if !cached {
                    let layer_id = execute_run(store, &layers, &config, &command)?;
                    layers.push(layer_id);
                    save_cache_entry(store, &state, Some(layer_id), &config)?;
                }
                steps.push(StepResult { instruction: label, cached });
            }
        }
    }

    let image = Image { layers, config };
    let image_id = image.save(store)?;
    Ok(BuildOutput { image_id, steps })
}

fn describe(instr: &Instruction) -> String {
    match instr {
        Instruction::From { image } => format!("FROM {image}"),
        Instruction::Run { command } => format!("RUN {command}"),
        Instruction::Copy { src, dst } => format!("COPY {src} {dst}"),
        Instruction::Env { key, value } => format!("ENV {key}={value}"),
        Instruction::Cmd { command } => format!("CMD {command}"),
        Instruction::Expose { port, proto } => format!("EXPOSE {port}/{proto}"),
        Instruction::Workdir { path } => format!("WORKDIR {path}"),
    }
}

fn chain(prev: Option<Hash>, label: &str, payload: &[u8]) -> Hash {
    let mut buf = Vec::new();
    if let Some(p) = prev {
        buf.extend_from_slice(p.to_hex().as_bytes());
    }
    buf.push(0);
    buf.extend_from_slice(label.as_bytes());
    buf.push(0);
    buf.extend_from_slice(payload);
    Hash::of_bytes(&buf)
}

#[derive(serde::Serialize, serde::Deserialize)]
struct CacheEntry {
    layer: Option<Hash>,
    config: ImageConfig,
}

fn cache_path(store: &Store, state: &Hash) -> PathBuf {
    store.root().join("build-cache").join(format!("{state}.json"))
}

/// If `state` has a cached result, apply it (push the layer if there is
/// one, replace `config` with the cached config) and return `true`.
/// Otherwise leave `layers`/`config` untouched and return `false`.
fn apply_cache_hit(store: &Store, state: &Hash, layers: &mut Vec<Hash>, config: &mut ImageConfig) -> Result<bool> {
    let path = cache_path(store, state);
    if !path.is_file() {
        return Ok(false);
    }
    let entry: CacheEntry = store.read_json(&path)?;
    if let Some(layer_id) = entry.layer {
        layers.push(layer_id);
    }
    *config = entry.config;
    Ok(true)
}

fn save_cache_entry(store: &Store, state: &Hash, layer: Option<Hash>, config: &ImageConfig) -> Result<()> {
    let path = cache_path(store, state);
    store.write_json(&path, &CacheEntry { layer, config: config.clone() })
}

/// Hash the content (bytes + mode of every file, not mtimes, not anything
/// about files outside `src`) under `context_dir/src`, for use as a `COPY`
/// cache key. See the module docs for exactly what this does and doesn't
/// protect against.
fn hash_context_paths(context_dir: &Path, src: &str) -> Result<Hash> {
    let root = context_dir.join(src);
    let meta = fs::symlink_metadata(&root).map_err(Error::io(&root))?;
    let mut items: Vec<(String, u32, String)> = Vec::new();

    if meta.is_dir() {
        for dirent in walkdir::WalkDir::new(&root) {
            let dirent = dirent.map_err(|e| Error::Build(format!("walking {}: {e}", root.display())))?;
            let path = dirent.path();
            let rel = path.strip_prefix(&root).expect("walkdir yields paths under root");
            let m = fs::symlink_metadata(path).map_err(Error::io(path))?;
            let mode = m.permissions().mode() & 0o7777;
            let content = if m.is_file() {
                Hash::of_bytes(&fs::read(path).map_err(Error::io(path))?).to_hex()
            } else {
                String::new()
            };
            items.push((rel.to_string_lossy().replace('\\', "/"), mode, content));
        }
    } else {
        let mode = meta.permissions().mode() & 0o7777;
        let content = Hash::of_bytes(&fs::read(&root).map_err(Error::io(&root))?).to_hex();
        items.push((String::new(), mode, content));
    }

    items.sort();
    let json = serde_json::to_vec(&items).expect("serialization cannot fail");
    Ok(Hash::of_bytes(&json))
}

/// `COPY` needs no container at all: it's a pure host-side operation that
/// reads files from the build context and writes a new layer directly.
/// Copied files are owned by container-relative root (`0:0`) by default,
/// matching Docker's default `COPY` (without `--chown`) behavior.
fn execute_copy(store: &Store, context_dir: &Path, src: &str, dst: &str) -> Result<Hash> {
    let root = context_dir.join(src);
    let meta = fs::symlink_metadata(&root).map_err(Error::io(&root))?;
    let dst_clean = dst.trim_start_matches('/');
    let mut entries = Vec::new();

    if meta.is_dir() {
        for dirent in walkdir::WalkDir::new(&root).min_depth(1) {
            let dirent = dirent.map_err(|e| Error::Build(format!("walking {}: {e}", root.display())))?;
            let path = dirent.path();
            let rel = path.strip_prefix(&root).expect("walkdir yields paths under root");
            let rel_str = rel.to_string_lossy().replace('\\', "/");
            let entry_path = if dst_clean.is_empty() {
                rel_str
            } else {
                format!("{dst_clean}/{rel_str}")
            };

            let m = fs::symlink_metadata(path).map_err(Error::io(path))?;
            let mode = m.permissions().mode() & 0o7777;
            let kind = if m.file_type().is_dir() {
                EntryKind::Dir { opaque: false }
            } else if m.file_type().is_symlink() {
                let target = fs::read_link(path).map_err(Error::io(path))?;
                EntryKind::Symlink { target: target.to_string_lossy().replace('\\', "/") }
            } else {
                let blob = store.put_file(path)?;
                EntryKind::File { blob, size: m.len() }
            };
            entries.push(Entry { path: entry_path, mode, uid: 0, gid: 0, kind });
        }
    } else {
        let mode = meta.permissions().mode() & 0o7777;
        let blob = store.put_file(&root)?;
        entries.push(Entry {
            path: dst_clean.to_string(),
            mode,
            uid: 0,
            gid: 0,
            kind: EntryKind::File { blob, size: meta.len() },
        });
    }

    entries.sort();
    LayerManifest { entries }.save(store)
}

fn chown(path: &Path, uid: u32, gid: u32) -> Result<()> {
    nix::unistd::chown(path, Some(nix::unistd::Uid::from_raw(uid)), Some(nix::unistd::Gid::from_raw(gid)))
        .map_err(|e| Error::Build(format!("chown {}: {e}", path.display())))
}

/// A permanently-empty directory used as the sole overlayfs `lowerdir`
/// when a build step has no real layers yet (`FROM scratch` before any
/// `RUN`/`COPY`) - overlayfs requires at least one `lowerdir`.
fn empty_dir(store: &Store) -> Result<PathBuf> {
    let dir = store.root().join("empty");
    fs::create_dir_all(&dir).map_err(Error::io(&dir))?;
    Ok(dir)
}

/// Run `command` (shell form, via `/bin/sh -c`) in a real, isolated
/// container built from `layers` + `config`, and turn whatever it wrote
/// into the container's writable layer into a new [`LayerManifest`].
fn execute_run(store: &Store, layers: &[Hash], config: &ImageConfig, command: &str) -> Result<Hash> {
    let uid_base = identity::SUBORDINATE_UID_BASE;
    let gid_base = identity::SUBORDINATE_GID_BASE;

    let mut lower_dirs = Vec::new();
    for id in layers.iter().rev() {
        lower_dirs.push(layer::materialize_cached(store, id, uid_base, gid_base)?);
    }
    if lower_dirs.is_empty() {
        lower_dirs.push(empty_dir(store)?);
    }

    let build_tmp = store.root().join("build-tmp");
    fs::create_dir_all(&build_tmp).map_err(Error::io(&build_tmp))?;
    let step_dir = tempfile::Builder::new()
        .prefix("run-")
        .tempdir_in(&build_tmp)
        .map_err(Error::io(&build_tmp))?;

    let upper = step_dir.path().join("upper");
    let work = step_dir.path().join("work");
    let merged = step_dir.path().join("merged");
    for d in [&upper, &work, &merged] {
        fs::create_dir_all(d).map_err(Error::io(d))?;
        // These directories are created here, by the host-side build
        // process (real root), *before* the container exists. Inside the
        // container, "root" is a mapped identity (container uid 0 = host
        // uid `uid_base`, not host uid 0) - a user namespace's
        // capabilities only carry authority over resources whose on-disk
        // owner falls inside that namespace's own mapped range. Left
        // owned by real root, the container's mapped root is just an
        // unrecognized outside party as far as these directories are
        // concerned, reduced to "other" permissions - which is not enough
        // to write into an overlayfs upperdir. Chowning them into the
        // container's own mapped range first is what makes the overlay
        // mount actually writable from inside.
        chown(d, uid_base, gid_base)?;
    }

    let overlay = OverlaySpec {
        lower_dirs,
        upper_dir: upper.clone(),
        work_dir: work.clone(),
        merged_dir: merged.clone(),
    };

    let opts = Spawn {
        uid_map: identity::container_id_map(uid_base),
        gid_map: identity::container_id_map(gid_base),
        hostname: Some("kiln-build".to_string()),
        ..Spawn::default()
    };

    let env = config.env.clone();
    let workdir = if config.workdir.is_empty() { "/".to_string() } else { config.workdir.clone() };
    let command_owned = command.to_string();
    let merged_for_child = merged.clone();

    // Every RUN step gets real network access (a shared "kiln-build"
    // bridge, created on first use and reused after) - the same reasoning
    // as `kiln run`'s own `--network`, just always-on here rather than
    // opt-in: a Kilnfile RUN step that can't reach the network at all
    // can't do the single most common thing a build step does (apt-get,
    // pip install, curl a release tarball, ...), and unlike `kiln run`
    // there's no per-build flag to ask for it with.
    kilnd_core::network::ensure_network(store.root(), BUILD_NETWORK_NAME, BUILD_NETWORK_SUBNET).map_err(Error::Runtime)?;

    let pending = spawn_paused(&opts, move || -> kilnd_core::Result<()> {
        run_command_in_container(&merged_for_child, &overlay, &workdir, &env, &command_owned)
    })
    .map_err(Error::Runtime)?;
    let pid = pending.pid();
    // A build step's own container id isn't known this early (it's
    // derived from the *resulting* layer, computed only after this step
    // finishes) - the pid is already unique for exactly as long as this
    // attachment needs to be (this one RUN step), so it doubles as the
    // veth-naming tag `attach_container` needs.
    kilnd_core::network::attach_container(store.root(), BUILD_NETWORK_NAME, &pid.to_string(), pid.as_raw())
        .map_err(Error::Runtime)?;
    pending.release().map_err(Error::Runtime)?;

    let status = nix::sys::wait::waitpid(pid, None).map_err(|e| Error::Build(format!("waitpid: {e}")))?;
    match status {
        nix::sys::wait::WaitStatus::Exited(_, 0) => {}
        nix::sys::wait::WaitStatus::Exited(_, code) => {
            return Err(Error::Build(format!("RUN {command:?} exited with status {code}")));
        }
        other => {
            return Err(Error::Build(format!("RUN {command:?} did not exit cleanly: {other:?}")));
        }
    }

    let manifest = layer::snapshot_dir(&upper, store, uid_base, gid_base)?;
    manifest.save(store)
}

/// Runs inside the freshly-cloned container process: mount the rootfs,
/// pivot into it, and `execve` into `/bin/sh -c <command>`. Never returns
/// on success (the shell replaces this process); on failure returns the
/// error for `spawn_isolated`'s wrapper to report and exit(1) with.
fn run_command_in_container(
    merged: &Path,
    overlay: &OverlaySpec,
    workdir: &str,
    env: &[(String, String)],
    command: &str,
) -> kilnd_core::Result<()> {
    use kilnd_core::Error as RtError;

    // See kiln-cli/src/commands/run.rs::run_container_init for why this
    // must come before setresgid/setresuid: clone() never touches
    // supplementary groups, so without this the child keeps its parent's
    // real gid 0, which makes the kernel's DAC check use the (more
    // restrictive) group permission bits instead of "other" on any inode
    // owned by group 0 - e.g. `/root` - causing spurious EACCES.
    nix::unistd::setgroups(&[]).map_err(|e| RtError::InvalidArgument(format!("setgroups: {e}")))?;
    nix::unistd::setresgid(nix::unistd::Gid::from_raw(0), nix::unistd::Gid::from_raw(0), nix::unistd::Gid::from_raw(0))
        .map_err(|e| RtError::InvalidArgument(format!("setresgid: {e}")))?;
    nix::unistd::setresuid(nix::unistd::Uid::from_raw(0), nix::unistd::Uid::from_raw(0), nix::unistd::Uid::from_raw(0))
        .map_err(|e| RtError::InvalidArgument(format!("setresuid: {e}")))?;

    make_mounts_private()?;
    mount_overlay(overlay)?;
    bind_mount_host_devices(merged)?;
    bind_mount_host_resolv_conf(merged)?;
    pivot_root_into(merged)?;
    mount_proc(Path::new("/proc"))?;

    nix::unistd::chdir(workdir).map_err(|e| RtError::InvalidArgument(format!("chdir({workdir}): {e}")))?;

    for (k, v) in env {
        std::env::set_var(k, v);
    }

    let shell = std::ffi::CString::new("/bin/sh").unwrap();
    let dash_c = std::ffi::CString::new("-c").unwrap();
    let cmd_c = std::ffi::CString::new(command)
        .map_err(|e| RtError::InvalidArgument(format!("command contains a NUL byte: {e}")))?;

    // See the identical reset in kiln-cli's run_container_init: Rust's
    // runtime ignores SIGPIPE at startup, and that disposition survives
    // execve(2) unlike a handler function would - left alone, a RUN
    // step's shell pipeline would silently inherit kiln's own
    // SIGPIPE-ignored, not the default behavior it'd have running
    // natively.
    unsafe {
        nix::sys::signal::signal(nix::sys::signal::Signal::SIGPIPE, nix::sys::signal::SigHandler::SigDfl)
            .map_err(|e| RtError::InvalidArgument(format!("resetting SIGPIPE: {e}")))?;
    }

    // Always the full default profile - no per-instruction escape hatch
    // exists in the Kilfile format today (see kilnd_core::security's own
    // docs on this scope choice). Same ordering constraint as
    // kiln-cli::commands::run::run_container_init: after every
    // mount/pivot_root above (still need CAP_SYS_ADMIN), seccomp last.
    let security = kilnd_core::security::SecurityProfile::default();
    kilnd_core::security::drop_capabilities(&security)?;
    kilnd_core::security::apply_seccomp(&security)?;

    nix::unistd::execv(&shell, &[shell.clone(), dash_c, cmd_c])
        .map_err(|e| RtError::InvalidArgument(format!("execv(/bin/sh): {e}")))?;
    unreachable!("execv only returns on error, which is handled above")
}
