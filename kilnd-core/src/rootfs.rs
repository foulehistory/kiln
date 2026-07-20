//! Root filesystem assembly: overlayfs layering + `pivot_root`.
//!
//! A container's root filesystem is built from read-only image layers
//! (`lowerdir`) stacked under a single writable layer private to that
//! container (`upperdir`/`workdir`), merged by the kernel's `overlay`
//! filesystem into one view (`merged_dir`). This is the same mechanism
//! Docker's `overlay2` graph driver uses; Kiln's own image layers
//! (`kiln-image`, phase 2) are just directories of files that get handed to
//! this module as `lowerdir` entries.
//!
//! Once mounted, [`pivot_root_into`] switches the *process's* root to that
//! merged view, so the container can no longer see the host filesystem at
//! all (as opposed to `chroot(2)`, which only changes the apparent root for
//! path resolution but leaves the old root reachable via `..` or already-open
//! file descriptors referencing it — `pivot_root` genuinely detaches it).

use crate::error::{self, Result};
use nix::mount::{mount, umount2, MntFlags, MsFlags};
use nix::unistd::chdir;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Paths making up one overlayfs mount.
pub struct OverlaySpec {
    /// Read-only layers, ordered **highest priority first** — the first
    /// entry wins when the same path exists in multiple layers. This
    /// matches `kiln-image`'s layer order (topmost applied layer first),
    /// which is the reverse of how `Kilnfile` instructions are usually
    /// read top-to-bottom.
    pub lower_dirs: Vec<PathBuf>,
    /// The container's writable layer. All file creates/modifications
    /// while the container runs land here, leaving the lower layers
    /// untouched — which is what lets many containers share the same
    /// image layers on disk.
    pub upper_dir: PathBuf,
    /// Scratch space overlayfs uses internally for atomic operations
    /// (renames, etc.). Must be on the same filesystem as `upper_dir`,
    /// must exist, and must be empty before mounting.
    pub work_dir: PathBuf,
    /// Mountpoint where the merged view appears.
    pub merged_dir: PathBuf,
}

/// Mount the overlayfs described by `spec`. `merged_dir` must already
/// exist as a directory.
pub fn mount_overlay(spec: &OverlaySpec) -> Result<()> {
    if spec.lower_dirs.is_empty() {
        return Err(error::Error::InvalidArgument("overlay mount requires at least one lowerdir".into()));
    }

    let lower = spec.lower_dirs.iter().map(|p| p.to_string_lossy()).collect::<Vec<_>>().join(":");
    // `userxattr`: every Kiln container mounts its overlay from inside a
    // freshly-created (non-initial) user namespace. Overlayfs's default
    // bookkeeping xattrs live in the `trusted.*` namespace, which is
    // gated on CAP_SYS_ADMIN as checked against the *initial* user
    // namespace - full capabilities inside our own nested namespace
    // don't count for it. Without `userxattr`, the kernel logs "failed
    // to set xattr on upper" and falls back to degraded behavior
    // (`redirect_dir=nofollow`, `uuid=null`). `userxattr` moves
    // overlayfs's own bookkeeping into the unprivileged `user.*` xattr
    // namespace instead, which our namespace's own capabilities *are*
    // sufficient for.
    // `xino=on`: without it, overlayfs can synthesize merged-directory
    // inode numbers that don't fit the 32-bit `ino_t`/`stat` ABI some
    // statically-linked tools (e.g. busybox) still use, surfacing as
    // `EOVERFLOW` ("Value too large for defined data type") from calls
    // like `chmod` on a file that COPY just placed in a new layer.
    // `xino=on` forces overlayfs to always use its 64-bit-safe inode
    // numbering instead of falling back to that synthesis.
    let options = format!(
        "lowerdir={},upperdir={},workdir={},userxattr,xino=on",
        lower,
        spec.upper_dir.display(),
        spec.work_dir.display()
    );

    mount(
        Some("overlay"),
        &spec.merged_dir,
        Some("overlay"),
        MsFlags::empty(),
        Some(options.as_str()),
    )
    .map_err(error::syscall("mount(overlay)"))
}

/// Lazily unmount whatever's at `target` (`MNT_DETACH`: succeeds
/// immediately, actually goes away once nothing still references it) -
/// the general-purpose counterpart to the specific unmounts already
/// inlined elsewhere in this module (e.g. `pivot_root_into`'s own old-root
/// detach). Used by callers that mount something *without* going through
/// a full container lifecycle - e.g. a throwaway overlay for scanning an
/// image's contents, never pivoted into or torn down by a container exit.
pub fn unmount(target: &Path) -> Result<()> {
    umount2(target, MntFlags::MNT_DETACH).map_err(error::syscall("umount2"))
}

/// Make the entire mount tree private (`MS_PRIVATE | MS_REC` on `/`),
/// severing propagation to and from the host's mount namespace.
///
/// Without this, mounts performed inside the container's new mount
/// namespace can still propagate to (or be affected by) the host, because
/// by default new mount namespaces inherit their parent's mount
/// propagation settings, which on most distributions are "shared". This
/// must run before any other mount/pivot_root calls in the new namespace.
pub fn make_mounts_private() -> Result<()> {
    mount(None::<&str>, "/", None::<&str>, MsFlags::MS_PRIVATE | MsFlags::MS_REC, None::<&str>).map_err(error::syscall("mount(MS_PRIVATE)"))
}

/// Switch the process's root filesystem to `new_root` using
/// `pivot_root(2)`, then unmount and discard the old root entirely.
///
/// Must be called from inside a process that already has its own mount
/// namespace (`CLONE_NEWNS`) with propagation made private (see
/// [`make_mounts_private`]) — otherwise this will either fail outright or
/// leak the old root's mounts to the host.
pub fn pivot_root_into(new_root: &Path) -> Result<()> {
    // pivot_root(2) requires `new_root` to be a mount point (and not the
    // same mount as its parent directory). A recursive bind mount of
    // new_root onto itself is the standard way to guarantee that even
    // when new_root is a plain directory rather than something already
    // mounted (e.g. our overlayfs merged_dir, which already qualifies,
    // but callers may also point this at a plain rootfs directory).
    mount(Some(new_root), new_root, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>).map_err(error::syscall("mount(bind self)"))?;

    // pivot_root(2) also wants somewhere under new_root to move the old
    // root to.
    let old_root = new_root.join(".kiln-old-root");
    fs::create_dir_all(&old_root).map_err(error::io(&old_root))?;

    chdir(new_root).map_err(error::syscall("chdir(new_root)"))?;
    nix::unistd::pivot_root(".", ".kiln-old-root").map_err(error::syscall("pivot_root"))?;
    chdir("/").map_err(error::syscall("chdir(/)"))?;

    // The old root is now mounted at /.kiln-old-root inside the new root;
    // detach it (MNT_DETACH: unmount once nothing still references it,
    // without blocking) and remove the now-empty mountpoint directory so
    // no trace of the host filesystem remains reachable.
    umount2("/.kiln-old-root", MntFlags::MNT_DETACH).map_err(error::syscall("umount2(old root)"))?;
    fs::remove_dir("/.kiln-old-root").map_err(error::io("/.kiln-old-root"))?;

    Ok(())
}

/// Mount a fresh `/proc` inside the container.
///
/// This is not optional cosmetic setup: a procfs mount is permanently
/// bound to whichever PID namespace was active when it was mounted, so
/// simply being inside a new PID namespace does not make an *inherited*
/// `/proc` (mounted for the host's PID namespace before the container's
/// PID namespace existed) show only the container's processes. Reading
/// `/proc` would still enumerate every host PID. A fresh mount, performed
/// after entering the new PID namespace (and after `pivot_root`, so it
/// lands at the container's own `/proc`), is what actually scopes it.
pub fn mount_proc(target: &Path) -> Result<()> {
    // Base container images won't necessarily ship an empty /proc
    // directory to mount onto (it's pointless dead weight in every image
    // otherwise), so ensure the mountpoint exists rather than requiring
    // every caller to remember to create it.
    fs::create_dir_all(target).map_err(error::io(target))?;
    mount(
        Some("proc"),
        target,
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .map_err(error::syscall("mount(proc)"))
}

/// Recursively bind-mount `src` onto `dest`, creating `dest` if it doesn't
/// exist. Used for volumes: `src` is a host directory (e.g. one of
/// `kiln-image`'s named volume directories), `dest` a path *inside* an
/// about-to-be-pivoted merged overlay view.
///
/// Must be called **before** [`pivot_root_into`], while `dest` is still
/// reachable through the pre-pivot root. `pivot_root`'s own initial
/// self-bind-mount is recursive (`MS_BIND | MS_REC`), so any mount already
/// sitting under `merged_dir` - this one included - rides along through
/// the pivot and ends up exactly where it was mounted, just now under the
/// container's new `/`.
pub fn bind_mount(src: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).map_err(error::io(dest))?;
    mount(Some(src), dest, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REC, None::<&str>).map_err(error::syscall("mount(bind volume)"))
}

/// The handful of device nodes almost every real program assumes exist
/// and work - not an attempt at a complete `/dev`.
const STANDARD_DEVICES: &[&str] = &["null", "zero", "full", "random", "urandom", "tty"];

/// `(link, target)` pairs mirroring every mainstream container runtime's
/// default `/dev` population - `/dev/fd` and friends are how shell
/// process substitution (`<(...)`) and `/dev/std{in,out,err}` redirects
/// work, both common enough in real entrypoint scripts (MySQL's own
/// among them) that a container without them fails in confusing,
/// script-specific ways rather than a clean "no such file".
const STANDARD_DEV_SYMLINKS: &[(&str, &str)] = &[
    ("fd", "/proc/self/fd"),
    ("stdin", "/proc/self/fd/0"),
    ("stdout", "/proc/self/fd/1"),
    ("stderr", "/proc/self/fd/2"),
];

/// Populate the container's `/dev` with the bare minimum every real
/// program assumes exists and works - not an attempt at a complete
/// `/dev`: the standard device nodes (bind-mounted from the host) plus
/// the standard `/proc/self/fd`-based symlinks.
///
/// The device nodes look redundant with `kiln-image`'s `EntryKind::Device`
/// (which faithfully materializes whatever device nodes an image's own
/// layers bake in, e.g. Debian-derived images' static `/dev/null`) - it
/// isn't. Every Kiln container's overlay is mounted from *inside* its own
/// freshly-created user namespace, and the kernel unconditionally forces
/// `MS_NODEV` onto any filesystem mounted by a process that lacks
/// `CAP_SYS_ADMIN` in the *initial* user namespace (`mount_namespaces(7)`)
/// - full capabilities inside our own nested namespace never count for
/// this check. That makes every device node an image's layers provide
/// permanently inert (`open()` fails with `EACCES` regardless of mode
/// bits) no matter how faithfully it was materialized. Every other
/// container runtime works around this the same way: bind-mount the
/// host's own, already-functional device nodes over the image's inert
/// ones. Best-effort for the devices - a host missing one of these
/// (rare) just leaves the image's own, non-functional node in place
/// rather than failing the whole container start; the symlinks always
/// succeed since they don't depend on anything about the host.
///
/// Must be called **before** [`pivot_root_into`], same as [`bind_mount`] -
/// the symlinks' targets don't need to exist yet (nothing resolves them
/// until well after `/proc` is mounted, later in container startup), but
/// the bind mounts do need the pre-pivot host `/dev` to still be reachable.
pub fn bind_mount_host_devices(merged_dir: &Path) -> Result<()> {
    let dev_dir = merged_dir.join("dev");
    fs::create_dir_all(&dev_dir).map_err(error::io(&dev_dir))?;

    for name in STANDARD_DEVICES {
        let host_path = Path::new("/dev").join(name);
        if !host_path.exists() {
            continue;
        }
        let target = dev_dir.join(name);
        // Standard container-runtime convention: bind-mount onto a
        // fresh, empty regular file, discarding whatever the image's own
        // layers may have already placed there (typically the
        // non-functional device-special file described above).
        let _ = fs::remove_file(&target);
        fs::File::create(&target).map_err(error::io(&target))?;
        mount(Some(&host_path), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(error::syscall("mount(bind device)"))?;
    }

    for (name, dest) in STANDARD_DEV_SYMLINKS {
        let target = dev_dir.join(name);
        let _ = fs::remove_file(&target);
        std::os::unix::fs::symlink(dest, &target).map_err(error::io(&target))?;
    }

    Ok(())
}

/// Bind-mount the host's own `/etc/resolv.conf` onto the container's
/// `/etc/resolv.conf`, so DNS resolution actually works for any container
/// with real network access - nothing else populates it (an image's own
/// layers essentially never ship a working one, since it has to name
/// *this specific host's* resolvers), so without this every hostname
/// lookup inside a networked container fails outright regardless of how
/// correctly its bridge/NAT is set up. Best-effort: a host with no
/// `/etc/resolv.conf` (rare) just leaves the container without one,
/// rather than failing container start entirely.
///
/// Must be called **before** [`pivot_root_into`], same as [`bind_mount`].
pub fn bind_mount_host_resolv_conf(merged_dir: &Path) -> Result<()> {
    let host_path = Path::new("/etc/resolv.conf");
    if !host_path.exists() {
        return Ok(());
    }
    let target = merged_dir.join("etc/resolv.conf");
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent).map_err(error::io(parent))?;
    }
    let _ = fs::remove_file(&target);
    fs::File::create(&target).map_err(error::io(&target))?;
    mount(Some(host_path), &target, None::<&str>, MsFlags::MS_BIND, None::<&str>).map_err(error::syscall("mount(bind resolv.conf)"))
}

/// Mounts a small tmpfs at `merged_dir/run/secrets` and writes each
/// `(name, plaintext)` pair as its own file - unlike [`bind_mount`],
/// there is no host-side directory backing this at all: tmpfs is
/// RAM-only, so a secret's plaintext never touches host disk (including
/// the container's own overlay `upperdir`) and vanishes the moment the
/// container's mount namespace goes away.
///
/// Must run *after* the calling process has already dropped to the
/// container's mapped identity (`run_container_init`'s
/// `setresuid`/`setresgid` calls, which happen before any of this
/// module's mount calls) - files created here are owned by whatever the
/// calling process's own uid/gid already are by that point, unlike
/// [`bind_mount`]'s pre-existing, host-root-owned volume directories,
/// which need an explicit `chown` from the caller instead.
///
/// Must be called **before** [`pivot_root_into`], same as [`bind_mount`].
pub fn mount_tmpfs_secrets(merged_dir: &Path, secrets: &[(String, Vec<u8>)]) -> Result<()> {
    if secrets.is_empty() {
        return Ok(());
    }
    let secrets_dir = merged_dir.join("run").join("secrets");
    fs::create_dir_all(&secrets_dir).map_err(error::io(&secrets_dir))?;
    mount(
        Some("tmpfs"),
        &secrets_dir,
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        Some("mode=0700,size=1m"),
    )
    .map_err(error::syscall("mount(tmpfs secrets)"))?;

    for (name, value) in secrets {
        let path = secrets_dir.join(name);
        fs::write(&path, value).map_err(error::io(&path))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).map_err(error::io(&path))?;
    }
    Ok(())
}
