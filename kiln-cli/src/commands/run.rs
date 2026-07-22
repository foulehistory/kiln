//! `kiln run` - the command most of this project exists to support:
//! materialize an image's layers, assemble them into a fresh overlayfs
//! rootfs, and launch an isolated process in it. Rootless (via the
//! subordinate uid/gid remap from `kiln-image::identity`) and daemonless
//! by default.
//!
//! [`start`] is the reusable core: it always launches via the
//! per-container supervisor (`supervisor.rs`) and always captures output
//! to a log file, regardless of whether the caller is this CLI command or
//! `kiln-compose` starting several services at once. The CLI's own
//! foreground/background distinction ([`run`]) is just a thin choice
//! layered on top: `-d` prints the id and returns immediately, plain
//! `kiln run` calls [`wait_and_stream`] to tail that same log file to the
//! terminal and block until the container exits.

use crate::container::{generate_id, now_unix, Container, RestartPolicy, Status};
use crate::error::{CliError, CliResult};
use crate::supervisor;
use kiln_image::identity;
use kiln_image::image::Image;
use kiln_image::layer;
use kiln_image::store::Store;
use kilnd_core::namespaces::Spawn;
use kilnd_core::rootfs::{
    bind_mount_host_devices, bind_mount_host_resolv_conf, make_mounts_private, mount_overlay, mount_proc, pivot_root_into, OverlaySpec,
};
use std::ffi::CString;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;
use std::time::Duration;

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Run in the background and print the container id
    #[arg(short = 'd', long)]
    pub detach: bool,

    /// Assign a name to the container (defaults to a generated id prefix)
    #[arg(long)]
    pub name: Option<String>,

    /// Mount a named volume into the container, as `<volume>:<path>`
    #[arg(short = 'v', long = "volume")]
    pub volumes: Vec<String>,

    /// Attach to a network created with `kiln network create`
    #[arg(long)]
    pub network: Option<String>,

    /// Publish a container port to the host, as `<host>:<container>[/tcp|udp]` (requires --network)
    #[arg(short = 'p', long = "publish")]
    pub ports: Vec<String>,

    /// Set an environment variable inside the container, as `KEY=VALUE`
    /// (repeatable) - overrides the image's own ENV of the same name,
    /// same as `kiln-compose`'s `environment:` already did for services.
    #[arg(short = 'e', long = "env")]
    pub env: Vec<String>,

    /// Mount a secret (created with `kiln secret create`) into the
    /// container at `/run/secrets/<name>` (repeatable) - unlike -e, never
    /// visible in `kiln inspect` or the container's own persisted state.
    #[arg(long = "secret")]
    pub secrets: Vec<String>,

    /// Memory limit, e.g. `512m`, `1g`, or a plain byte count (unlimited by default)
    #[arg(long)]
    pub memory: Option<String>,

    /// CPU limit in number of CPUs, e.g. `0.5` or `2` (unlimited by default)
    #[arg(long)]
    pub cpus: Option<f64>,

    /// Restart policy: `no` (default), `always`, or `on-failure`
    #[arg(long, default_value = "no")]
    pub restart: String,

    /// Command to run periodically to check container health, e.g.
    /// `--health-cmd "curl -f http://localhost/"` (run via `/bin/sh -c`,
    /// same as `kiln.yaml`'s `healthcheck.test` bare-string form). No
    /// healthcheck is configured unless this is given.
    #[arg(long = "health-cmd")]
    pub health_cmd: Option<String>,

    /// Seconds between health probes (default 30)
    #[arg(long = "health-interval", default_value_t = crate::container::HealthCheckSpec::DEFAULT_INTERVAL_SECS)]
    pub health_interval: u64,

    /// Seconds before a health probe is considered timed out (default 5)
    #[arg(long = "health-timeout", default_value_t = crate::container::HealthCheckSpec::DEFAULT_TIMEOUT_SECS)]
    pub health_timeout: u64,

    /// Consecutive failures before the container is reported unhealthy (default 3)
    #[arg(long = "health-retries", default_value_t = crate::container::HealthCheckSpec::DEFAULT_RETRIES)]
    pub health_retries: u32,

    /// Disable the default seccomp filter for this container - only
    /// `seccomp=unconfined` is accepted (matches Docker's own
    /// `--security-opt` flag name/value for muscle-memory familiarity;
    /// no other `--security-opt` values are implemented).
    #[arg(long = "security-opt")]
    pub security_opt: Option<String>,

    /// Add a Linux capability on top of the default baseline (repeatable),
    /// e.g. `--cap-add NET_ADMIN` (the `CAP_` prefix is optional)
    #[arg(long = "cap-add")]
    pub cap_add: Vec<String>,

    /// Remove a capability from the default baseline (repeatable) -
    /// checked after --cap-add, so adding and dropping the same
    /// capability nets out to it being dropped
    #[arg(long = "cap-drop")]
    pub cap_drop: Vec<String>,

    /// Image reference (name[:tag], a bare content hash, or "scratch")
    pub image: String,

    /// Command to run instead of the image's default CMD
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    pub command: Vec<String>,
}

/// Parse a Docker-style size string (`512m`, `1g`, `1024k`, or a bare byte
/// count) into bytes.
pub fn parse_size(s: &str) -> Result<u64, String> {
    let s = s.trim();
    let (digits, multiplier) = match s.chars().last() {
        Some(c) if c.eq_ignore_ascii_case(&'k') => (&s[..s.len() - 1], 1024u64),
        Some(c) if c.eq_ignore_ascii_case(&'m') => (&s[..s.len() - 1], 1024 * 1024),
        Some(c) if c.eq_ignore_ascii_case(&'g') => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    digits
        .trim()
        .parse::<u64>()
        .map(|n| n * multiplier)
        .map_err(|_| format!("invalid size {s:?} (expected e.g. 512m, 1g, or a plain byte count)"))
}

pub fn run(store: &Store, args: Args) -> CliResult {
    let memory_limit_bytes = args.memory.map(|s| parse_size(&s)).transpose().map_err(CliError::msg)?;
    let restart_policy = RestartPolicy::parse(&args.restart).map_err(CliError::msg)?;
    let extra_env = args
        .env
        .iter()
        .map(|kv| {
            kv.split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .ok_or_else(|| CliError::msg(format!("invalid -e/--env {kv:?}: expected KEY=VALUE")))
        })
        .collect::<CliResult<Vec<_>>>()?;
    let seccomp_unconfined = match args.security_opt.as_deref() {
        None => false,
        Some("seccomp=unconfined") => true,
        Some(other) => {
            return Err(CliError::msg(format!(
                "unsupported --security-opt {other:?} (only seccomp=unconfined is implemented)"
            )))
        }
    };

    let healthcheck = args.health_cmd.map(|cmd| crate::container::HealthCheckSpec {
        test: vec!["/bin/sh".to_string(), "-c".to_string(), cmd],
        interval_secs: args.health_interval,
        timeout_secs: args.health_timeout,
        retries: args.health_retries,
    });

    let spec = RunSpec {
        image: args.image,
        command: args.command,
        name: args.name,
        volumes: args.volumes,
        network: args.network,
        extra_env,
        extra_hosts: Vec::new(),
        memory_limit_bytes,
        cpu_limit: args.cpus,
        ports: args.ports,
        restart_policy,
        secrets: args.secrets,
        security: kilnd_core::security::SecurityProfile {
            seccomp_unconfined,
            cap_add: args.cap_add,
            cap_drop: args.cap_drop,
        },
        healthcheck,
    };

    let container = start(store, spec, None)?;

    if args.detach {
        println!("{}", container.id);
        Ok(())
    } else {
        let code = wait_and_stream(store, &container)?;
        std::process::exit(code);
    }
}

/// Everything needed to start a container, independent of how the request
/// was made - CLI flags here, or programmatically from `kiln-compose`.
pub struct RunSpec {
    pub image: String,
    pub command: Vec<String>,
    pub name: Option<String>,
    pub volumes: Vec<String>,
    pub network: Option<String>,
    pub extra_env: Vec<(String, String)>,
    /// Extra `/etc/hosts` entries (`hostname`, `ip`), written into the
    /// container's writable layer before it starts. This is how
    /// `kiln-compose` gives services name-based reachability to
    /// dependencies that already have an allocated IP by the time a
    /// dependent service starts - see `kiln-compose`'s module docs for
    /// the (deliberately modest) scope of this.
    pub extra_hosts: Vec<(String, String)>,
    pub memory_limit_bytes: Option<u64>,
    pub cpu_limit: Option<f64>,
    /// `<host>:<container>[/tcp|udp]` specs - see `network::PortSpec`.
    /// Requires `network` to be set (there's no container IP to route to
    /// otherwise); `start` rejects the combination of ports with no network.
    pub ports: Vec<String>,
    pub restart_policy: crate::container::RestartPolicy,
    /// Names of secrets (created with `kiln secret create`) to decrypt
    /// and mount at `/run/secrets/<name>` - see `kiln_image::secrets` and
    /// `kilnd_core::rootfs::mount_tmpfs_secrets`.
    pub secrets: Vec<String>,
    /// Seccomp/capability overrides - default (`SecurityProfile::default()`)
    /// is the full restricted profile every container gets unless a
    /// caller explicitly widens it. See `kilnd_core::security`'s own docs.
    pub security: kilnd_core::security::SecurityProfile,
    /// Command to probe container health with, if any - see
    /// `crate::container::HealthCheckSpec`. Restart-fidelity field, same
    /// role as `security`/`secrets` above.
    pub healthcheck: Option<crate::container::HealthCheckSpec>,
}

impl RunSpec {
    pub fn new(image: impl Into<String>) -> Self {
        RunSpec {
            image: image.into(),
            command: Vec::new(),
            name: None,
            volumes: Vec::new(),
            network: None,
            extra_env: Vec::new(),
            extra_hosts: Vec::new(),
            memory_limit_bytes: None,
            cpu_limit: None,
            ports: Vec::new(),
            restart_policy: crate::container::RestartPolicy::No,
            secrets: Vec::new(),
            security: kilnd_core::security::SecurityProfile::default(),
            healthcheck: None,
        }
    }
}

/// Materialize, mount, and launch a container per `spec` via the
/// per-container supervisor, so its output is always captured and its
/// exit status always eventually recorded regardless of whether the
/// caller waits around for that. Returns as soon as the container is
/// confirmed started (`Status::Running`, real pid, already persisted).
///
/// `existing_id`, if given, reuses that id instead of generating a new
/// one - this is what makes [`start`] do double duty as `restart`'s core
/// too: every path keyed by id (the writable `upper`/`work` layer, the log
/// file, the cgroup) naturally picks up whatever's already there from a
/// previous run rather than starting fresh, since `fs::create_dir_all`
/// and friends are no-ops on a directory that already exists with content
/// in it. A plain `kiln run` never passes this.
pub fn start(store: &Store, spec: RunSpec, existing_id: Option<String>) -> CliResult<Container> {
    if !spec.ports.is_empty() && spec.network.is_none() {
        return Err(CliError::msg(
            "publishing ports (-p) requires --network (there's no container IP to route to otherwise)",
        ));
    }
    let port_specs: Vec<super::network::PortSpec> = spec
        .ports
        .iter()
        .map(|s| super::network::PortSpec::parse(s))
        .collect::<Result<_, _>>()
        .map_err(CliError::msg)?;

    let image = Image::resolve(store, &spec.image).map_err(|e| CliError::msg(format!("resolving image {:?}: {e}", spec.image)))?;
    let image_id = image.id();

    let command: Vec<String> = if !spec.command.is_empty() {
        spec.command
    } else if let Some(cmd) = &image.config.cmd {
        vec!["/bin/sh".to_string(), "-c".to_string(), cmd.clone()]
    } else {
        return Err(CliError::msg(
            "image has no default CMD; specify a command, e.g. `kiln run <image> /bin/sh`",
        ));
    };

    let id = existing_id.unwrap_or_else(generate_id);
    // Inherited rather than reset to 0 unconditionally: a restart-policy
    // relaunch (`restart()` below) reuses this same id, and the whole
    // point of `restart_count` is to survive across exactly that
    // relaunch so `supervisor.rs`'s backoff keeps escalating through a
    // crash loop instead of resetting on every attempt. A brand new id
    // (plain `kiln run`) has no on-disk state yet, so this is just 0.
    let restart_count = Container::load(store, &id).map(|c| c.restart_count).unwrap_or(0);
    let name = spec.name.unwrap_or_else(|| id[..12].to_string());
    let uid_base = identity::SUBORDINATE_UID_BASE;
    let gid_base = identity::SUBORDINATE_GID_BASE;

    let mut volume_mounts = Vec::new();
    for vspec in &spec.volumes {
        let (vol_name, container_path) = vspec
            .split_once(':')
            .ok_or_else(|| CliError::msg(format!("invalid volume {vspec:?}: expected <volume>:<path>")))?;
        let host_path = super::volume::path(store, vol_name);
        fs::create_dir_all(&host_path).map_err(|e| CliError::msg(format!("creating volume {vol_name}: {e}")))?;
        // See the identical note in `execute_run`'s upper/work handling
        // below: this directory is created by the host-side process
        // (real root), outside the container's own mapped uid/gid range,
        // and must be chowned into that range to actually be writable
        // from inside. Only the top level - files a previous container
        // wrote keep whatever ownership they already have.
        super::chown(&host_path, uid_base, gid_base)?;
        volume_mounts.push((host_path, container_path.to_string()));
    }

    // Decrypted here, in this host-side (real root) process, before the
    // container even exists - never as an env var, never written to the
    // container's writable layer or `Container`'s own persisted JSON.
    // `child_fn` below captures the plaintext directly; the container
    // never sees anything but the secret's *name*.
    let mut secret_files = Vec::new();
    for secret_name in &spec.secrets {
        let value = kiln_image::secrets::read(store.root(), secret_name)
            .map_err(|e| CliError::msg(format!("reading secret {secret_name:?}: {e}")))?
            .ok_or_else(|| CliError::msg(format!("no such secret: {secret_name:?} (create it with `kiln secret create`)")))?;
        secret_files.push((secret_name.clone(), value));
    }

    let mut lower_dirs = Vec::new();
    for lid in image.lower_dirs_order() {
        lower_dirs.push(layer::materialize_cached(store, lid, uid_base, gid_base)?);
    }
    if lower_dirs.is_empty() {
        lower_dirs.push(super::empty_dir(store)?);
    }

    let upper = Container::upper_dir(store, &id);
    let work = Container::work_dir(store, &id);
    let merged = Container::merged_dir(store, &id);
    for d in [&upper, &work, &merged] {
        fs::create_dir_all(d).map_err(|e| CliError::msg(format!("creating {}: {e}", d.display())))?;
        super::chown(d, uid_base, gid_base)?;
    }

    if !spec.extra_hosts.is_empty() {
        let hosts_path = upper.join("etc/hosts");
        let etc_dir = hosts_path.parent().unwrap();
        // `etc` doesn't already exist in `upper` (only in the image's
        // lower layers), so this always creates it fresh - and, left
        // unchowned, that's exactly the bug `layer::materialize`'s
        // `create_dir_all_owned` fixes for image layers: a directory
        // owned by real (unmapped) root conflicting with the base image's
        // own `/etc` (owned by the container's mapped uid) is a merge
        // overlayfs refuses to show at all, not just write to - `ls /`
        // silently omits `etc` and `ls /etc` comes back EACCES, even
        // though the file underneath is perfectly world-readable.
        fs::create_dir_all(etc_dir).map_err(|e| CliError::msg(format!("preparing /etc/hosts: {e}")))?;
        super::chown(etc_dir, uid_base, gid_base)?;
        let mut content = fs::read_to_string(&hosts_path).unwrap_or_default();
        if content.is_empty() {
            content.push_str("127.0.0.1\tlocalhost\n");
        }
        for (hostname, ip) in &spec.extra_hosts {
            content.push_str(&format!("{ip}\t{hostname}\n"));
        }
        fs::write(&hosts_path, content).map_err(|e| CliError::msg(format!("writing /etc/hosts: {e}")))?;
        super::chown(&hosts_path, uid_base, gid_base)?;
    }

    let overlay = OverlaySpec {
        lower_dirs,
        upper_dir: upper,
        work_dir: work,
        merged_dir: merged.clone(),
    };

    let opts = Spawn {
        uid_map: identity::container_id_map(uid_base),
        gid_map: identity::container_id_map(gid_base),
        hostname: Some(name.clone()),
        ..Spawn::default()
    };

    let log_path = Container::log_path(store, &id);
    let log_file = fs::File::create(&log_path).map_err(|e| CliError::msg(format!("creating log file: {e}")))?;
    let log_fd: RawFd = log_file.as_raw_fd();
    // Created here, by this host-side process (real root), so it's
    // host-root-owned (0644) by default - fine for the fd this process
    // itself already has open and dup2's into the child, but the
    // container's own mapped identity (uid_base on the host, not real
    // root) is a different, unprivileged uid. Any program inside the
    // container that path-opens /dev/stdout, /dev/stderr, or /dev/fd/{0,1,2}
    // (all symlinks to /proc/self/fd/N - see bind_mount_host_devices)
    // triggers a fresh permission check against this file's real on-disk
    // owner, which the already-open fd's own access mode has no bearing
    // on. Chowning it to the container's own mapped uid/gid is what makes
    // that re-open succeed - the same reasoning already applied to a
    // container's overlay upper/work dirs (see build.rs's execute_run).
    super::chown(&log_path, uid_base, gid_base)?;

    let mut env = image.config.env.clone();
    env.extend(spec.extra_env.iter().cloned());
    let workdir = if image.config.workdir.is_empty() {
        "/".to_string()
    } else {
        image.config.workdir.clone()
    };
    let command_for_state = command.clone();

    let security = spec.security.clone();
    let child_fn = move || -> kilnd_core::Result<()> {
        run_container_init(
            &merged,
            &overlay,
            &workdir,
            &env,
            &command,
            log_fd,
            &volume_mounts,
            &secret_files,
            &security,
        )
    };

    let container = Container {
        id: id.clone(),
        name,
        image_reference: spec.image,
        image_id,
        command: command_for_state,
        pid: None,
        status: Status::Exited(0),
        created_at: now_unix(),
        ip: None,
        network: None,
        volumes: spec.volumes,
        env: spec.extra_env,
        memory_limit_bytes: spec.memory_limit_bytes,
        cpu_limit: spec.cpu_limit,
        ports: spec.ports,
        restart_policy: spec.restart_policy,
        secrets: spec.secrets,
        security: spec.security,
        healthcheck: spec.healthcheck,
        health: crate::container::HealthStatus::Starting,
        restart_count,
        last_started_at: None,
    };

    // Created (unrestricted unless --memory/--cpus were given) before the
    // container exists, so the post-spawn hook below can move the
    // container's pid into it before the container has a chance to run
    // anything; the resulting memory.current/cpu.stat/pids.current are
    // what `kilnd`'s dashboard API reads for live stats.
    let limits = kilnd_core::cgroups::Limits {
        cpu_max_us: spec.cpu_limit.map(|cpus| (cpus * 100_000.0) as u64),
        cpu_period_us: 100_000,
        memory_max_bytes: spec.memory_limit_bytes,
        // See Limits::memory_swap_max_bytes's docs: without also capping
        // swap, a memory limit isn't really a hard cap.
        memory_swap_max_bytes: spec.memory_limit_bytes.map(|_| 0),
        pids_max: None,
    };
    let cgroup = crate::cgroup::create_for(&id, &limits).map_err(CliError::from)?;

    let container_id_for_net = id.clone();
    let network = spec.network;
    let post_spawn = move |store: &Store, pid: i32| -> CliResult<Option<(String, String)>> {
        cgroup.add_process(nix::unistd::Pid::from_raw(pid)).map_err(CliError::from)?;
        match &network {
            Some(net) => {
                let ip = super::network::attach_container(store, net, &container_id_for_net, pid)?;
                for port in &port_specs {
                    super::network::spawn_port_forwarder(port, ip.clone())?;
                }
                Ok(Some((net.clone(), ip)))
            }
            None => Ok(None),
        }
    };

    let saved = supervisor::spawn_detached(store, container, &opts, child_fn, Some(post_spawn))?;
    drop(log_file);
    Ok(saved)
}

/// Restart a stopped container: rebuild a [`RunSpec`] from what it was
/// last started with and re-[`start`] it under the *same* id, so its
/// existing writable layer (and hence anything the previous run wrote to
/// disk) carries over rather than starting from a clean image again -
/// the same "state survives a restart" behavior `docker start` has.
///
/// Deliberately does not resurrect `extra_hosts`: those already live on
/// disk as whatever `/etc/hosts` the previous run last wrote (untouched
/// by this restart, since `start` only touches `/etc/hosts` when
/// `extra_hosts` is non-empty), so re-supplying them here would just
/// duplicate entries rather than restore anything.
pub fn restart(store: &Store, id_or_name: &str) -> CliResult<Container> {
    let mut container = Container::resolve(store, id_or_name).ok_or_else(|| CliError::msg(format!("no such container: {id_or_name}")))?;
    container.refresh(store);
    if container.status == Status::Running {
        return Err(CliError::msg(format!("container {} is already running", container.id)));
    }

    let spec = RunSpec {
        image: container.image_reference.clone(),
        command: container.command.clone(),
        name: Some(container.name.clone()),
        volumes: container.volumes.clone(),
        network: container.network.clone(),
        extra_env: container.env.clone(),
        extra_hosts: Vec::new(),
        memory_limit_bytes: container.memory_limit_bytes,
        cpu_limit: container.cpu_limit,
        ports: container.ports.clone(),
        restart_policy: container.restart_policy,
        secrets: container.secrets.clone(),
        security: container.security.clone(),
        healthcheck: container.healthcheck.clone(),
    };
    start(store, spec, Some(container.id.clone()))
}

/// Tail a container's log to stdout and block until it exits, returning
/// its exit code. This is what gives plain (non-`-d`) `kiln run` its
/// live, foreground feel despite [`start`] always running things through
/// the same detached/supervised path.
pub fn wait_and_stream(store: &Store, container: &Container) -> CliResult<i32> {
    let log_path = Container::log_path(store, &container.id);
    let mut file = fs::File::open(&log_path).map_err(|e| CliError::msg(format!("opening log: {e}")))?;
    let mut pos = 0u64;
    let mut stdout = std::io::stdout();

    loop {
        let len = file.metadata().map(|m| m.len()).unwrap_or(pos);
        if len > pos {
            file.seek(SeekFrom::Start(pos)).ok();
            let mut chunk = Vec::new();
            file.read_to_end(&mut chunk).ok();
            stdout.write_all(&chunk).ok();
            stdout.flush().ok();
            pos += chunk.len() as u64;
        }

        let mut current = Container::load(store, &container.id).unwrap_or_else(|| container.clone());
        current.refresh(store);
        if let Status::Exited(code) = current.status {
            return Ok(code);
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Runs inside the freshly-cloned container process: mount the rootfs,
/// pivot into it, and `execve` into the container's command. Like
/// `kiln-image::build`'s `RUN` steps, this never returns on success - the
/// command replaces this process outright, becoming the container's PID 1
/// directly (no extra init layer), so its own exit status is exactly what
/// the container's exit status is.
#[allow(clippy::too_many_arguments)] // one call site (child_fn's closure); a params struct would just move the same fields, not reduce them
fn run_container_init(
    merged: &Path,
    overlay: &OverlaySpec,
    workdir: &str,
    env: &[(String, String)],
    command: &[String],
    log_fd: RawFd,
    volume_mounts: &[(std::path::PathBuf, String)],
    secret_files: &[(String, Vec<u8>)],
    security: &kilnd_core::security::SecurityProfile,
) -> kilnd_core::Result<()> {
    use kilnd_core::Error as RtError;

    // Clear supplementary groups before assuming the container's identity.
    // `clone(2)` never touches the supplementary group list, so without
    // this the child keeps whatever groups its parent had (for kiln,
    // invoked as real root, that's group 0). The kernel's DAC check
    // (`in_group_p`) uses the *group* permission bits whenever the real
    // gid list contains the inode's group — even if the process's fsgid
    // doesn't match it and "other" bits would otherwise apply. That silently
    // turns a "should fall through to other" check into a "use group bits"
    // check, which is how a inherited group-0 membership caused EACCES on
    // `/root` (mode 0701: group bits are `---`, but other bits are `--x`)
    // despite the mapped uid/gid being entirely correct. `nsenter -S -G`
    // clears supplementary groups as part of switching identity, which is
    // why manual repros via nsenter never hit this.
    nix::unistd::setgroups(&[]).map_err(|e| RtError::InvalidArgument(format!("setgroups: {e}")))?;
    nix::unistd::setresgid(
        nix::unistd::Gid::from_raw(0),
        nix::unistd::Gid::from_raw(0),
        nix::unistd::Gid::from_raw(0),
    )
    .map_err(|e| RtError::InvalidArgument(format!("setresgid: {e}")))?;
    nix::unistd::setresuid(
        nix::unistd::Uid::from_raw(0),
        nix::unistd::Uid::from_raw(0),
        nix::unistd::Uid::from_raw(0),
    )
    .map_err(|e| RtError::InvalidArgument(format!("setresuid: {e}")))?;

    make_mounts_private()?;
    mount_overlay(overlay)?;

    for (host_path, container_path) in volume_mounts {
        let target = merged.join(container_path.trim_start_matches('/'));
        kilnd_core::rootfs::bind_mount(host_path, &target)?;
    }
    bind_mount_host_devices(merged)?;
    bind_mount_host_resolv_conf(merged)?;
    kilnd_core::rootfs::mount_tmpfs_secrets(merged, secret_files)?;

    pivot_root_into(merged)?;
    mount_proc(Path::new("/proc"))?;

    let _ = nix::unistd::chdir(workdir);

    nix::unistd::dup2(log_fd, 1).map_err(|e| RtError::InvalidArgument(format!("dup2(stdout): {e}")))?;
    nix::unistd::dup2(log_fd, 2).map_err(|e| RtError::InvalidArgument(format!("dup2(stderr): {e}")))?;

    for (k, v) in env {
        std::env::set_var(k, v);
    }

    if command.is_empty() {
        return Err(RtError::InvalidArgument("empty command".into()));
    }
    let args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_str()).map_err(|e| RtError::InvalidArgument(format!("command has a NUL byte: {e}"))))
        .collect::<kilnd_core::Result<_>>()?;

    // Rust's runtime sets SIGPIPE to SIG_IGN at startup (so this process's
    // own write()s return an EPIPE Result instead of dying by signal) -
    // and unlike a handler function, a SIG_IGN disposition survives
    // execve(2) unchanged. Left alone, that means every container's
    // command inherits SIGPIPE-ignored from kiln's own process, silently
    // different from how it would behave run natively. Most programs
    // don't care (they check write()'s return value), but some very much
    // do: e.g. a multi-stage shell pipeline where an upstream tool is
    // expected to be killed by SIGPIPE once a downstream `head -n1` exits
    // early - with the signal ignored, that upstream tool never receives
    // the signal that would otherwise end it, and neither does whatever
    // sits between them still trying to write into an unread pipe -
    // hanging a pipeline that would terminate in half a second natively.
    unsafe {
        nix::sys::signal::signal(nix::sys::signal::Signal::SIGPIPE, nix::sys::signal::SigHandler::SigDfl)
            .map_err(|e| RtError::InvalidArgument(format!("resetting SIGPIPE: {e}")))?;
    }

    // Last narrowing steps before the container's actual command replaces
    // this process - see `kilnd_core::security`'s own docs on why this
    // must come after every mount/pivot_root operation above (both still
    // need CAP_SYS_ADMIN, which capability-dropping removes) and in this
    // exact order (seccomp last: once installed, it also governs
    // everything else this process does from here on, including the
    // execve itself).
    kilnd_core::security::drop_capabilities(security)?;
    kilnd_core::security::apply_seccomp(security)?;

    nix::unistd::execvp(&args[0], &args).map_err(|e| RtError::InvalidArgument(format!("execvp({:?}): {e}", command[0])))?;
    unreachable!("execvp only returns on error, which is handled above")
}
