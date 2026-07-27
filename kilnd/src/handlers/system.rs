//! Store-wide disk usage and garbage collection - `GET /disk-usage` and
//! `POST /gc`, the HTTP counterparts of `kiln gc`'s reporting (there's no
//! existing CLI equivalent of `disk_usage` itself; it's assembled here
//! straight from the store's own directory layout, the same directories
//! `kiln-image::store::Store` already owns) - plus `GET /metrics`, a
//! Prometheus text-exposition rendering of the same per-container data
//! `kiln inspect --resources` / `GET /containers/:id/resources` already
//! report (see `metrics`'s own docs: deliberately no new data collection,
//! just a different format for numbers this project already tracks).

use kiln_cli::commands::gc::collect_garbage;
use kiln_cli::commands::inspect::resources_report;
use kiln_cli::container::{Container, HealthStatus, Status};
use kiln_image::store::Store;
use kilnd_core::http::Response;
use serde::Serialize;
use std::fmt::Write as _;

#[derive(Serialize)]
pub struct DiskUsageJson {
    /// Content-addressed file content - shared across every layer/image
    /// that references it (see `kiln-image::store`'s dedup docs), so this
    /// is usually the biggest number and the one `gc` actually shrinks.
    pub blobs_bytes: u64,
    /// Layer manifests and their materialized directories - not touched
    /// by `gc` (see `commands::gc`'s module docs on why).
    pub layers_bytes: u64,
    pub volumes_bytes: u64,
    pub containers_bytes: u64,
    pub total_bytes: u64,
}

pub fn disk_usage(store: &Store) -> Response {
    let blobs_bytes = super::dir_size(&store.root().join("blobs"));
    let layers_bytes = super::dir_size(&store.root().join("layers"));
    let volumes_bytes = super::dir_size(&store.root().join("volumes"));
    let containers_bytes = super::dir_size(&store.root().join("containers"));
    Response::json(
        200,
        &DiskUsageJson {
            blobs_bytes,
            layers_bytes,
            volumes_bytes,
            containers_bytes,
            total_bytes: blobs_bytes + layers_bytes + volumes_bytes + containers_bytes,
        },
    )
}

#[derive(Serialize)]
pub struct GcResultJson {
    pub blobs_removed: u64,
    pub bytes_freed: u64,
    pub images_removed: u64,
}

pub fn gc(store: &Store) -> Response {
    let summary = collect_garbage(store);
    Response::json(
        200,
        &GcResultJson {
            blobs_removed: summary.blobs_removed,
            bytes_freed: summary.bytes_freed,
            images_removed: summary.images_removed,
        },
    )
}

/// Prometheus label values must escape backslash, double-quote, and
/// newline (the exposition format spec's own escaping rules) - container
/// names/ids are effectively always safe already, but a name is
/// user-chosen text, not a value this project controls the shape of.
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

struct Metric {
    name: &'static str,
    help: &'static str,
    kind: &'static str, // "gauge" or "counter"
}

/// Renders one metric's `# HELP`/`# TYPE` header followed by one sample
/// line per `(labels, value)` pair - grouped this way (not per-container)
/// because the exposition format expects each metric's header to appear
/// exactly once, immediately before all of its own samples.
fn render_metric(out: &mut String, metric: &Metric, samples: &[(String, f64)]) {
    if samples.is_empty() {
        return;
    }
    let _ = writeln!(out, "# HELP {} {}", metric.name, metric.help);
    let _ = writeln!(out, "# TYPE {} {}", metric.name, metric.kind);
    for (labels, value) in samples {
        let _ = writeln!(out, "{}{{{}}} {}", metric.name, labels, value);
    }
}

/// `GET /metrics` - the same per-container CPU/memory/network/health data
/// `kiln inspect --resources` and the dashboard's own resource views
/// already surface, reformatted for Prometheus rather than recomputed
/// from a different source. No cluster-wide or historical data (no
/// counters this process didn't already have in memory/cgroupfs) - one
/// scrape reflects this `kilnd`'s current view, same as every other
/// endpoint here.
pub fn metrics(store: &Store) -> Response {
    let containers = Container::list(store);

    let mut up = Vec::new();
    let mut healthy = Vec::new();
    let mut cpu_limit = Vec::new();
    let mut memory_limit = Vec::new();
    let mut memory_current = Vec::new();
    let mut cpu_seconds = Vec::new();
    let mut pids_current = Vec::new();
    let mut net_rx = Vec::new();
    let mut net_tx = Vec::new();
    let mut last_exit_oom = Vec::new();

    for mut c in containers {
        c.refresh(store);
        let labels = format!("id=\"{}\",name=\"{}\"", escape_label(&c.id), escape_label(&c.name));

        up.push((labels.clone(), if c.status == Status::Running { 1.0 } else { 0.0 }));
        healthy.push((labels.clone(), if c.health == HealthStatus::Healthy { 1.0 } else { 0.0 }));
        last_exit_oom.push((labels.clone(), if c.last_exit_oom_killed { 1.0 } else { 0.0 }));

        let report = resources_report(&c);
        if let Some(cpu) = report.cpu_limit {
            cpu_limit.push((labels.clone(), cpu));
        }
        if let Some(mem) = report.memory_limit_bytes {
            memory_limit.push((labels.clone(), mem as f64));
        }
        if let Some(live) = report.live {
            memory_current.push((labels.clone(), live.memory_current_bytes as f64));
            cpu_seconds.push((labels.clone(), live.cpu_usage_usec as f64 / 1_000_000.0));
            pids_current.push((labels.clone(), live.pids_current as f64));
            if let Some(rx) = live.rx_bytes {
                net_rx.push((labels.clone(), rx as f64));
            }
            if let Some(tx) = live.tx_bytes {
                net_tx.push((labels, tx as f64));
            }
        }
    }

    let mut out = String::new();
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_up",
            help: "Whether the container is currently running (1) or not (0).",
            kind: "gauge",
        },
        &up,
    );
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_healthy",
            help: "Healthcheck status: 1 if healthy, 0 otherwise (including a container with no healthcheck configured, which never leaves \"starting\").",
            kind: "gauge",
        },
        &healthy,
    );
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_cpu_limit_cores",
            help: "Configured CPU limit in cores - absent (no sample) if unlimited.",
            kind: "gauge",
        },
        &cpu_limit,
    );
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_memory_limit_bytes",
            help: "Configured hard memory limit - absent (no sample) if unlimited.",
            kind: "gauge",
        },
        &memory_limit,
    );
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_memory_current_bytes",
            help: "Current cgroup memory usage (memory.current).",
            kind: "gauge",
        },
        &memory_current,
    );
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_cpu_seconds_total",
            help: "Cumulative CPU time consumed since the container started (cgroup cpu.stat usage_usec).",
            kind: "counter",
        },
        &cpu_seconds,
    );
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_pids_current",
            help: "Current number of processes in the container's cgroup.",
            kind: "gauge",
        },
        &pids_current,
    );
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_network_receive_bytes_total",
            help: "Cumulative bytes received on the container's network interface - absent (no sample) if it has no network attached.",
            kind: "counter",
        },
        &net_rx,
    );
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_network_transmit_bytes_total",
            help: "Cumulative bytes transmitted on the container's network interface - absent (no sample) if it has no network attached.",
            kind: "counter",
        },
        &net_tx,
    );
    render_metric(
        &mut out,
        &Metric {
            name: "kiln_container_last_exit_oom_killed",
            help: "Whether the container's most recent exit was an OOM-kill (1) or not (0).",
            kind: "gauge",
        },
        &last_exit_oom,
    );

    Response::text(200, out)
}
