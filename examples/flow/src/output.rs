//! Parquet output for the flow-feature pipeline.
//!
//! Two independent streams, each with its own pool of pinned writer threads:
//! - `snapshot`: per-flow snapshots + final label, sharded by snapshot depth
//! - `trace`: per-packet cumulative-bytes trace (optional)

mod pool;
mod sink;
mod snapshot;
mod trace;

pub use snapshot::{FinalLabel, Snapshot, write_flow_batch};
pub use trace::{TraceRecord, write_trace_batch};

use std::path::PathBuf;
use std::sync::OnceLock;

use iris_core::CoreId;

static OUT_DIR: OnceLock<PathBuf> = OnceLock::new();

/// Must be called before `init_writer`; later calls are ignored.
pub fn set_out_dir(dir: impl Into<PathBuf>) {
    let _ = OUT_DIR.set(dir.into());
}

fn out_path(name: &str) -> PathBuf {
    OUT_DIR
        .get_or_init(|| "/mnt/netdata".into())
        .join(name)
}

pub fn init_writer(cores: Vec<CoreId>, trace: bool) {
    println!(
        "Writing parquet to {} (trace {})",
        out_path("").display(),
        if trace { "on" } else { "off" }
    );
    snapshot::start(&cores);
    if trace {
        trace::start(&cores);
    }
}

/// Drain all queues, stop the writer threads and finalize every file.
pub fn shutdown_writer() {
    pools().for_each(|p| p.shutdown());
}

pub fn print_stats() {
    let mut report = String::from("=== Writer Dispatcher Stats ===\n");
    pools().for_each(|p| p.report(&mut report));
    print!("{report}");
    let path = out_path("writer_stats.txt");
    match std::fs::write(&path, &report) {
        Ok(()) => println!("Wrote writer stats to {}", path.display()),
        Err(e) => eprintln!("warning: writing {}: {e}", path.display()),
    }
}

fn pools() -> impl Iterator<Item = &'static dyn pool::AnyPool> {
    [snapshot::pool(), trace::pool()].into_iter().flatten()
}
