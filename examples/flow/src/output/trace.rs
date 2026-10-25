//! Stream 2 (optional): per-packet cumulative bytes, one file per writer core,
//! `flow_features_tls_trace_{i}.parquet`.

use std::sync::OnceLock;

use arrow::datatypes::FieldRef;
use iris_core::CoreId;
use serde::Serialize;

use super::pool::{AnyPool, Pool, Shard};
use super::sink::{Sink, traced};

#[derive(Clone, Debug, Default, Serialize)]
pub struct TraceRecord {
    pub conn_hash: u64,        // full-tuple hash (1st half of the composite key)
    pub first_seen_ts: u64,    // connection first-seen, us (2nd half of the key)
    pub snapshot_ts: u64,      // per-packet arrival, us since UNIX_EPOCH
    pub cumulative_bytes: u64, // orig+resp payload bytes through this packet
}

/// No-op unless `init_writer` was called with `trace = true`.
pub fn write_trace_batch(rows: Vec<TraceRecord>, core: &CoreId) {
    if let (false, Some(p)) = (rows.is_empty(), POOL.get()) {
        p.dispatch(rows, core);
    }
}

static POOL: OnceLock<Pool<TraceShard>> = OnceLock::new();

pub(super) fn start(cores: &[CoreId]) {
    let open = |i| {
        TraceShard(Some(Sink::open(
            format!("flow_features_tls_trace_{i}"),
            fields(),
        )))
    };
    let _ = POOL.set(Pool::spawn("trace_writer", cores, open));
}

pub(super) fn pool() -> Option<&'static dyn AnyPool> {
    POOL.get().map(|p| p as &dyn AnyPool)
}

fn fields() -> &'static [FieldRef] {
    static F: OnceLock<Vec<FieldRef>> = OnceLock::new();
    F.get_or_init(|| traced(TraceRecord::default()))
}

/// `Option` so `close` can consume the sink exactly once.
struct TraceShard(Option<Sink>);

impl Shard for TraceShard {
    type Event = Vec<TraceRecord>;

    fn handle(&mut self, rows: Vec<TraceRecord>) {
        if let Some(s) = &mut self.0 {
            s.write(&rows);
        }
    }

    fn close(&mut self) {
        if let Some(s) = self.0.take() {
            s.close();
        }
    }
}
