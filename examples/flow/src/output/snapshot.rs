//! Stream 1: one row per flow snapshot, labelled with the flow's final totals,
//! sharded into `depth_{N}_core_{i}.parquet` by snapshot packet depth.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use arrow::datatypes::FieldRef;
use iris_core::CoreId;
use serde::Serialize;

use super::pool::{AnyPool, Pool, Shard};
use super::sink::{Sink, traced};
use crate::features::{conn_features::ConnFeatures, tls_features::TlsFeatures};

#[derive(Clone, Debug, Default, Serialize)]
pub struct FinalLabel {
    pub final_total_payload_bytes: u64,
    pub final_duration_ms: u64,
    pub final_total_pkts: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub conn: ConnFeatures,
    pub tls: Arc<TlsFeatures>,
}

/// Flush a terminated flow's buffered snapshots with its final label.
pub fn write_flow_batch(snaps: Vec<Snapshot>, label: FinalLabel, core: &CoreId) {
    if let (false, Some(p)) = (snaps.is_empty(), POOL.get()) {
        p.dispatch(FlowBatch { snaps, label }, core);
    }
}

static POOL: OnceLock<Pool<DepthShards>> = OnceLock::new();

pub(super) fn start(cores: &[CoreId]) {
    let _ = POOL.set(Pool::spawn("snapshot_writer", cores, |core| DepthShards {
        core,
        sinks: HashMap::new(),
    }));
}

pub(super) fn pool() -> Option<&'static dyn AnyPool> {
    POOL.get().map(|p| p as &dyn AnyPool)
}

#[derive(Clone, Serialize)]
struct FlowBatch {
    snaps: Vec<Snapshot>,
    label: FinalLabel,
}

/// Output row: conn + tls + label flattened into one record.
#[derive(Serialize)]
struct FlowRow<'a> {
    #[serde(flatten)]
    conn: &'a ConnFeatures,
    #[serde(flatten)]
    tls: &'a TlsFeatures,
    #[serde(flatten)]
    label: &'a FinalLabel,
}

fn fields() -> &'static [FieldRef] {
    static F: OnceLock<Vec<FieldRef>> = OnceLock::new();
    F.get_or_init(|| {
        let (c, t, l) = (
            ConnFeatures::default(),
            TlsFeatures::default(),
            FinalLabel::default(),
        );
        [traced(c), traced(t), traced(l)].concat()
    })
}

/// One writer thread's files: lazily opened, one per snapshot depth.
struct DepthShards {
    core: usize,
    sinks: HashMap<u64, Sink>,
}

impl Shard for DepthShards {
    type Event = FlowBatch;

    fn handle(&mut self, FlowBatch { snaps, label }: FlowBatch) {
        let mut by_depth: HashMap<u64, Vec<FlowRow>> = HashMap::new();
        for s in &snaps {
            let row = FlowRow {
                conn: &s.conn,
                tls: &s.tls,
                label: &label,
            };
            by_depth.entry(s.conn.pkt_snapshot).or_default().push(row);
        }
        let core = self.core;
        for (d, rows) in by_depth {
            self.sinks
                .entry(d)
                .or_insert_with(|| Sink::open(format!("depth_{d}_core_{core}"), fields()))
                .write(&rows);
        }
    }

    fn close(&mut self) {
        self.sinks.drain().for_each(|(_, s)| s.close());
    }
}
