use crate::features::conn_features::ConnFeatures;
use crate::features::tls_features::TlsFeatures;
use serde::Serialize;
use serde_arrow::schema::{SchemaLike, TracingOptions};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::sync::{Arc, Mutex, OnceLock};

use arrow::datatypes::{FieldRef, Schema};
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::{WriterProperties, WriterVersion};

use iris_core::CoreId;
use iris_core::multicore::{
    ChannelDispatcher, ChannelMode, DedicatedWorkerHandle, DedicatedWorkerThreadSpawner,
};

const CHANNEL_CAP: usize = 1 << 18;

const MAX_ROW_GROUP_ROWS: usize = 1 << 17;

const ZSTD_LEVEL: i32 = 3;

/// File extension for the shards. Both streams are now Parquet.
const SHARD_EXT: &str = "parquet";

const DEFAULT_OUT_DIR: &str = "/mnt/netdata/";
const OUT_DIR_ENV: &str = "FLOW_OUT_DIR";
static OUT_DIR_CELL: OnceLock<String> = OnceLock::new();

pub fn set_out_dir(dir: &str) {
    let mut d = dir.to_string();
    if !d.ends_with('/') {
        d.push('/');
    }
    let _ = OUT_DIR_CELL.set(d);
}

fn out_dir() -> &'static str {
    OUT_DIR_CELL.get_or_init(|| {
        let mut d = std::env::var(OUT_DIR_ENV).unwrap_or_else(|_| DEFAULT_OUT_DIR.to_string());
        if !d.ends_with('/') {
            d.push('/');
        }
        d
    })
}

// Stream-1 per-(depth,core) shard basename: depth_{N}_core_{i}.parquet (under out_dir())
const DEPTH_PREFIX: &str = "depth_";
// Stream-2 per-core trace basename: flow_features_tls_trace_{i}.parquet (under out_dir())
const TRACE_PREFIX: &str = "flow_features_tls_trace_";
// Writer-dispatcher stats are also persisted here (under out_dir()).
const STATS_FILE: &str = "writer_stats.txt";

type ParquetSink = ArrowWriter<File>;

fn writer_props() -> WriterProperties {
    WriterProperties::builder()
        .set_compression(Compression::ZSTD(
            ZstdLevel::try_new(ZSTD_LEVEL).expect("valid zstd level"),
        ))
        .set_max_row_group_size(MAX_ROW_GROUP_ROWS)
        .set_writer_version(WriterVersion::PARQUET_2_0)
        .build()
}

/// Build a Parquet writer at `path` for the given fields.
fn parquet_writer(path: &str, fields: &[FieldRef]) -> ParquetSink {
    let file = File::create(path).unwrap_or_else(|e| panic!("could not create shard {path}: {e}"));
    let schema = Arc::new(Schema::new(fields.to_vec()));
    ArrowWriter::try_new(file, schema, Some(writer_props()))
        .unwrap_or_else(|e| panic!("could not init parquet writer for {path}: {e}"))
}

fn traced_fields<T: Serialize>(sample: T) -> Vec<FieldRef> {
    Vec::<FieldRef>::from_samples(&[sample], TracingOptions::default())
        .expect("serde_arrow could not trace output schema")
}

fn flow_fields() -> &'static [FieldRef] {
    static FIELDS: OnceLock<Vec<FieldRef>> = OnceLock::new();
    FIELDS.get_or_init(|| {
        let mut fields = traced_fields(ConnFeatures::default());
        fields.extend(traced_fields(TlsFeatures::default()));
        fields.extend(traced_fields(FinalLabel::default()));
        fields
    })
}

fn trace_fields() -> &'static [FieldRef] {
    static FIELDS: OnceLock<Vec<FieldRef>> = OnceLock::new();
    FIELDS.get_or_init(|| traced_fields(TraceRecord::default()))
}

#[derive(Serialize)]
struct FlowRow<'a> {
    #[serde(flatten)]
    conn: &'a ConnFeatures,
    #[serde(flatten)]
    tls: &'a TlsFeatures,
    #[serde(flatten)]
    label: &'a FinalLabel,
}

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

#[derive(Clone, Debug, Default, Serialize)]
pub struct TraceRecord {
    pub conn_hash: u64, // full-tuple u64 hash (1st half of the composite connection key)
    pub first_seen_ts: u64, // connection first-seen wall clock, us (2nd half of the key)
    pub snapshot_ts: u64, // microseconds since UNIX_EPOCH (per-packet arrival)
    pub cumulative_bytes: u64, // running orig+resp payload bytes through this packet
}

#[derive(Clone, Serialize)]
pub enum WriteEvent {
    FlowBatch {
        snaps: Vec<Snapshot>,
        label: FinalLabel,
    },
    TraceBatch { rows: Vec<TraceRecord> },
}

struct Sinks {
    core_idx: usize,
    depth_writers: HashMap<u64, ParquetSink>,
    trace: Option<ParquetSink>,
}

impl Sinks {
    /// Get (creating if needed) the stream-1 writer for `depth` on this core.
    fn depth_writer(&mut self, depth: u64) -> &mut ParquetSink {
        let core_idx = self.core_idx;
        self.depth_writers.entry(depth).or_insert_with(|| {
            let path = format!(
                "{}{DEPTH_PREFIX}{depth}_core_{core_idx}.{SHARD_EXT}",
                out_dir()
            );
            parquet_writer(&path, flow_fields())
        })
    }

    fn close_all(&mut self) {
        for (depth, w) in self.depth_writers.drain() {
            if let Err(e) = w.close() {
                eprintln!(
                    "warning: failed closing depth {depth} shard on core {}: {e}",
                    self.core_idx
                );
            }
        }
        if let Some(w) = self.trace.take() {
            if let Err(e) = w.close() {
                eprintln!(
                    "warning: failed closing trace shard on core {}: {e}",
                    self.core_idx
                );
            }
        }
    }
}

struct WriterPool {
    dispatchers: Vec<Arc<ChannelDispatcher<WriteEvent>>>,
    sinks: Vec<Arc<Mutex<Sinks>>>,
    n: usize,
}

static POOL: OnceLock<WriterPool> = OnceLock::new();

pub fn init_writer(
    worker_cores: Vec<CoreId>,
    trace: bool,
) -> Vec<DedicatedWorkerHandle<WriteEvent>> {
    println!(
        "Writing output to {} (parquet, zstd level {ZSTD_LEVEL}, row-group {MAX_ROW_GROUP_ROWS} rows, shards *.{SHARD_EXT}, trace {})",
        out_dir(),
        if trace { "on" } else { "off" }
    );
    let mut dispatchers = Vec::with_capacity(worker_cores.len());
    let mut sinks_vec = Vec::with_capacity(worker_cores.len());
    let mut handles = Vec::with_capacity(worker_cores.len());
    for (i, core) in worker_cores.iter().enumerate() {
        let dispatcher = Arc::new(ChannelDispatcher::new(
            ChannelMode::Shared,
            CHANNEL_CAP,
            format!("flow_writer_{i}"),
        ));
        let sinks = Arc::new(Mutex::new(Sinks {
            core_idx: i,
            depth_writers: HashMap::new(),
            trace: if trace {
                Some(parquet_writer(
                    &format!("{}{TRACE_PREFIX}{i}.{SHARD_EXT}", out_dir()),
                    trace_fields(),
                ))
            } else {
                None
            },
        }));
        let handler_sinks = sinks.clone();
        let handle = DedicatedWorkerThreadSpawner::new()
            .set_cores(vec![*core])
            .set_dispatcher(dispatcher.clone())
            .set_handler(move |event: WriteEvent| {
                let mut s = handler_sinks.lock().unwrap();
                match event {
                    WriteEvent::FlowBatch { snaps, label } => {
                        let mut by_depth: HashMap<u64, Vec<FlowRow>> = HashMap::new();
                        for snap in &snaps {
                            by_depth
                                .entry(snap.conn.pkt_snapshot)
                                .or_default()
                                .push(FlowRow {
                                    conn: &snap.conn,
                                    tls: &snap.tls,
                                    label: &label,
                                });
                        }
                        for (depth, rows) in by_depth {
                            let batch = match serde_arrow::to_record_batch(flow_fields(), &rows) {
                                Ok(batch) => batch,
                                Err(e) => {
                                    eprintln!("warning: failed building depth {depth} batch: {e}");
                                    continue;
                                }
                            };
                            if let Err(e) = s.depth_writer(depth).write(&batch) {
                                eprintln!("warning: failed writing depth {depth} batch: {e}");
                            }
                        }
                    }
                    WriteEvent::TraceBatch { rows } => {
                        if let Some(w) = s.trace.as_mut() {
                            match serde_arrow::to_record_batch(trace_fields(), &rows) {
                                Ok(batch) => {
                                    if let Err(e) = w.write(&batch) {
                                        eprintln!("warning: failed writing trace batch: {e}");
                                    }
                                }
                                Err(e) => eprintln!("warning: failed building trace batch: {e}"),
                            }
                        }
                    }
                }
            })
            .run();
        dispatchers.push(dispatcher);
        sinks_vec.push(sinks);
        handles.push(handle);
    }
    let n = dispatchers.len();
    POOL.set(WriterPool {
        dispatchers,
        sinks: sinks_vec,
        n,
    })
    .ok();
    handles
}

pub fn shutdown_writer(handles: Vec<DedicatedWorkerHandle<WriteEvent>>) {
    if let Some(pool) = POOL.get() {
        for d in &pool.dispatchers {
            d.close_channels();
        }
    }
    for h in handles {
        let _ = h.shutdown(None);
    }
    if let Some(pool) = POOL.get() {
        for sinks in &pool.sinks {
            sinks.lock().unwrap().close_all();
        }
    }
}

pub fn print_stats() {
    if let Some(pool) = POOL.get() {
        // Build the full report once, then emit to both stdout and the file.
        let mut report = String::new();
        report.push_str("=== Writer Dispatcher Stats ===\n");
        for (i, d) in pool.dispatchers.iter().enumerate() {
            report.push_str(&format!("[writer {i}]\n"));
            report.push_str(&format!("{}\n", d.stats()));
        }
        print!("{report}");
        let path = format!("{}{STATS_FILE}", out_dir());
        match File::create(&path) {
            Ok(f) => {
                let mut w = BufWriter::new(f);
                if let Err(e) = w.write_all(report.as_bytes()) {
                    eprintln!("warning: failed writing stats to {path}: {e}");
                } else {
                    println!("Wrote writer stats to {path}");
                }
            }
            Err(e) => eprintln!("warning: could not create stats file {path}: {e}"),
        }
    }
}

/// Flush a terminated flow's buffered stream-1 snapshots with its final label.
pub fn write_flow_batch(snaps: Vec<Snapshot>, label: FinalLabel, core: &CoreId) {
    if snaps.is_empty() {
        return;
    }
    if let Some(pool) = POOL.get() {
        let idx = core.raw() as usize % pool.n;
        let _ = pool.dispatchers[idx].dispatch(WriteEvent::FlowBatch { snaps, label }, None);
    }
}

pub fn write_trace_batch(rows: Vec<TraceRecord>, core: &CoreId) {
    if rows.is_empty() {
        return;
    }
    if let Some(pool) = POOL.get() {
        let idx = core.raw() as usize % pool.n;
        let _ = pool.dispatchers[idx].dispatch(WriteEvent::TraceBatch { rows }, None);
    }
}
