// examples/flow/src/bin/flow_collect.rs

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use clap::Parser;
use iris_compiler::*;
use iris_core::{CoreId, L4Pdu, Runtime, config::load_config};
use iris_datatypes::conn_fts::InterArrivals;
use iris_datatypes::{ConnRecord, TlsHandshake};

use flow::features::conn_features::{ConnFeatures, ConnInvariants};
use flow::features::tls_features::TlsFeatures;
use flow::output::{self, FinalLabel, Snapshot, TraceRecord};

const TRACE_BATCH_N: usize = 64;
const WRITER_CORES: &[u32] = &[
    24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
];

static TRACE_ENABLED: AtomicBool = AtomicBool::new(true);

static DEPTHS: OnceLock<Vec<u64>> = OnceLock::new();

fn depths() -> &'static [u64] {
    DEPTHS.get().expect("depths set in main")
}

#[inline(always)]
fn trace_enabled() -> bool {
    TRACE_ENABLED.load(Ordering::Relaxed)
}

#[derive(Parser, Debug)]
struct Args {
    /// Path to the runtime config TOML (e.g. configs/online-train.toml).
    #[clap(
        short,
        long,
        value_parser,
        value_name = "FILE",
        default_value = "./configs/online.toml"
    )]
    config: PathBuf,

    /// Collect stream 2, the per-packet cumulative-bytes trace (A_i(t)).
    #[clap(long, action = clap::ArgAction::Set, default_value_t = true,
           num_args = 0..=1, default_missing_value = "true")]
    trace: bool,

    /// Output root for all shards and stats.
    #[clap(long, value_parser, value_name = "DIR")]
    out_dir: Option<PathBuf>,

    /// Packet depths for stream-1 snapshots, e.g. `--depths 5,10,40`.
    /// Sorted and deduplicated, and 1 is always included.
    #[clap(long, value_delimiter = ',', default_value = "1,5,10,20,40,80",
           value_parser = clap::value_parser!(u64).range(1..))]
    depths: Vec<u64>,
}

#[inline]
fn packet_wall_ts_us(conn: &ConnRecord) -> u64 {
    let delta_us = (conn.last_seen_ts - conn.first_seen_ts).as_micros() as u64;
    conn.first_seen_epoch_micros() + delta_us
}

#[callback("tls,level=InL4Conn")]
#[derive(Debug)]
struct PrefixSweep {
    snapshots: Vec<Snapshot>,
    next_depth_i: usize,
    baseline: Option<u64>,
    tls: Option<Arc<TlsFeatures>>,
    inv: Option<ConnInvariants>,
    trace_batch: Vec<TraceRecord>,
    key: Option<(u64, u64)>,
}

impl StreamingCallback for PrefixSweep {
    fn new(_first_pkt: &L4Pdu) -> PrefixSweep {
        PrefixSweep {
            snapshots: Vec::with_capacity(depths().len()),
            next_depth_i: 0,
            baseline: None,
            tls: None,
            inv: None,
            trace_batch: Vec::with_capacity(if trace_enabled() { TRACE_BATCH_N } else { 0 }),
            key: None,
        }
    }

    fn clear(&mut self) {
        self.snapshots = Vec::new();
        self.trace_batch = Vec::new();
    }
}

impl PrefixSweep {
    #[inline]
    fn conn_key(&mut self, conn: &ConnRecord) -> (u64, u64) {
        *self
            .key
            .get_or_insert_with(|| (conn.five_tuple.conn_hash(), conn.first_seen_epoch_micros()))
    }

    fn record_trace(&mut self, conn: &ConnRecord, core_id: &CoreId) {
        let (conn_hash, first_seen_ts) = self.conn_key(conn);
        self.trace_batch.push(TraceRecord {
            conn_hash,
            first_seen_ts,
            snapshot_ts: packet_wall_ts_us(conn),
            cumulative_bytes: conn.total_payload_bytes(),
        });
        if self.trace_batch.len() >= TRACE_BATCH_N {
            let full = std::mem::replace(&mut self.trace_batch, Vec::with_capacity(TRACE_BATCH_N));
            output::write_trace_batch(full, core_id);
        }
    }

    fn record_snapshots(&mut self, conn: &ConnRecord, iat: &InterArrivals, tls: &TlsHandshake) {
        let total = conn.total_pkts();
        let pkts = total - *self.baseline.get_or_insert(total);
        let Some(&next_depth) = depths().get(self.next_depth_i) else {
            return;
        };
        if pkts < next_depth {
            return;
        }
        if self.tls.is_none() {
            self.tls = TlsFeatures::from_tls(tls).map(Arc::new);
        }
        let (conn_hash, first_seen_ts) = self.conn_key(conn);
        let Some(tls_features) = &self.tls else {
            return;
        };
        let inv = self
            .inv
            .get_or_insert_with(|| ConnInvariants::from_conn(conn, conn_hash, first_seen_ts));
        while let Some(&depth) = depths().get(self.next_depth_i).filter(|&&d| d <= pkts) {
            if let Some(cf) = ConnFeatures::from_conn_at(conn, iat, depth, inv) {
                self.snapshots.push(Snapshot {
                    conn: cf,
                    tls: Arc::clone(tls_features),
                });
            }
            self.next_depth_i += 1;
        }
    }

    #[callback_fn("PrefixSweep,level=InL4Conn")]
    fn on_packet(
        &mut self,
        conn: &ConnRecord,
        iat: &InterArrivals,
        tls: &TlsHandshake,
        core_id: &CoreId,
    ) -> bool {
        if trace_enabled() {
            self.record_trace(conn, core_id);
        }
        self.record_snapshots(conn, iat, tls);
        true
    }

    #[callback_fn("PrefixSweep,level=L4Terminated")]
    fn on_terminate(&mut self, conn: &ConnRecord, core_id: &CoreId) -> bool {
        if !self.trace_batch.is_empty() {
            output::write_trace_batch(std::mem::take(&mut self.trace_batch), core_id);
        }
        if !self.snapshots.is_empty() {
            let label = FinalLabel {
                final_total_payload_bytes: conn.total_payload_bytes(),
                final_duration_ms: conn.duration().as_millis() as u64,
                final_total_pkts: conn.total_pkts(),
            };
            output::write_flow_batch(std::mem::take(&mut self.snapshots), label, core_id);
        }
        true
    }
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    let args = Args::parse();
    TRACE_ENABLED.store(args.trace, Ordering::Relaxed);
    DEPTHS
        .set(
            args.depths
                .into_iter()
                .chain([1])
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        )
        .expect("depths set once");
    println!("Stream-1 snapshot depths: {:?}", depths());
    if let Some(dir) = args.out_dir {
        output::set_out_dir(dir);
    }

    let config = load_config(args.config.to_str().expect("Invalid config path"));
    output::init_writer(
        WRITER_CORES.iter().map(|&c| CoreId(c)).collect(),
        args.trace,
    );

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    output::shutdown_writer();
    output::print_stats();
}
