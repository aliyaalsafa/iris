// examples/flow/src/bin/flow_collect.rs
use clap::Parser;
use flow::features::conn_features::{ConnFeatures, ConnInvariants};
use flow::features::tls_features::TlsFeatures;
use iris_compiler::*;
use iris_core::{CoreId, L4Pdu, Runtime, config::load_config};
use iris_datatypes::conn_fts::InterArrivals;
use iris_datatypes::{ConnRecord, TlsHandshake};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use flow::output::{self, FinalLabel, Snapshot, TraceRecord};

const SNAPSHOT_DEPTHS: &[u64] = &[1, 5, 10, 20, 40, 80];
/// Stream-2 trace flush granularity (one record per packet -> flush a bit larger).
const TRACE_BATCH_N: usize = 64;
const WRITER_CORES: &[u32] = &[
    24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46,
];
static TRACE_ENABLED: AtomicBool = AtomicBool::new(true);
#[inline(always)]
fn trace_enabled() -> bool {
    TRACE_ENABLED.load(Ordering::Relaxed)
}
// ===== CLI =====
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
    /// Print parsed args and exit-adjacent debug info.
    #[clap(long, action = clap::ArgAction::SetTrue)]
    show_args: bool,
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
    /// TLS handshake features, computed once and reused (immutable post-handshake).
    tls: Option<std::sync::Arc<TlsFeatures>>,
    /// Per-connection invariant features, computed once on first packet.
    inv: Option<ConnInvariants>,
    trace_batch: Vec<TraceRecord>,
    key: Option<(u64, u64)>,
}
impl StreamingCallback for PrefixSweep {
    fn new(_first_pkt: &L4Pdu) -> PrefixSweep {
        PrefixSweep {
            snapshots: Vec::with_capacity(SNAPSHOT_DEPTHS.len()),
            next_depth_i: 0,
            tls: None,
            inv: None,
            trace_batch: if trace_enabled() {
                Vec::with_capacity(TRACE_BATCH_N)
            } else {
                Vec::new()
            },
            key: None,
        }
    }
    fn clear(&mut self) {
        self.snapshots = Vec::with_capacity(0);
        self.trace_batch = Vec::with_capacity(0);
    }
}
impl PrefixSweep {
    #[inline]
    fn conn_key(&mut self, conn: &ConnRecord) -> (u64, u64) {
        *self
            .key
            .get_or_insert_with(|| (conn.five_tuple.conn_hash(), conn.first_seen_epoch_micros()))
    }
    #[callback_fn("PrefixSweep,level=InL4Conn")]
    fn on_packet(
        &mut self,
        conn: &ConnRecord,
        iat: &InterArrivals,
        tls: &TlsHandshake,
        core_id: &CoreId,
    ) -> bool {
        let total = conn.total_pkts();
        if trace_enabled() {
            let (conn_hash, first_seen_ts) = self.conn_key(conn);
            self.trace_batch.push(TraceRecord {
                conn_hash,
                first_seen_ts,
                snapshot_ts: packet_wall_ts_us(conn),
                cumulative_bytes: conn.total_payload_bytes(),
            });
            if self.trace_batch.len() >= TRACE_BATCH_N {
                output::write_trace_batch(
                    std::mem::replace(&mut self.trace_batch, Vec::with_capacity(TRACE_BATCH_N)),
                    core_id,
                );
            }
        }
        // --- Stream 1: buffer full feature snapshots (gated on TLS presence) -
        if self.tls.is_none() {
            self.tls = TlsFeatures::from_tls(tls).map(std::sync::Arc::new);
        }
        let Some(tls_features) = self.tls.as_ref() else {
            return true;
        };
        if self.next_depth_i >= SNAPSHOT_DEPTHS.len() {
            return true;
        }
        if total < SNAPSHOT_DEPTHS[self.next_depth_i] {
            return true;
        }
        let tls_arc = std::sync::Arc::clone(tls_features);
        let (conn_hash, first_seen_ts) = self.conn_key(conn);
        let inv = self
            .inv
            .get_or_insert_with(|| ConnInvariants::from_conn(conn, conn_hash, first_seen_ts));
        while self.next_depth_i < SNAPSHOT_DEPTHS.len()
            && SNAPSHOT_DEPTHS[self.next_depth_i] <= total
        {
            let bucket = SNAPSHOT_DEPTHS[self.next_depth_i];
            if let Some(cf) = ConnFeatures::from_conn_at(conn, iat, bucket, inv) {
                self.snapshots.push(Snapshot {
                    conn: cf,
                    tls: std::sync::Arc::clone(&tls_arc),
                });
            }
            self.next_depth_i += 1;
        }
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
    // Parse CLI args (config path selectable per train/test run).
    let args = Args::parse();
    if args.show_args {
        println!("{args:#?}");
    }
    let config_path = args.config.to_str().expect("Invalid config path");
    println!("Loading config from {config_path}");
    TRACE_ENABLED.store(args.trace, Ordering::Relaxed);
    println!("Stream-1 snapshot depths: {SNAPSHOT_DEPTHS:?}");
    println!(
        "Stream-2 per-packet trace: {}",
        if args.trace {
            "ENABLED (bandwidth_sim.py can run against this capture)"
        } else {
            "DISABLED (--no-trace; classifier.py only -- bandwidth_sim.py CANNOT run against this capture)"
        }
    );
    debug_assert!(
        !SNAPSHOT_DEPTHS.is_empty(),
        "SNAPSHOT_DEPTHS must not be empty"
    );
    debug_assert!(
        SNAPSHOT_DEPTHS.windows(2).all(|w| w[0] < w[1]),
        "SNAPSHOT_DEPTHS must be strictly ascending"
    );
    debug_assert!(
        SNAPSHOT_DEPTHS.first() == Some(&1),
        "SNAPSHOT_DEPTHS must include depth 1 (classifier.py's global elephant threshold)"
    );
    if let Some(dir) = args.out_dir.as_ref() {
        let s = dir.to_str().expect("--out-dir is not valid UTF-8");
        output::set_out_dir(s);
    }
    let config = load_config(config_path);
    let writer_handles = output::init_writer(
        WRITER_CORES.iter().map(|&c| CoreId(c)).collect(),
        args.trace,
    );
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();
    output::shutdown_writer(writer_handles);
    output::print_stats();
}
