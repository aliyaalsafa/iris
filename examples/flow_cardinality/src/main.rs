//! Counts distinct five-tuples per second over **every packet the datapath receives**,
//! rather than over the connections Iris chooses to track.
//!
//! Two series, both credited to the second the packet arrived in:
//!
//!   directional     each `(src, sport, dst, dport, proto)` as seen on the wire, so
//!                   A->B and B->A are two
//!   bidirectional   endpoints canonicalized, so A->B and B->A are one -- the same
//!                   notion of "a flow" Iris' connection tracking uses
//!
//! A live line goes to stdout every `--print-interval` seconds; the full per-second
//! series is written to `--csv` at shutdown.
//!
//! ## Why this needs a core hook
//!
//! Every ordinary Iris subscription is scoped to a connection, and connection tracking
//! is lossy for this particular question: a TCP connection is only built from a pure
//! SYN, so mid-stream TCP never enters the table; packets that are not IPv4/IPv6 +
//! TCP/UDP are dropped before any callback; and once `max_connections` is reached new
//! flows are dropped wholesale. A packet-level subscription does not exist -- the
//! compiler panics on one outright. So this app installs an
//! [`iris_core::lcore::packet_tap`] instead, which runs ahead of the software flow
//! table and the generated packet filter.
//!
//! Comparing this app's bidirectional count against `flow_arrivals`, which counts the
//! same traffic through ordinary callbacks, measures exactly what conntrack discards.
//!
//! ## What the numbers do and don't include
//!
//! - Counted: every mbuf the processing datapath received, including ones a software
//!   flow-table drop rule sheds.
//! - Not counted: traffic steered to a sink queue (`rx_sink` is a drain, not part of
//!   the pipeline), and packets a hardware `rte_flow` rule dropped, which never reach
//!   `rte_eth_rx_burst` at all.
//! - Packets with no five-tuple -- ARP, ICMP, malformed, non-Ethernet -- are reported
//!   separately as `unparsed` rather than silently ignored. That column is an exact
//!   counter, not an estimate.
//! - **Per-second estimates do not sum to the run total.** A flow spanning three
//!   seconds appears in all three buckets. The run total comes from a separate
//!   run-wide sketch and is the only number comparable against ground truth.
//! - Counts are HyperLogLog estimates, so they carry a relative standard error of
//!   `1.04/sqrt(2^p)` -- 1.6% at the default `--precision 12`. Sketches merge exactly
//!   across cores, so a flow whose two directions land on different RX cores via
//!   non-symmetric RSS is still counted once in the bidirectional series.
//! - Both keys derive from FNV-1a hashes that fold an IPv6 address in half and shift
//!   the top 16 bits of the fold away, so IPv6 endpoints differing only in those bits
//!   alias. At ~1M IPv6 endpoints that is a sub-percent error floor; for IPv4 the
//!   packing is injective and there is none.
//! - Offline runs timestamp by Iris observation time, not pcap capture time, so a pcap
//!   replays into the first second or two and only the run totals are meaningful.
//!   `--exact` is the way to check correctness offline.

use clap::Parser;
use iris_compiler::*;
use iris_core::config::load_config;
use iris_core::lcore::packet_tap;
use iris_core::{CoreId, FiveTuple, L4Context, Mbuf, Runtime};

use std::collections::HashSet;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

mod hll;
use hll::{estimate, fmix64};

// ===== Series =====

const DIR: usize = 0;
const BIDIR: usize = 1;
const NSERIES: usize = 2;
const SERIES_NAMES: [&str; NSERIES] = ["directional", "bidirectional"];

// ===== Per-core state =====

/// One core's sketches. Only that core's RX thread writes them, so no register is ever
/// contended -- the `transport_meter` pattern, sharded by second as well as by core so
/// a packet lands straight in its own second's slot and no sampling thread is needed.
///
/// All of a core's per-second sketches live in a single allocation, laid out
/// `[second][series][register]`. That is not just tidiness: allocating each 4 KiB sketch
/// separately makes the whole grid resident at startup, because glibc serves anything
/// under its 128 KiB mmap threshold from the heap arena and zeroes it by hand. One
/// multi-megabyte slab is mapped lazily instead, so reserving an hour of seconds for a
/// two-minute run costs address space rather than memory.
#[repr(align(64))]
struct CoreSketches {
    /// `[second][series]`, each `2^p` registers, contiguous.
    secs: Box<[AtomicU8]>,
    /// `[series]`. The run-wide union, kept apart because per-second estimates do not
    /// sum to it.
    totals: Box<[AtomicU8]>,
    /// Packets with no five-tuple, per second. Exact, not estimated.
    unparsed: Box<[AtomicU64]>,
    /// Registers per sketch, i.e. `2^p`.
    m: usize,
}

impl CoreSketches {
    fn new(nsecs: usize, p: u32) -> Self {
        let m = 1usize << p;
        Self {
            secs: hll::zeroed(nsecs * NSERIES * m),
            totals: hll::zeroed(NSERIES * m),
            unparsed: (0..nsecs)
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
            m,
        }
    }

    /// This core's sketches for `sec`, one per series back to back, or `None` past the
    /// end of the grid. Split with `chunks_exact(self.m)`.
    #[inline]
    fn sec(&self, sec: usize) -> Option<&[AtomicU8]> {
        let width = NSERIES * self.m;
        self.secs.get(sec * width..(sec + 1) * width)
    }

    /// This core's run-wide sketches, one per series back to back.
    #[inline]
    fn total(&self) -> &[AtomicU8] {
        &self.totals
    }
}

static GRID: OnceLock<Vec<CoreSketches>> = OnceLock::new();
/// Baseline for the second index. Set once the runtime is built, just before it runs,
/// so EAL initialisation does not burn the first buckets.
static START: OnceLock<Instant> = OnceLock::new();
/// Packets counted in the run totals but missing from the per-second series, because
/// their second or core id fell outside the grid. A bookkeeping shortfall in this app,
/// not packet loss -- the online monitor reports that separately as `HW/SW Dropped`.
static UNFILED: AtomicU64 = AtomicU64::new(0);
/// Every packet the tap was handed, parseable or not.
static TAPPED: AtomicU64 = AtomicU64::new(0);
static RUNNING: AtomicBool = AtomicBool::new(true);

/// Ground-truth sets for `--exact`. Off the datapath's fast path only because this
/// mode is documented as offline, single-core, unbounded-memory debugging.
static EXACT: OnceLock<[Mutex<HashSet<u64>>; NSERIES]> = OnceLock::new();

fn grid() -> &'static Vec<CoreSketches> {
    GRID.get().expect("grid() before init_grid()")
}

fn init_grid(ncores: usize, nsecs: usize, p: u32) {
    let _ = GRID.set((0..ncores).map(|_| CoreSketches::new(nsecs, p)).collect());
}

// ===== The tap =====

/// Invoked for every packet the datapath receives, inline on the RX core.
fn observe(mbuf: &Mbuf, core_id: &CoreId, now: Instant) {
    TAPPED.fetch_add(1, Ordering::Relaxed);

    let Some(core) = grid().get(core_id.raw() as usize) else {
        UNFILED.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let base = START.get().expect("START unset");
    let sec = now.saturating_duration_since(*base).as_secs() as usize;

    // No five-tuple to count: ARP, ICMP, malformed, anything not IPv4/IPv6 + TCP/UDP.
    let Ok(ctxt) = L4Context::new(mbuf) else {
        match core.unparsed.get(sec) {
            Some(c) => {
                c.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                UNFILED.fetch_add(1, Ordering::Relaxed);
            }
        }
        return;
    };

    let five_tuple = FiveTuple::from_ctxt(&ctxt);
    // fmix64 is not optional -- see its doc comment. Without it, structured traffic
    // drives the register index far from uniform and the estimate off by tens of
    // percent.
    let keys = [
        fmix64(five_tuple.dir_hash()),
        fmix64(five_tuple.conn_hash()),
    ];

    for (regs, &key) in core.total().chunks_exact(core.m).zip(keys.iter()) {
        hll::add(regs, key);
    }
    match core.sec(sec) {
        Some(block) => {
            for (regs, &key) in block.chunks_exact(core.m).zip(keys.iter()) {
                hll::add(regs, key);
            }
        }
        // Still in the run totals above, just off the end of the series.
        None => {
            UNFILED.fetch_add(1, Ordering::Relaxed);
        }
    }

    if let Some(exact) = EXACT.get() {
        for (set, &key) in exact.iter().zip(keys.iter()) {
            set.lock().expect("exact set poisoned").insert(key);
        }
    }
}

// ===== Reading the grid back =====

/// Merge one second's slot across every core, then estimate. Merging before estimating
/// is what makes the cross-core case correct; summing per-core estimates would
/// double-count.
fn second_estimate(sec: usize) -> [f64; NSERIES] {
    std::array::from_fn(|series| {
        let mut acc = vec![0u8; registers_per_sketch()];
        for core in grid() {
            if let Some(block) = core.sec(sec) {
                hll::merge_into(&block[series * core.m..(series + 1) * core.m], &mut acc);
            }
        }
        estimate(&acc)
    })
}

/// The run-wide union across every core.
fn total_estimate() -> [f64; NSERIES] {
    std::array::from_fn(|series| {
        let mut acc = vec![0u8; registers_per_sketch()];
        for core in grid() {
            let total = core.total();
            hll::merge_into(&total[series * core.m..(series + 1) * core.m], &mut acc);
        }
        estimate(&acc)
    })
}

fn unparsed_in(sec: usize) -> u64 {
    grid()
        .iter()
        .map(|c| c.unparsed[sec].load(Ordering::Relaxed))
        .sum()
}

fn registers_per_sketch() -> usize {
    grid()[0].m
}

fn series_len() -> usize {
    grid().first().map_or(0, |c| c.unparsed.len())
}

// ===== Reporting =====

#[derive(Parser, Debug)]
struct Args {
    #[clap(
        short,
        long,
        parse(from_os_str),
        value_name = "FILE",
        default_value = "./configs/offline.toml"
    )]
    config: PathBuf,

    /// Where to write the full per-second series at shutdown.
    #[clap(long, parse(from_os_str), default_value = "./flow_cardinality.csv")]
    csv: PathBuf,

    /// Seconds between live stdout lines.
    #[clap(long, default_value = "30")]
    print_interval: u64,

    /// HyperLogLog precision: 2^p registers per sketch, one byte each. The relative
    /// standard error is 1.04/sqrt(2^p), so 12 gives 1.6% from 4 KiB.
    #[clap(long, default_value = "12")]
    precision: u32,

    /// Seconds of grid to reserve. Defaults to `[online] duration` plus a minute, or
    /// 3600 if unset. Reserved seconds cost address space, not resident memory.
    #[clap(long)]
    max_seconds: Option<usize>,

    /// Refuse to start if the grid would reserve more than this many MiB.
    #[clap(long, default_value = "4096")]
    max_reserve_mib: usize,

    /// Also keep exact sets of both keys and print them beside the estimates.
    /// Unbounded memory: for offline validation against a pcap, not for live runs.
    #[clap(long)]
    exact: bool,
}

/// Live line: the run-wide distinct count so far, plus the most recent completed
/// second. A cumulative sketch cannot be differenced, so there is no "rate" here --
/// the per-second buckets already are the rate.
fn print_live(elapsed: Duration, totals: &[f64; NSERIES], last: Option<(usize, [f64; NSERIES])>) {
    let mut line = format!("[flow_cardinality t={:>5.0}s] total", elapsed.as_secs_f64());
    for s in 0..NSERIES {
        line += &format!(" {}={:.0}", SERIES_NAMES[s], totals[s]);
    }
    if let Some((sec, row)) = last {
        line += &format!(" | sec {sec}");
        for s in 0..NSERIES {
            line += &format!(" {}={:.0}", SERIES_NAMES[s], row[s]);
        }
    }
    println!("{line}");
}

/// One row per second, trimmed to the last second with any activity.
fn write_csv(path: &PathBuf) -> std::io::Result<usize> {
    let rows: Vec<(usize, [f64; NSERIES], u64)> = (0..series_len())
        .map(|sec| (sec, second_estimate(sec), unparsed_in(sec)))
        .collect();
    let last = rows
        .iter()
        .rposition(|(_, est, unparsed)| est.iter().any(|&v| v > 0.0) || *unparsed > 0)
        .map_or(0, |i| i + 1);

    let mut w = BufWriter::new(File::create(path)?);
    writeln!(
        w,
        "second,distinct_directional,distinct_bidirectional,unparsed"
    )?;
    for (sec, est, unparsed) in &rows[..last] {
        writeln!(w, "{sec},{:.0},{:.0},{unparsed}", est[DIR], est[BIDIR])?;
    }
    w.flush()?;
    Ok(last)
}

// No `#[callback]` anywhere in this crate: the tap is the whole datapath hook, and
// declaring a subscription would switch connection tracking back on for traffic
// nothing here reads.
#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros(no_subscriptions)]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    let p = args.precision;
    assert!(
        (hll::MIN_PRECISION..=hll::MAX_PRECISION).contains(&p),
        "--precision must be between {} and {}",
        hll::MIN_PRECISION,
        hll::MAX_PRECISION
    );

    // One slot per core id, indexed by raw id, so the tap needs no lookup table.
    let ncores = config
        .get_all_core_ids()
        .iter()
        .map(|c| c.raw() as usize + 1)
        .max()
        .unwrap_or(1);
    let nsecs = args.max_seconds.unwrap_or_else(|| {
        config
            .online
            .as_ref()
            .and_then(|o| o.duration)
            .map_or(3600, |d| d as usize + 60)
    });

    // Reserved, not resident: the sketches are allocated zeroed, so a second that is
    // never written is never faulted in. Resident memory grows at the per-second
    // figure below as the run proceeds.
    let reserve = ncores * nsecs * NSERIES * (1usize << p);
    let per_sec = ncores * NSERIES * (1usize << p);
    let mib = |b: usize| b as f64 / (1024.0 * 1024.0);
    assert!(
        mib(reserve) <= args.max_reserve_mib as f64,
        "grid would reserve {:.1} MiB, over the {} MiB limit; lower --max-seconds or \
         --precision, or raise --max-reserve-mib",
        mib(reserve),
        args.max_reserve_mib
    );
    println!(
        "flow_cardinality: p={p} (m={}, sigma={:.2}%), {ncores} core slots x {nsecs} s \
         x {NSERIES} series = {:.1} MiB reserved, ~{:.0} KiB/s resident",
        1usize << p,
        hll::std_error(p) * 100.0,
        mib(reserve),
        per_sec as f64 / 1024.0,
    );

    init_grid(ncores, nsecs, p);
    if args.exact {
        println!("flow_cardinality: --exact on; keeping unbounded ground-truth sets");
        let _ = EXACT.set(std::array::from_fn(|_| Mutex::new(HashSet::new())));
    }

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();

    // Only now, once EAL and the ports are up, does second 0 begin -- otherwise
    // initialisation would eat the first buckets.
    let start = Instant::now();
    START.set(start).expect("START already set");
    packet_tap::install(observe).expect("a packet tap is already installed");

    // No app-level periodic hook exists (the 1Hz Monitor is core-internal and online
    // only), so live reporting is our own thread. It only reads.
    let interval = Duration::from_secs(args.print_interval.max(1));
    let reporter = std::thread::spawn(move || {
        let mut next_print = interval;
        while RUNNING.load(Ordering::Relaxed) {
            // Short naps so shutdown is prompt rather than up to `interval` late.
            std::thread::sleep(Duration::from_millis(250));
            let elapsed = start.elapsed();
            if elapsed < next_print {
                continue;
            }
            // The second before the current one, which is the newest complete bucket.
            let last = (elapsed.as_secs() as usize)
                .checked_sub(1)
                .filter(|&s| s < series_len())
                .map(|s| (s, second_estimate(s)));
            print_live(elapsed, &total_estimate(), last);
            next_print = elapsed + interval;
        }
    });

    runtime.run();

    RUNNING.store(false, Ordering::Relaxed);
    let _ = reporter.join();

    let elapsed = start.elapsed().as_secs_f64();
    let totals = total_estimate();
    let tapped = TAPPED.load(Ordering::Relaxed);
    let unparsed: u64 = (0..series_len()).map(unparsed_in).sum();

    println!("\n=== distinct five-tuples over {elapsed:.1}s ===");
    println!("{:>24}  {tapped}", "packets tapped");
    println!("{:>24}  {unparsed}  (no five-tuple)", "unparsed");
    for s in 0..NSERIES {
        println!("{:>24}  {:.0}", SERIES_NAMES[s], totals[s]);
    }
    if let Some(exact) = EXACT.get() {
        println!("  --exact ground truth:");
        for s in 0..NSERIES {
            let truth = exact[s].lock().expect("exact set poisoned").len() as f64;
            let err = if truth > 0.0 {
                (totals[s] / truth - 1.0) * 100.0
            } else {
                0.0
            };
            println!(
                "{:>24}  {truth:.0} exact vs {:.0} estimated ({err:+.2}%)",
                SERIES_NAMES[s], totals[s]
            );
        }
    }
    let unfiled = UNFILED.load(Ordering::Relaxed);
    if unfiled != 0 {
        println!(
            "warning: {unfiled} packets are in the totals above but missing from the \
             per-second series -- they arrived after the {nsecs}s of grid ran out; \
             re-run with a larger --max-seconds"
        );
    }
    println!(
        "note: the per-second rows do not sum to these totals -- a flow spanning N \
         seconds is counted in all N buckets"
    );

    match write_csv(&args.csv) {
        Ok(rows) => println!("wrote {rows} per-second rows to {}", args.csv.display()),
        Err(e) => eprintln!("failed to write {}: {e}", args.csv.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything about the grid that an offline pcap run cannot reach.
    ///
    /// A replayed trace lands entirely in second 0 on one core, so the per-second
    /// routing, the cross-core merge and the CSV trim are all untested by the
    /// end-to-end run. They are checked here by writing keys straight into the grid.
    ///
    /// One test, not several: `GRID` is a process-wide `OnceLock`, so only one test can
    /// own it.
    #[test]
    fn per_second_series_merges_cores_and_trims() {
        const NCORES: usize = 4;
        const NSECS: usize = 10;
        const P: u32 = 12;

        init_grid(NCORES, NSECS, P);

        let key = |i: u64| fmix64(i);

        let slot = |core: usize, sec: usize, series: usize| {
            let c = &grid()[core];
            &c.sec(sec).expect("slot in range")[series * c.m..(series + 1) * c.m]
        };

        // Second 2: 500 distinct keys, split across two cores with no overlap.
        for i in 0..500u64 {
            hll::add(slot((i % 2) as usize, 2, DIR), key(i));
        }

        // Second 5: the *same* 300 keys observed on two different cores, which is what
        // non-symmetric RSS does to a flow's two directions. Merging registers must
        // collapse them; summing per-core estimates would report ~600.
        for i in 1000..1300u64 {
            hll::add(slot(0, 5, BIDIR), key(i));
            hll::add(slot(3, 5, BIDIR), key(i));
        }

        // Second 7: unparsed only, no five-tuples at all.
        grid()[1].unparsed[7].store(42, Ordering::Relaxed);

        let tol = |n: f64| 3.0 * 0.0181 * n; // 3 sigma, linear-counting regime

        let s2 = second_estimate(2);
        assert!(
            (s2[DIR] - 500.0).abs() < tol(500.0),
            "second 2 directional estimated {}, want ~500",
            s2[DIR]
        );
        assert_eq!(s2[BIDIR], 0.0, "second 2 wrote nothing bidirectional");

        let s5 = second_estimate(5);
        assert!(
            (s5[BIDIR] - 300.0).abs() < tol(300.0),
            "second 5 bidirectional estimated {}, want ~300 -- the same key on two \
             cores must merge, not double",
            s5[BIDIR]
        );

        // Untouched seconds must read exactly zero, not `alpha * m`.
        for sec in [0usize, 1, 3, 4, 6, 8, 9] {
            assert_eq!(second_estimate(sec), [0.0; NSERIES], "second {sec}");
        }
        assert_eq!(unparsed_in(7), 42);
        assert_eq!(unparsed_in(6), 0);

        // The CSV stops after the last second with any activity -- second 7, the
        // unparsed-only one, so trimming must consider that column too.
        let path = std::env::temp_dir().join("flow_cardinality_test.csv");
        assert_eq!(write_csv(&path).expect("write csv"), 8);
        let csv = std::fs::read_to_string(&path).expect("read csv");
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 9, "header plus seconds 0..=7");
        assert_eq!(
            lines[0],
            "second,distinct_directional,distinct_bidirectional,unparsed"
        );
        assert_eq!(lines[1], "0,0,0,0");
        assert_eq!(lines[8], "7,0,0,42");
        let _ = std::fs::remove_file(&path);
    }
}
