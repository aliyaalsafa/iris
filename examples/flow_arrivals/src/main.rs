//! Counts arriving flows per second, broken down by transport and by encrypted
//! application protocol.
//!
//! Eight series, each credited to the second in which the flow's *first packet*
//! arrived — so every column answers the same question: "how many flows that arrived
//! during second N were of this kind?"
//!
//!   tcp / udp            every arriving flow, at `L4FirstPacket`
//!   tcp_unanswered_syn   TCP flows whose SYN drew no response at all
//!   tcp_refused_syn      TCP flows whose SYN drew only a RST
//!   tls / quic / ssh     whatever the L7 parsers claim, at `L7OnDisc`
//!   maybe_quic           mid-stream QUIC the parsers miss, by heuristic
//!
//! A live line goes to stdout every `--print-interval` seconds; the full per-second
//! series — a column per category plus `all` — is written to `--csv` at shutdown.
//!
//! ## What the numbers do and don't include
//!
//! - Iris builds a TCP connection only from a pure SYN (`Conn::new_tcp`), so SYN scans
//!   are counted — that is the point — but mid-stream TCP and scan *backscatter*
//!   (SYN-ACK-first, RST-first) never enter the table at all. UDP flows are created on
//!   the first datagram, unconditionally.
//! - The two scan series split on what came back: `tcp_unanswered_syn` is a silent
//!   responder, `tcp_refused_syn` a RST from a closed port. They are disjoint, so their
//!   sum is every scan-shaped TCP flow — together they are the Zeek-history definition
//!   ("SYN with no SYN-ACK"), kept apart because a silent host and a closed port say
//!   different things about the target.
//! - Both scan series can only be decided at `L4Terminated`, i.e. one
//!   `tcp_establish_timeout` (5s by default) after arrival. Their buckets therefore
//!   fill in behind the others, and the tail of a run undercounts them.
//! - `maybe_quic` is credited as soon as the heuristic accepts, roughly 12
//!   payload-bearing packets in. Flows too short for that also get counted, but only
//!   at teardown (see `on_maybe_quic`), so this series has a small late-filling tail
//!   too. Every other series is complete the moment it is written.
//! - `quic` (parser-claimed) and `maybe_quic` (heuristic) are disjoint:
//!   `MaybeQuic::unclaimed` vetoes anything a parser already named.
//! - `L7OnDisc` fires per session. For TLS/SSH/QUIC that is effectively once per flow,
//!   but a flow carrying several sessions would be counted more than once.
//! - Offline runs timestamp by Iris observation time, not pcap capture time, so the
//!   series reflects replay speed rather than the capture's original timeline.

use clap::Parser;
use iris_compiler::*;
use iris_core::config::load_config;
use iris_core::protocols::packet::tcp::{RST, SYN, TCP_PROTOCOL};
use iris_core::protocols::packet::udp::UDP_PROTOCOL;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::{FilterResult, StreamingFilter};
use iris_core::{CoreId, FiveTuple, L4Pdu, Runtime};
use iris_datatypes::StartTime;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ===== Categories =====

const CAT_TCP: usize = 0;
const CAT_UDP: usize = 1;
const CAT_UNANSWERED_SYN: usize = 2;
const CAT_REFUSED_SYN: usize = 3;
const CAT_TLS: usize = 4;
const CAT_QUIC: usize = 5;
const CAT_SSH: usize = 6;
const CAT_MAYBE_QUIC: usize = 7;
const NCAT: usize = 8;

const CAT_NAMES: [&str; NCAT] = [
    "tcp",
    "udp",
    "tcp_unanswered_syn",
    "tcp_refused_syn",
    "tls",
    "quic",
    "ssh",
    "maybe_quic",
];

/// Flows of any kind. Only tcp + udp: the other six categories are subsets of one of
/// those two, so adding all eight would count a TLS flow once as `tls` and again as
/// `tcp`.
#[inline]
fn all(row: &[u64; NCAT]) -> u64 {
    row[CAT_TCP] + row[CAT_UDP]
}

/// Flows carrying an encrypted protocol. These four *can* be added: a flow resolves to
/// a single `SessionProto`, and `MaybeQuic::unclaimed` vetoes the heuristic on anything
/// a parser already claimed, so they do not overlap.
#[inline]
fn encrypted(row: &[u64; NCAT]) -> u64 {
    row[CAT_TLS] + row[CAT_QUIC] + row[CAT_SSH] + row[CAT_MAYBE_QUIC]
}

// ===== Per-second, per-core counters =====

/// One core's series. Only that core's RX thread writes it, so the counters never
/// share a cache line with another writer — the `transport_meter` pattern, sharded by
/// second so the per-second series needs no sampling thread — a flow is written
/// straight into the bucket for the second it arrived in.
#[repr(align(64))]
struct CoreBuckets {
    secs: Box<[[AtomicU64; NCAT]]>,
}

impl CoreBuckets {
    fn new(nsecs: usize) -> Self {
        let secs = (0..nsecs)
            .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
            .collect::<Vec<_>>()
            .into_boxed_slice();
        Self { secs }
    }
}

static BUCKETS: OnceLock<Vec<CoreBuckets>> = OnceLock::new();
/// Baseline for the second index. Set just before the runtime starts.
static START: OnceLock<Instant> = OnceLock::new();
/// Flows that arrived but could not be filed: their arrival second (or core id) was
/// outside the allocated bucket array, so there was nowhere to count them. A
/// bookkeeping shortfall in this app — not packet loss, which the online monitor
/// reports separately as `HW/SW Dropped`.
static UNFILED: AtomicU64 = AtomicU64::new(0);
static RUNNING: AtomicBool = AtomicBool::new(true);

fn buckets() -> &'static Vec<CoreBuckets> {
    BUCKETS.get().expect("buckets() before init_buckets()")
}

fn init_buckets(ncores: usize, nsecs: usize) {
    let _ = BUCKETS.set((0..ncores).map(|_| CoreBuckets::new(nsecs)).collect());
}

/// Seconds between the run's start and this flow's first packet.
#[inline]
fn arrival_sec(start: &StartTime) -> usize {
    let base = START.get().expect("START unset");
    start.saturating_duration_since(*base).as_secs() as usize
}

/// Credit one flow of `cat`, arriving in second `sec`, to `core_id`'s series.
#[inline]
fn bump(core_id: &CoreId, sec: usize, cat: usize) {
    let b = buckets();
    match b
        .get(core_id.raw() as usize)
        .and_then(|core| core.secs.get(sec))
    {
        Some(slot) => {
            slot[cat].fetch_add(1, Ordering::Relaxed);
        }
        None => {
            UNFILED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Sum every core's series into `[sec][cat]`.
fn collect() -> Vec<[u64; NCAT]> {
    let b = buckets();
    let nsecs = b.first().map_or(0, |c| c.secs.len());
    let mut out = vec![[0u64; NCAT]; nsecs];
    for core in b {
        for (sec, slot) in core.secs.iter().enumerate() {
            for cat in 0..NCAT {
                out[sec][cat] += slot[cat].load(Ordering::Relaxed);
            }
        }
    }
    out
}

// ===== Filters =====

/// Accepts a TCP connection whose opening SYN the responder never answered — the shape
/// a SYN scan leaves behind.
///
/// Cheaper than reading it back out of a `ConnHistory`: no per-connection allocation,
/// and the filter takes itself out of the datapath (`Drop`) as soon as the responder
/// speaks, which for ordinary traffic is the second packet of the connection.
#[derive(Debug)]
#[filter]
struct UnansweredSyn {
    /// The connection opened with a bare SYN. Iris only builds TCP connections on a
    /// pure SYN, so in practice this just excludes UDP flows.
    opened_on_syn: bool,
    /// The responder sent at least one packet.
    answered: bool,
}

impl StreamingFilter for UnansweredSyn {
    fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            opened_on_syn: first_pkt.ctxt.proto == TCP_PROTOCOL && first_pkt.flags() == SYN,
            answered: false,
        }
    }

    fn clear(&mut self) {
        self.opened_on_syn = false;
        self.answered = false;
    }
}

impl UnansweredSyn {
    #[filter_fn("UnansweredSyn,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) -> FilterResult {
        if !self.opened_on_syn {
            return FilterResult::Drop;
        }
        // `dir` is true for orig -> resp. Anything coming back is an answer, and
        // dropping here retires the filter for the rest of the connection.
        if !pdu.dir {
            self.answered = true;
            return FilterResult::Drop;
        }
        // Originator retransmitting its SYN, or sending data into the void.
        FilterResult::Continue
    }

    #[filter_fn("UnansweredSyn,level=L4Terminated")]
    fn terminated(&self) -> FilterResult {
        if self.opened_on_syn && !self.answered {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }
}

/// Accepts a TCP connection whose opening SYN the responder answered only with a RST —
/// a scan that found a closed port rather than a silent one.
///
/// Disjoint from [`UnansweredSyn`] by construction: that filter needs zero responder
/// packets, this one needs at least one, and it is a RST. Sum the two for all
/// scan-shaped TCP flows.
#[derive(Debug)]
#[filter]
struct RefusedSyn {
    /// See [`UnansweredSyn::opened_on_syn`].
    opened_on_syn: bool,
    /// The responder sent at least one RST.
    refused: bool,
}

impl StreamingFilter for RefusedSyn {
    fn new(first_pkt: &L4Pdu) -> Self {
        Self {
            opened_on_syn: first_pkt.ctxt.proto == TCP_PROTOCOL && first_pkt.flags() == SYN,
            refused: false,
        }
    }

    fn clear(&mut self) {
        self.opened_on_syn = false;
        self.refused = false;
    }
}

impl RefusedSyn {
    #[filter_fn("RefusedSyn,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) -> FilterResult {
        if !self.opened_on_syn {
            return FilterResult::Drop;
        }
        if pdu.dir {
            // Originator retransmitting its SYN.
            return FilterResult::Continue;
        }
        if pdu.flags() & RST != 0 {
            self.refused = true;
            return FilterResult::Continue;
        }
        // The responder said something other than "go away" — a SYN-ACK, or data on a
        // connection that went on to establish. Not a refusal, so retire the filter.
        FilterResult::Drop
    }

    #[filter_fn("RefusedSyn,level=L4Terminated")]
    fn terminated(&self) -> FilterResult {
        if self.opened_on_syn && self.refused {
            FilterResult::Accept
        } else {
            FilterResult::Drop
        }
    }
}

// ===== Callbacks =====

/// Every arriving flow, split by transport. This is the only hook that fires at the
/// flow's first packet, so it is also the only one whose buckets are complete the
/// instant they are written.
#[callback("(ipv4 or ipv6) and (tcp or udp),level=L4FirstPacket")]
fn on_arrival(five_tuple: &FiveTuple, start: &StartTime, core_id: &CoreId) {
    let cat = match five_tuple.proto {
        TCP_PROTOCOL => CAT_TCP,
        UDP_PROTOCOL => CAT_UDP,
        _ => return,
    };
    bump(core_id, arrival_sec(start), cat);
}

/// Whatever the L7 parsers claim, credited back to the flow's arrival second.
/// `SessionProto::Null` means every parser declined; `Probing` that discovery is still
/// running. Neither is a protocol arrival.
///
/// `parsers=` is mandatory here: requesting `SessionProto` registers no parsers of its
/// own, so without it the registry is empty, `probe_all` declines immediately, and every
/// flow reads as `Null`. Only the three protocols we count are registered — adding
/// `dns`/`http` would cost probing work for a verdict nothing here reads. Registering
/// `quic` also arms `MaybeQuic`'s veto, keeping the `quic` and `maybe_quic` populations
/// disjoint.
#[callback("tcp or udp,level=L7OnDisc,parsers=tls&quic&ssh")]
fn on_l7_discovery(session_proto: &SessionProto, start: &StartTime, core_id: &CoreId) {
    let cat = match session_proto {
        SessionProto::Tls => CAT_TLS,
        SessionProto::Quic => CAT_QUIC,
        SessionProto::Ssh => CAT_SSH,
        _ => return,
    };
    bump(core_id, arrival_sec(start), cat);
}

/// TCP flows whose SYN went unanswered, as decided by [`UnansweredSyn`] at
/// termination and credited back to the second the SYN arrived.
#[callback("tcp and UnansweredSyn,level=L4Terminated")]
fn on_unanswered_syn(start: &StartTime, core_id: &CoreId) {
    bump(core_id, arrival_sec(start), CAT_UNANSWERED_SYN);
}

/// TCP flows whose SYN drew only a RST, as decided by [`RefusedSyn`] at termination
/// and credited back to the second the SYN arrived.
#[callback("tcp and RefusedSyn,level=L4Terminated")]
fn on_refused_syn(start: &StartTime, core_id: &CoreId) {
    bump(core_id, arrival_sec(start), CAT_REFUSED_SYN);
}

/// Mid-stream QUIC the parsers miss, credited back to the flow's arrival second.
///
/// Fires on the first packet after `MaybeQuic` reaches `Accept` — around 12
/// payload-bearing packets in — and returning `false` unsubscribes the flow, so a
/// long-lived flow is counted once rather than once per packet.
///
/// The compiler also wires this callback into the `L4Terminated` tree, which is what
/// picks up flows too short for `MaybeQuic::update` to accept and that only clear its
/// `terminated` bar. Verified on both paths: each is counted exactly once, and the
/// `false` return keeps a flow accepted mid-stream from being counted again at
/// teardown.
#[callback("MaybeQuic,level=InL4Conn")]
fn on_maybe_quic(start: &StartTime, core_id: &CoreId) -> bool {
    bump(core_id, arrival_sec(start), CAT_MAYBE_QUIC);
    false
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
    #[clap(long, parse(from_os_str), default_value = "./flow_arrivals.csv")]
    csv: PathBuf,

    /// Seconds between live stdout lines.
    #[clap(long, default_value = "30")]
    print_interval: u64,

    /// Seconds of bucket space to allocate. Defaults to `[online] duration` plus a
    /// minute of slack for the late-resolving series, or one hour if unset.
    #[clap(long)]
    max_seconds: Option<usize>,
}

/// Live line: cumulative total per category, and the mean rate over the interval just
/// elapsed.
fn print_live(elapsed: Duration, prev: &[u64; NCAT], curr: &[u64; NCAT], interval_secs: f64) {
    let mut line = format!("[flow_arrivals t={:>5.0}s]", elapsed.as_secs_f64());
    for cat in 0..NCAT {
        let rate = (curr[cat] - prev[cat]) as f64 / interval_secs;
        line += &format!(" {}={} ({:.0}/s)", CAT_NAMES[cat], curr[cat], rate);
    }
    println!("{line}");
}

/// A run total and its mean rate. `derivation` spells out which rows were added,
/// because the per-category rows overlap and must not simply be summed.
fn print_summary(label: &str, avg_label: &str, total: u64, derivation: &str, elapsed: f64) {
    println!("{label:>20}  {total}   ({derivation})");
    println!(
        "{avg_label:>20}  {:.1} flows/s   ({label} / {elapsed:.1}s)",
        total as f64 / elapsed.max(f64::EPSILON)
    );
}

/// Totals across the whole run, per category.
fn totals(series: &[[u64; NCAT]]) -> [u64; NCAT] {
    let mut out = [0u64; NCAT];
    for row in series {
        for cat in 0..NCAT {
            out[cat] += row[cat];
        }
    }
    out
}

/// One row per second, up to the last second with any activity: a column per category,
/// plus the two derived totals from the summary — `all` and `encrypted`. A running
/// cumulative is a prefix sum away, so it is left to whatever reads this.
fn write_csv(path: &PathBuf, series: &[[u64; NCAT]]) -> std::io::Result<usize> {
    let last = series
        .iter()
        .rposition(|row| row.iter().any(|&v| v != 0))
        .map_or(0, |i| i + 1);

    let mut w = BufWriter::new(File::create(path)?);
    write!(w, "second")?;
    for name in CAT_NAMES {
        write!(w, ",{name}")?;
    }
    writeln!(w, ",all,encrypted")?;

    for (sec, row) in series[..last].iter().enumerate() {
        write!(w, "{sec}")?;
        for count in row {
            write!(w, ",{count}")?;
        }
        writeln!(w, ",{},{}", all(row), encrypted(row))?;
    }
    w.flush()?;
    Ok(last)
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();
    let args = Args::parse();
    let config = load_config(&args.config);

    // One bucket array per core id, indexed by raw id, so `bump` needs no lookup table.
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
    init_buckets(ncores, nsecs);
    println!("flow_arrivals: {ncores} core slots x {nsecs} seconds");

    let interval = Duration::from_secs(args.print_interval.max(1));
    let start = Instant::now();
    START.set(start).expect("START already set");

    // No app-level periodic hook exists (the 1Hz Monitor is core-internal and online
    // only), so live reporting is our own thread. The buckets are already indexed by
    // arrival second, so it only reads and prints.
    let reporter = std::thread::spawn(move || {
        let mut prev = [0u64; NCAT];
        let mut prev_elapsed = Duration::ZERO;
        let mut next_print = interval;
        while RUNNING.load(Ordering::Relaxed) {
            // Short naps so shutdown is prompt rather than up to `interval` late.
            std::thread::sleep(Duration::from_millis(250));
            let elapsed = start.elapsed();
            if elapsed < next_print {
                continue;
            }
            let curr = totals(&collect());
            // The actual gap, not the nominal interval: waking on a 250ms granularity
            // overshoots a little every time, and that drift would skew the rate.
            print_live(
                elapsed,
                &prev,
                &curr,
                (elapsed - prev_elapsed).as_secs_f64(),
            );
            prev = curr;
            prev_elapsed = elapsed;
            next_print = elapsed + interval;
        }
    });

    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config, filter).unwrap();
    runtime.run();

    RUNNING.store(false, Ordering::Relaxed);
    let _ = reporter.join();

    let series = collect();
    let totals = totals(&series);
    let elapsed = start.elapsed().as_secs_f64();
    println!("\n=== flow arrivals over {elapsed:.1}s ===");
    for cat in 0..NCAT {
        println!("{:>20}  {}", CAT_NAMES[cat], totals[cat]);
    }
    print_summary(
        "TOTAL",
        "average",
        all(&totals),
        "tcp + udp; the rows above are subsets of these two",
        elapsed,
    );
    print_summary(
        "TOTAL ENCRYPTED",
        "average encrypted",
        encrypted(&totals),
        "tls + quic + ssh + maybe_quic",
        elapsed,
    );
    let unfiled = UNFILED.load(Ordering::Relaxed);
    if unfiled != 0 {
        println!(
            "warning: the counts above are short by {unfiled} flows that arrived after the \
             {nsecs}s of bucket space ran out; re-run with a larger --max-seconds"
        );
    }
    println!(
        "note: the two scan series resolve at connection teardown, and short maybe_quic \
         flows do too, so the last few seconds of those are still filling in"
    );

    match write_csv(&args.csv, &series) {
        Ok(rows) => println!("wrote {rows} per-second rows to {}", args.csv.display()),
        Err(e) => eprintln!("failed to write {}: {e}", args.csv.display()),
    }
}
