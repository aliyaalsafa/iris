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
//! Two further columns, `active_tuples_directional` and `active_tuples_bidirectional`,
//! answer a deliberately *different* question, and the difference is the point of
//! having them here. Every series above is scoped to a connection, so it inherits
//! conntrack's blind spots -- most of all that a TCP connection is only built from a
//! pure SYN, so mid-stream TCP is invisible. The tuple columns come instead from an
//! [`iris_core::lcore::packet_tap`], which sees every packet the datapath receives
//! ahead of the software flow table and the generated packet filter. The gap between
//! them is what connection tracking discards.
//!
//! They are *observation* counts, not arrivals: a tuple is credited to every second in
//! which it sent a packet, so a ten-second flow appears in ten buckets. They therefore
//! do not sum down the column, and a row does not invite an arrivals-vs-tuples
//! subtraction. Getting a packet-level *arrival* rate would need a "have I seen this
//! before" structure rather than a cardinality sketch.
//!
//! A live line goes to stdout every `--print-interval` seconds; the full per-second
//! series — a column per category plus `all` — is written to `--csv` at shutdown.
//!
//! `--warmup-secs N` throws away every flow arriving in the first N seconds so the
//! startup transient stays out of the measurement. It filters on *arrival* time, so a
//! flow that arrived during warmup is discarded even when its classification only
//! resolves later. Second 0 of the series, and the denominator of both averages, are
//! then the end of warmup rather than the start of the process.
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
//! - The tuple columns are HyperLogLog estimates, carrying a relative standard error of
//!   `1.04/sqrt(2^p)` -- 1.6% at the default `--tuple-precision 12`. Sketches merge
//!   exactly across cores, so a flow whose two directions land on different RX cores
//!   under non-symmetric RSS is still counted once in the bidirectional column.
//! - The tap cannot see two things, both by construction: traffic steered to a sink
//!   queue (`rx_sink` is a drain, not part of the pipeline), and packets a hardware
//!   `rte_flow` rule dropped, which never reach `rte_eth_rx_burst`.
//! - `unparsed_packets` counts tapped packets with no five-tuple at all -- ARP, ICMP,
//!   malformed, non-Ethernet. It is exact, not estimated.

use clap::Parser;
use iris_compiler::*;
use iris_core::config::load_config;
use iris_core::lcore::packet_tap;
use iris_core::protocols::packet::tcp::{RST, SYN, TCP_PROTOCOL};
use iris_core::protocols::packet::udp::UDP_PROTOCOL;
use iris_core::protocols::stream::SessionProto;
use iris_core::subscription::{FilterResult, StreamingFilter};
use iris_core::{CoreId, FiveTuple, L4Context, L4Pdu, Mbuf, Runtime};
use iris_datatypes::StartTime;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

mod hll;

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

// ===== Per-second distinct five-tuples, from the packet tap =====

/// The two observed-tuple series. These are **not** arrival counts and are deliberately
/// kept out of `CAT_NAMES`, which `all()` sums: a tuple is credited to every second in
/// which it sent a packet, so a flow lasting ten seconds appears in ten buckets.
const TUP_DIR: usize = 0;
const TUP_BIDIR: usize = 1;
const NTUP: usize = 2;
const TUP_NAMES: [&str; NTUP] = ["active_tuples_directional", "active_tuples_bidirectional"];

/// One core's tuple sketches, laid out `[second][series][register]` in one allocation.
///
/// The single slab is not just tidiness. Allocating each 4 KiB sketch separately makes
/// the whole grid resident at startup, because glibc serves anything under its 128 KiB
/// mmap threshold from the heap arena and zeroes it by hand; one multi-megabyte slab is
/// mapped lazily instead. Measured at a 1250 MiB reservation: 1190 MiB resident
/// per-sketch, 576 KiB as a slab.
///
/// Written only by the owning core's RX thread, like [`CoreBuckets`].
#[repr(align(64))]
struct CoreSketches {
    secs: Box<[AtomicU8]>,
    /// Packets with no five-tuple -- ARP, ICMP, malformed -- per second. Exact.
    unparsed: Box<[AtomicU64]>,
    /// Registers per sketch, i.e. `2^p`.
    m: usize,
}

impl CoreSketches {
    fn new(nsecs: usize, p: u32) -> Self {
        let m = 1usize << p;
        Self {
            secs: hll::zeroed(nsecs * NTUP * m),
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
        let width = NTUP * self.m;
        self.secs.get(sec * width..(sec + 1) * width)
    }
}

static SKETCHES: OnceLock<Vec<CoreSketches>> = OnceLock::new();
/// Every packet the tap was handed, warmup included.
static TAPPED: AtomicU64 = AtomicU64::new(0);
/// Packets discarded because they arrived during warmup, and packets that arrived after
/// the grid ran out. Counted apart from their flow-level equivalents because the units
/// differ -- these are packets, those are flows.
static WARMUP_DISCARDED_PKTS: AtomicU64 = AtomicU64::new(0);
static UNFILED_PKTS: AtomicU64 = AtomicU64::new(0);

fn sketches() -> &'static Vec<CoreSketches> {
    SKETCHES.get().expect("sketches() before init_sketches()")
}

fn init_sketches(ncores: usize, nsecs: usize, p: u32) {
    let _ = SKETCHES.set((0..ncores).map(|_| CoreSketches::new(nsecs, p)).collect());
}

/// Observe one packet. Installed as an [`iris_core::lcore::packet_tap`], so it runs
/// inline on the RX core for **every** packet the datapath receives -- ahead of the
/// software flow table and the generated packet filter, and so ahead of everything that
/// makes the arrival series above a partial view of the wire.
fn observe_packet(mbuf: &Mbuf, core_id: &CoreId, now: Instant) {
    TAPPED.fetch_add(1, Ordering::Relaxed);

    let Some(core) = sketches().get(core_id.raw() as usize) else {
        UNFILED_PKTS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    // The same warmup and second mapping the flow series uses, so a CSV row's columns
    // all describe the same second.
    let Some(sec) = arrival_sec(&now) else {
        WARMUP_DISCARDED_PKTS.fetch_add(1, Ordering::Relaxed);
        return;
    };

    let Ok(ctxt) = L4Context::new(mbuf) else {
        match core.unparsed.get(sec) {
            Some(c) => {
                c.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                UNFILED_PKTS.fetch_add(1, Ordering::Relaxed);
            }
        }
        return;
    };

    let Some(block) = core.sec(sec) else {
        UNFILED_PKTS.fetch_add(1, Ordering::Relaxed);
        return;
    };
    let five_tuple = FiveTuple::from_ctxt(&ctxt);
    // `dir_hash` leaves the endpoints in wire order, `conn_hash` sorts them, which is
    // the whole difference between the two columns. fmix64 is not optional -- see its
    // doc comment: without it, structured traffic drives the register index far from
    // uniform and the estimate off by tens of percent.
    let mut keys = [0u64; NTUP];
    keys[TUP_DIR] = hll::fmix64(five_tuple.dir_hash());
    keys[TUP_BIDIR] = hll::fmix64(five_tuple.conn_hash());
    for (regs, &key) in block.chunks_exact(core.m).zip(keys.iter()) {
        hll::add(regs, key);
    }
}

/// Merge one second's sketches across every core, then estimate.
///
/// Merging before estimating is what makes the cross-core case correct: the two
/// directions of a flow can land on different RX cores under non-symmetric RSS, and
/// register-wise max collapses them. Summing per-core estimates would double-count.
fn tuple_estimates(sec: usize) -> [f64; NTUP] {
    std::array::from_fn(|series| {
        let mut acc = vec![0u8; sketches()[0].m];
        for core in sketches() {
            if let Some(block) = core.sec(sec) {
                hll::merge_into(&block[series * core.m..(series + 1) * core.m], &mut acc);
            }
        }
        hll::estimate(&acc)
    })
}

fn unparsed_in(sec: usize) -> u64 {
    sketches()
        .iter()
        .map(|c| c.unparsed[sec].load(Ordering::Relaxed))
        .sum()
}

static BUCKETS: OnceLock<Vec<CoreBuckets>> = OnceLock::new();
/// Baseline for the second index. Set just before the runtime starts.
static START: OnceLock<Instant> = OnceLock::new();
/// Seconds of arrivals to throw away at the start of the run (`--warmup-secs`).
static WARMUP_SECS: OnceLock<u64> = OnceLock::new();
/// Flows deliberately thrown away because they arrived during warmup. Distinct from
/// [`UNFILED`]: this is the feature working, not a shortfall.
static WARMUP_DISCARDED: AtomicU64 = AtomicU64::new(0);
/// Flows that arrived but could not be filed: their arrival second (or core id) was
/// outside the allocated bucket array, so there was nowhere to count them. A
/// bookkeeping shortfall in this app — not packet loss, which the online monitor
/// reports separately as `HW/SW Dropped`.
static UNFILED: AtomicU64 = AtomicU64::new(0);
static RUNNING: AtomicBool = AtomicBool::new(true);

#[inline]
fn warmup_secs() -> u64 {
    *WARMUP_SECS.get().unwrap_or(&0)
}

fn buckets() -> &'static Vec<CoreBuckets> {
    BUCKETS.get().expect("buckets() before init_buckets()")
}

fn init_buckets(ncores: usize, nsecs: usize) {
    let _ = BUCKETS.set((0..ncores).map(|_| CoreBuckets::new(nsecs)).collect());
}

/// This flow's position in the measured series: seconds since the end of warmup, or
/// `None` if it arrived during warmup and is being discarded.
///
/// `checked_sub` gives both behaviours at once -- `None` inside the warmup window, and
/// `0` for a flow arriving exactly at the boundary, which counts because N seconds
/// *have* passed by then.
#[inline]
fn arrival_sec(start: &StartTime) -> Option<usize> {
    let base = START.get().expect("START unset");
    let secs = start.saturating_duration_since(*base).as_secs();
    secs.checked_sub(warmup_secs()).map(|s| s as usize)
}

/// Credit one flow of `cat` to the second it arrived in.  Returns false if it arrived
/// during warmup and was discarded.
///
/// Warmup filters on *arrival* time, not on when this fires: the scan and maybe_quic
/// callbacks run seconds after the flow arrived, and crediting them by callback time
/// would drop rows into the warmup window the rest of the app has already excluded.
#[inline]
fn record(core_id: &CoreId, start: &StartTime, cat: usize) -> bool {
    match arrival_sec(start) {
        Some(sec) => {
            bump(core_id, sec, cat);
            true
        }
        None => false,
    }
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
    // Counting warmup discards here rather than inside `record` keeps the tally a flow
    // count: every flow reaches this callback exactly once, and through exactly one of
    // tcp/udp, whereas the later callbacks would each add another discard for the same
    // flow.
    if !record(core_id, start, cat) {
        WARMUP_DISCARDED.fetch_add(1, Ordering::Relaxed);
    }
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
    record(core_id, start, cat);
}

/// TCP flows whose SYN went unanswered, as decided by [`UnansweredSyn`] at
/// termination and credited back to the second the SYN arrived.
#[callback("tcp and UnansweredSyn,level=L4Terminated")]
fn on_unanswered_syn(start: &StartTime, core_id: &CoreId) {
    record(core_id, start, CAT_UNANSWERED_SYN);
}

/// TCP flows whose SYN drew only a RST, as decided by [`RefusedSyn`] at termination
/// and credited back to the second the SYN arrived.
#[callback("tcp and RefusedSyn,level=L4Terminated")]
fn on_refused_syn(start: &StartTime, core_id: &CoreId) {
    record(core_id, start, CAT_REFUSED_SYN);
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
    record(core_id, start, CAT_MAYBE_QUIC);
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

    /// Discard every flow arriving in the first N seconds, so the startup transient
    /// stays out of the measurement.  Filtered on arrival time, so a flow that arrives
    /// during warmup is discarded even when its classification resolves later.
    #[clap(long, default_value = "0")]
    warmup_secs: u64,

    /// Seconds of bucket space to allocate for the measured window (i.e. excluding
    /// warmup). Defaults to `[online] duration` plus a minute of slack for the
    /// late-resolving series, or one hour if unset.
    #[clap(long)]
    max_seconds: Option<usize>,

    /// HyperLogLog precision for the `active_tuples_*` columns: 2^p one-byte registers
    /// per sketch, per core, per second. The relative standard error is 1.04/sqrt(2^p),
    /// so 12 gives 1.6% from 4 KiB.
    #[clap(long, default_value = "12")]
    tuple_precision: u32,

    /// Refuse to start if the tuple sketches would reserve more than this many MiB.
    /// The reservation is address space; residency grows only as seconds are written.
    #[clap(long, default_value = "4096")]
    max_reserve_mib: usize,
}

/// Live line: cumulative total per category, and the mean rate over the interval just
/// elapsed.
///
/// `last_tuples` is the newest *complete* second of the observed-tuple series rather
/// than a cumulative figure, because sketches cannot be differenced: the run-so-far
/// union minus the union one second ago is a difference of two large estimates, and at
/// any real cardinality the noise swamps the answer.
fn print_live(
    elapsed: Duration,
    prev: &[u64; NCAT],
    curr: &[u64; NCAT],
    interval_secs: f64,
    last_tuples: Option<(usize, [f64; NTUP])>,
) {
    let mut line = format!("[flow_arrivals t={:>5.0}s]", elapsed.as_secs_f64());
    for cat in 0..NCAT {
        let rate = (curr[cat] - prev[cat]) as f64 / interval_secs;
        line += &format!(" {}={} ({:.0}/s)", CAT_NAMES[cat], curr[cat], rate);
    }
    if let Some((sec, est)) = last_tuples {
        line += &format!(" | sec {sec}");
        for tup in 0..NTUP {
            // Trim the shared prefix; the header above names them in full.
            let short = TUP_NAMES[tup].trim_start_matches("active_tuples_");
            line += &format!(" active_{short}={:.0}", est[tup]);
        }
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
///
/// `second` counts from the end of warmup, so row 0 is the first measured second.
/// The `active_tuples_*` columns come last and mean something different from the rest
/// of the row: they are distinct five-tuples *observed* in that second, from the packet
/// tap, not flows that *arrived* in it. `unparsed_packets` is an exact count of tapped
/// packets with no five-tuple at all.
fn write_csv(path: &PathBuf, series: &[[u64; NCAT]]) -> std::io::Result<usize> {
    let tuples: Vec<([f64; NTUP], u64)> = (0..series.len())
        .map(|sec| (tuple_estimates(sec), unparsed_in(sec)))
        .collect();
    let active = |sec: usize| tuples[sec].0.iter().any(|&v| v > 0.0) || tuples[sec].1 > 0;
    let last = (0..series.len())
        .rposition(|sec| series[sec].iter().any(|&v| v != 0) || active(sec))
        .map_or(0, |i| i + 1);

    let mut w = BufWriter::new(File::create(path)?);
    write!(w, "second")?;
    for name in CAT_NAMES {
        write!(w, ",{name}")?;
    }
    write!(w, ",all,encrypted")?;
    for name in TUP_NAMES {
        write!(w, ",{name}")?;
    }
    writeln!(w, ",unparsed_packets")?;

    for (sec, row) in series[..last].iter().enumerate() {
        write!(w, "{sec}")?;
        for count in row {
            write!(w, ",{count}")?;
        }
        write!(w, ",{},{}", all(row), encrypted(row))?;
        let (est, unparsed) = &tuples[sec];
        for v in est {
            write!(w, ",{v:.0}")?;
        }
        writeln!(w, ",{unparsed}")?;
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
    let warmup = args.warmup_secs;
    println!("flow_arrivals: {ncores} core slots x {nsecs} seconds, {warmup}s warmup");

    let p = args.tuple_precision;
    assert!(
        (hll::MIN_PRECISION..=hll::MAX_PRECISION).contains(&p),
        "--tuple-precision must be between {} and {}",
        hll::MIN_PRECISION,
        hll::MAX_PRECISION
    );
    // Reserved address space, not resident memory: the slabs are handed back as
    // untouched zero pages and fault in only as seconds are written.
    let reserve = ncores * nsecs * NTUP * (1usize << p);
    let mib = |b: usize| b as f64 / (1024.0 * 1024.0);
    assert!(
        mib(reserve) <= args.max_reserve_mib as f64,
        "tuple sketches would reserve {:.1} MiB, over the {} MiB limit; lower \
         --max-seconds or --tuple-precision, or raise --max-reserve-mib",
        mib(reserve),
        args.max_reserve_mib
    );
    println!(
        "flow_arrivals: tuple sketches p={p} (m={}, sigma={:.2}%), {:.1} MiB reserved, \
         ~{:.0} KiB/s resident",
        1usize << p,
        hll::std_error(p) * 100.0,
        mib(reserve),
        (ncores * NTUP * (1usize << p)) as f64 / 1024.0,
    );
    init_sketches(ncores, nsecs, p);

    let interval = Duration::from_secs(args.print_interval.max(1));
    let warmup_dur = Duration::from_secs(warmup);
    let start = Instant::now();
    START.set(start).expect("START already set");
    WARMUP_SECS.set(warmup).expect("WARMUP_SECS already set");
    // Must precede `Runtime::run`: each RX core reads the tap once at loop entry.
    packet_tap::install(observe_packet).expect("a packet tap is already installed");

    // No app-level periodic hook exists (the 1Hz Monitor is core-internal and online
    // only), so live reporting is our own thread. The buckets are already indexed by
    // arrival second, so it only reads and prints.
    let reporter = std::thread::spawn(move || {
        let mut prev = [0u64; NCAT];
        // Both clocks start at the end of warmup: nothing is counted before then, so
        // printing earlier emits all-zero lines and the first real interval would be
        // diluted by the warmup seconds it straddled.
        let mut prev_elapsed = warmup_dur;
        let mut next_print = warmup_dur + interval;
        while RUNNING.load(Ordering::Relaxed) {
            // Short naps so shutdown is prompt rather than up to `interval` late.
            std::thread::sleep(Duration::from_millis(250));
            let elapsed = start.elapsed();
            if elapsed < next_print {
                continue;
            }
            let curr = totals(&collect());
            // The second before the current one, i.e. the newest complete bucket.
            let last_tuples = ((elapsed - warmup_dur).as_secs() as usize)
                .checked_sub(1)
                .filter(|&s| s < nsecs)
                .map(|s| (s, tuple_estimates(s)));
            // The actual gap, not the nominal interval: waking on a 250ms granularity
            // overshoots a little every time, and that drift would skew the rate.
            print_live(
                elapsed - warmup_dur,
                &prev,
                &curr,
                (elapsed - prev_elapsed).as_secs_f64(),
                last_tuples,
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
    // The measured window, not the whole run: dividing the averages by wall clock would
    // dilute them with the warmup seconds whose flows were thrown away.
    let measured = (start.elapsed().as_secs_f64() - warmup as f64).max(0.0);
    if warmup == 0 {
        println!("\n=== flow arrivals over {measured:.1}s ===");
    } else {
        println!("\n=== flow arrivals over {measured:.1}s (after {warmup}s warmup) ===");
    }
    for cat in 0..NCAT {
        println!("{:>20}  {}", CAT_NAMES[cat], totals[cat]);
    }
    print_summary(
        "TOTAL",
        "average",
        all(&totals),
        "tcp + udp; the rows above are subsets of these two",
        measured,
    );
    print_summary(
        "TOTAL ENCRYPTED",
        "average encrypted",
        encrypted(&totals),
        "tls + quic + ssh + maybe_quic",
        measured,
    );
    // The observed-tuple series, summarised as its per-second mean. There is
    // deliberately no run total here: a tuple is credited to every second it was active
    // in, so the column does not sum to anything meaningful, and the sketches cannot be
    // unioned into a run-wide figure without answering a different question ("distinct
    // tuples all run") than the column does.
    let measured_secs = (measured.ceil() as usize).min(nsecs);
    let tuple_rows: Vec<[f64; NTUP]> = (0..measured_secs).map(tuple_estimates).collect();
    let nonempty = tuple_rows
        .iter()
        .filter(|r| r.iter().any(|&v| v > 0.0))
        .count();
    let plural = if nonempty == 1 { "" } else { "s" };
    println!("\n--- tuples observed per second (not arrivals; see note below) ---");
    for tup in 0..NTUP {
        let sum: f64 = tuple_rows.iter().map(|r| r[tup]).sum();
        let mean = if nonempty == 0 {
            0.0
        } else {
            sum / nonempty as f64
        };
        println!(
            "{:>20}  {mean:.0} /s mean over {nonempty} active second{plural}",
            TUP_NAMES[tup].trim_start_matches("active_tuples_")
        );
    }
    let tapped = TAPPED.load(Ordering::Relaxed);
    let unparsed: u64 = (0..measured_secs).map(unparsed_in).sum();
    println!(
        "{:>20}  {tapped} ({unparsed} with no five-tuple)",
        "packets tapped"
    );

    let discarded = WARMUP_DISCARDED.load(Ordering::Relaxed);
    if warmup != 0 {
        println!("discarded {discarded} flows that arrived during the {warmup}s warmup");
        println!(
            "discarded {} packets that arrived during the {warmup}s warmup",
            WARMUP_DISCARDED_PKTS.load(Ordering::Relaxed)
        );
    }
    if warmup != 0 && measured <= 0.0 {
        println!(
            "warning: the run ended before the {warmup}s warmup did, so nothing was \
             measured; lower --warmup-secs or run for longer"
        );
    }
    let unfiled = UNFILED.load(Ordering::Relaxed);
    if unfiled != 0 {
        println!(
            "warning: the counts above are short by {unfiled} flows that arrived after the \
             {nsecs}s of bucket space ran out; re-run with a larger --max-seconds"
        );
    }
    let unfiled_pkts = UNFILED_PKTS.load(Ordering::Relaxed);
    if unfiled_pkts != 0 {
        println!(
            "warning: the tuple columns are short by {unfiled_pkts} packets that arrived \
             after the {nsecs}s of bucket space ran out; re-run with a larger --max-seconds"
        );
    }
    println!(
        "note: the two scan series resolve at connection teardown, and short maybe_quic \
         flows do too, so the last few seconds of those are still filling in"
    );
    println!(
        "note: active_tuples_* count tuples *observed* in a second, not arriving in it, \
         so they do not sum and are not comparable row-wise to the arrival columns"
    );

    match write_csv(&args.csv, &series) {
        Ok(rows) => println!("wrote {rows} per-second rows to {}", args.csv.display()),
        Err(e) => eprintln!("failed to write {}: {e}", args.csv.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Everything about the tuple grid an offline pcap run cannot reach.
    ///
    /// A replayed trace lands entirely in second 0 on one core, so per-second routing,
    /// the cross-core merge and the CSV trim all go untested end to end. They are
    /// checked here by writing keys straight into the grid.
    ///
    /// One test, not several: `SKETCHES` and `BUCKETS` are process-wide `OnceLock`s, so
    /// only one test can own them.
    #[test]
    fn tuple_grid_merges_cores_and_extends_the_csv() {
        const NCORES: usize = 4;
        const NSECS: usize = 10;

        init_sketches(NCORES, NSECS, 12);
        init_buckets(NCORES, NSECS);

        let key = |i: u64| hll::fmix64(i);
        let slot = |core: usize, sec: usize, series: usize| {
            let c = &sketches()[core];
            &c.sec(sec).expect("slot in range")[series * c.m..(series + 1) * c.m]
        };

        // Second 2: 500 distinct tuples, split across two cores with no overlap.
        for i in 0..500u64 {
            hll::add(slot((i % 2) as usize, 2, TUP_DIR), key(i));
        }

        // Second 5: the *same* 300 tuples observed on two different cores, which is
        // what non-symmetric RSS does to a flow's two directions. Register-wise max
        // must collapse them; summing per-core estimates would report ~600.
        for i in 1000..1300u64 {
            hll::add(slot(0, 5, TUP_BIDIR), key(i));
            hll::add(slot(3, 5, TUP_BIDIR), key(i));
        }

        // Second 7: unparsed packets only, no five-tuples at all.
        sketches()[1].unparsed[7].store(42, Ordering::Relaxed);

        let tol = |n: f64| 3.0 * 0.0181 * n; // 3 sigma, linear-counting regime

        let s2 = tuple_estimates(2);
        assert!(
            (s2[TUP_DIR] - 500.0).abs() < tol(500.0),
            "second 2 directional estimated {}, want ~500",
            s2[TUP_DIR]
        );
        assert_eq!(s2[TUP_BIDIR], 0.0, "second 2 wrote nothing bidirectional");

        let s5 = tuple_estimates(5);
        assert!(
            (s5[TUP_BIDIR] - 300.0).abs() < tol(300.0),
            "second 5 bidirectional estimated {}, want ~300 -- the same tuple on two \
             cores must merge, not double",
            s5[TUP_BIDIR]
        );

        // Untouched seconds must read exactly zero, not `alpha * m`.
        for sec in [0usize, 1, 3, 4, 6, 8, 9] {
            assert_eq!(tuple_estimates(sec), [0.0; NTUP], "second {sec}");
        }
        assert_eq!(unparsed_in(7), 42);
        assert_eq!(unparsed_in(6), 0);

        // The CSV must extend past the last *flow* arrival to cover seconds that only
        // the tap saw -- here second 7, which holds nothing but unparsed packets.
        let series = vec![[0u64; NCAT]; NSECS];
        let path = std::env::temp_dir().join("flow_arrivals_tuple_test.csv");
        assert_eq!(write_csv(&path, &series).expect("write csv"), 8);
        let csv = std::fs::read_to_string(&path).expect("read csv");
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 9, "header plus seconds 0..=7");
        assert!(
            lines[0].ends_with(
                ",active_tuples_directional,active_tuples_bidirectional,unparsed_packets"
            ),
            "tuple columns come last: {}",
            lines[0]
        );
        assert!(lines[8].ends_with(",0,0,42"), "second 7 row: {}", lines[8]);
        let _ = std::fs::remove_file(&path);
    }
}
