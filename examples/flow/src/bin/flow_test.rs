use clap::{ArgAction, Parser};
use enum_map::{Enum, EnumMap};
use iris_datatypes::conn_fts::InterArrivals;
use iris_datatypes::{ConnRecord, PktCount, TlsHandshake};
use serde::Serialize;
use strum::IntoStaticStr;

use iris_core::{
    CoreId, FiveTuple, L4Pdu, Runtime,
    config::{FlowMode, default_config, load_config},
    filter::flow_drop::{DISCARDED_BYTES, DISCARDED_PACKETS, SplitQueueMap},
    multicore::{ChannelDispatcher, ChannelMode, SharedWorkerThreadSpawner},
    port::PortId,
    protocols::packet::tcp::TCP_PROTOCOL,
    protocols::packet::udp::UDP_PROTOCOL,
    subscription::Tracked,
};

use iris_compiler::{callback, datatype, datatype_fn, input_files, iris_end_macros};

use std::{
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::{Arc, Mutex, OnceLock, RwLock},
};

use flow::flow_table::{FlowTable, InstallError};
use flow::model;

use flow::features::conn_features::{ConnFeatures, ConnInvariants};
use flow::features::tls_features::TlsFeatures;

static TCP_BYTES: AtomicUsize = AtomicUsize::new(0);
static UDP_BYTES: AtomicUsize = AtomicUsize::new(0);

// Dispatching
static FLOW_DISPATCHER: OnceLock<Arc<ChannelDispatcher<FlowEvent>>> = OnceLock::new();
static MODE: RwLock<FlowMode> = RwLock::new(FlowMode::Standard);
static TABLE: OnceLock<Mutex<FlowTable>> = OnceLock::new();

static USE_MODEL: OnceLock<bool> = OnceLock::new();

static OFFLOAD_AFTER_PKTS: OnceLock<usize> = OnceLock::new();

#[inline]
fn offload_after_pkts() -> usize {
    *OFFLOAD_AFTER_PKTS.get().unwrap_or(&20)
}

#[inline]
fn offload_enabled(protocol: Protocol) -> bool {
    STATS[protocol].enabled.load(Ordering::Relaxed)
}

#[inline]
fn offer_for_offload(proto: Protocol, five_tuple: &FiveTuple, rx_core: &CoreId, total_pkts: usize) {
    if total_pkts != offload_after_pkts() || !offload_enabled(proto) {
        return;
    }
    if let Some(dispatcher) = FLOW_DISPATCHER.get() {
        let _ = dispatcher.dispatch(
            FlowEvent::FlowSeen {
                tuple: *five_tuple,
                rx_core: *rx_core,
                proto,
            },
            Some(rx_core),
        );
        STATS[proto].dispatched.fetch_add(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Enum, IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
enum Protocol {
    Tls,
    Ssh,
    Quic,
    MaybeQuic,
}

struct ProtocolStats {
    enabled: AtomicBool,
    dispatched: AtomicUsize,
    installed: AtomicUsize,
    wire_bytes: AtomicUsize,
}

impl ProtocolStats {
    const fn new() -> Self {
        Self {
            enabled: AtomicBool::new(false),
            dispatched: AtomicUsize::new(0),
            installed: AtomicUsize::new(0),
            wire_bytes: AtomicUsize::new(0),
        }
    }
}

/// Per-protocol switch and counters, indexed by `Protocol`: `STATS[Protocol::Ssh].dispatched`.
static STATS: EnumMap<Protocol, ProtocolStats> =
    EnumMap::from_array([const { ProtocolStats::new() }; 4]);

#[derive(Clone, Serialize)]
enum FlowEvent {
    /// Minimal payload to keep cloning cheap
    FlowSeen {
        tuple: FiveTuple,
        rx_core: CoreId,
        proto: Protocol,
    },
}

// ===== CLI =====
#[derive(Parser, Debug)]
struct Args {
    #[clap(short, long, value_parser, value_name = "FILE")]
    config: Option<PathBuf>,

    #[clap(
        short,
        long,
        value_parser,
        value_name = "FILE",
        default_value = "ports.jsonl"
    )]
    outfile: PathBuf,

    #[clap(long, action = ArgAction::SetTrue)]
    show_stats: bool,

    #[clap(long, action = ArgAction::SetTrue)]
    show_args: bool,

    #[clap(long, value_parser, value_name = "FILE")]
    model: Option<PathBuf>,

    #[clap(long, value_name = "COUNT", default_value = "100")]
    num_flows: usize,

    #[clap(long, value_name = "COUNT", default_value = "20")]
    offload_after_pkts: usize,
}

const MODEL_FEATURE_PKTS: usize = 20;

// ===== TCP/UDP byte counting =====

#[datatype]
struct TransportBytes {
    tcp_bytes: usize,
    udp_bytes: usize,
}

impl TransportBytes {
    #[datatype_fn("TransportBytes,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        let len = pdu.mbuf.data_len();
        match pdu.ctxt.proto {
            TCP_PROTOCOL => {
                self.tcp_bytes += len;
                iris_core::lcore::transport_meter::add_tcp(len);
            }
            UDP_PROTOCOL => {
                self.udp_bytes += len;
                iris_core::lcore::transport_meter::add_udp(len);
            }
            _ => {}
        }
    }
}

impl Tracked for TransportBytes {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            tcp_bytes: 0,
            udp_bytes: 0,
        }
    }

    fn clear(&mut self) {
        self.tcp_bytes = 0;
        self.udp_bytes = 0;
    }
}

#[callback("tcp or udp,level=L4Terminated")]
fn record_transport_bytes(bytes: &TransportBytes) {
    TCP_BYTES.fetch_add(bytes.tcp_bytes, Ordering::Relaxed);
    UDP_BYTES.fetch_add(bytes.udp_bytes, Ordering::Relaxed);
}

#[datatype]
struct EncryptedWireBytes {
    bytes: usize,
}

impl EncryptedWireBytes {
    #[datatype_fn("EncryptedWireBytes,level=InL4Conn")]
    fn update(&mut self, pdu: &L4Pdu) {
        self.bytes += pdu.mbuf.data_len();
    }
}

impl Tracked for EncryptedWireBytes {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { bytes: 0 }
    }

    fn clear(&mut self) {
        self.bytes = 0;
    }
}

#[inline]
fn record_encrypted_bytes(proto: Protocol, bytes: &EncryptedWireBytes) {
    if *MODE.read().unwrap() == FlowMode::Standard {
        STATS[proto]
            .wire_bytes
            .fetch_add(bytes.bytes, Ordering::Relaxed);
    }
}

#[callback("tls,level=L4Terminated")]
fn record_tls_bytes(bytes: &EncryptedWireBytes) {
    record_encrypted_bytes(Protocol::Tls, bytes);
}

#[callback("ssh,level=L4Terminated")]
fn record_ssh_bytes(bytes: &EncryptedWireBytes) {
    record_encrypted_bytes(Protocol::Ssh, bytes);
}

#[callback("quic,level=L4Terminated")]
fn record_quic_bytes(bytes: &EncryptedWireBytes) {
    record_encrypted_bytes(Protocol::Quic, bytes);
}

#[callback("MaybeQuic,level=L4Terminated")]
fn record_maybe_quic_bytes(bytes: &EncryptedWireBytes) {
    record_encrypted_bytes(Protocol::MaybeQuic, bytes);
}

// ===== Filters =====

// Fire on TLS connections
#[callback("tls,level=InL4Conn")]
#[allow(unused_variables)]
fn tls_cb(
    five_tuple: &FiveTuple,
    rx_core: &CoreId,
    pkts: &PktCount,
    conn: &ConnRecord,
    iat: &InterArrivals,
    tls: &TlsHandshake,
) -> bool {
    if pkts.total() != offload_after_pkts() {
        return true;
    }

    let is_elephant = if *USE_MODEL.get().unwrap_or(&false) {
        let conn_hash = conn.five_tuple.conn_hash();
        let first_seen_ts = conn
            .first_seen_wall
            .duration_since(std::time::SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let inv = ConnInvariants::from_conn(conn, conn_hash, first_seen_ts);

        match (
            ConnFeatures::from_conn_at(conn, iat, MODEL_FEATURE_PKTS as u64, &inv),
            TlsFeatures::from_tls(tls),
        ) {
            (Some(conn_features), Some(tls_features)) => {
                model::predict(&conn_features, &tls_features)
                    .map(|proba| proba >= 0.5)
                    .unwrap_or(false)
            }
            _ => false,
        }
    } else {
        true
    };

    if is_elephant {
        offer_for_offload(Protocol::Tls, five_tuple, rx_core, pkts.total());
    }

    true
}

#[callback("ssh,level=InL4Conn")]
fn ssh_cb(five_tuple: &FiveTuple, rx_core: &CoreId, pkts: &PktCount) -> bool {
    offer_for_offload(Protocol::Ssh, five_tuple, rx_core, pkts.total());
    true
}

#[callback("quic,level=InL4Conn")]
fn quic_cb(five_tuple: &FiveTuple, rx_core: &CoreId, pkts: &PktCount) -> bool {
    offer_for_offload(Protocol::Quic, five_tuple, rx_core, pkts.total());
    true
}

#[callback("MaybeQuic,level=InL4Conn")]
fn maybe_quic_cb(five_tuple: &FiveTuple, rx_core: &CoreId, pkts: &PktCount) -> bool {
    offer_for_offload(Protocol::MaybeQuic, five_tuple, rx_core, pkts.total());
    true
}

#[input_files("$IRIS_HOME/datatypes/data.txt")]
#[iris_end_macros]
fn main() {
    env_logger::init();

    // Parse CLI args
    let args = Args::parse();
    if args.show_args {
        println!("{args:#?}");
    }

    for proto in [Protocol::Tls, Protocol::Ssh, Protocol::Quic, Protocol::MaybeQuic] {
        STATS[proto].enabled.store(true, Ordering::Relaxed);
    }
    OFFLOAD_AFTER_PKTS.set(args.offload_after_pkts).unwrap();
    println!(
        "offloading: [{}] at {} packets",
        STATS
            .iter()
            .filter(|(_, s)| s.enabled.load(Ordering::Relaxed))
            .map(|(p, _)| <&str>::from(p))
            .collect::<Vec<_>>()
            .join(", "),
        args.offload_after_pkts,
    );

    if offload_enabled(Protocol::MaybeQuic)
        && args.offload_after_pkts <= iris_datatypes::MAYBE_QUIC_WINDOW
    {
        eprintln!(
            "warning: --offload-after-pkts {} does not exceed the MaybeQuic evidence window ({} \
             payload-bearing packets); connections carrying any non-payload packets will accept \
             too late to be offered, so the maybe_quic arm will under-report.",
            args.offload_after_pkts,
            iris_datatypes::MAYBE_QUIC_WINDOW,
        );
    }

    let use_model = match &args.model {
        Some(path) => {
            assert_eq!(
                args.offload_after_pkts, MODEL_FEATURE_PKTS,
                "--model requires --offload-after-pkts {MODEL_FEATURE_PKTS} (the packet count the \
                 model's features were trained at); got {}",
                args.offload_after_pkts,
            );
            model::load_model(path.to_str().expect("Invalid model path"));
            true
        }
        None => {
            println!("No model provided; running in admit-all mode.");
            false
        }
    };
    USE_MODEL.set(use_model).unwrap();
    if use_model {
        println!(
            "note: the elephant model gates the tls arm only; ssh/quic/maybe_quic admit all \
             matched connections at the threshold."
        );
    }

    let config = if let Some(path) = args.config.clone() {
        load_config(path)
    } else {
        default_config()
    };

    let flow_mode = config
        .online
        .as_ref()
        .map_or(FlowMode::Standard, |o| o.flow_mode);
    *MODE.write().unwrap() = flow_mode;
    println!(
        "resolved flow_mode = {:?} (online section present: {})",
        flow_mode,
        config.online.is_some()
    );

    let split_queues = if flow_mode.uses_split_queues()
        && let Some(online) = &config.online
    {
        Some(SplitQueueMap::from_config(online))
    } else {
        None
    };

    // Create and publish the dispatcher
    let flow_dispatcher = Arc::new(ChannelDispatcher::new(
        ChannelMode::PerCore(config.get_all_rx_core_ids()),
        32768,
        "flow_dispatcher".to_string(),
    ));
    FLOW_DISPATCHER
        .set(flow_dispatcher.clone())
        .map_err(|_| "Failed to set FLOW dispatcher")
        .unwrap();

    // Spawn workers and attach the handler
    let worker_handle = SharedWorkerThreadSpawner::new()
        .set_cores(vec![CoreId(40)])
        .set_batch_size(16)
        .measure_utilization(true)
        .add_dispatcher(flow_dispatcher.clone(), |event: FlowEvent| match event {
            FlowEvent::FlowSeen {
                tuple,
                rx_core,
                proto,
            } => {
                let Some(table) = TABLE.get() else {
                    if *MODE.read().unwrap() != FlowMode::Standard {
                        eprintln!("flow table not initialized; dropping offload request");
                    }
                    return;
                };
                match table.lock().unwrap().install(tuple, rx_core) {
                    Ok(()) => {
                        STATS[proto].installed.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(InstallError::Disabled | InstallError::AlreadyInstalled) => {}
                    Err(InstallError::NoSplitQueue(core)) => {
                        eprintln!("No split queue mapped for core {core:?}");
                    }
                    Err(e) => eprintln!("install flow failed: {e}"),
                }
            }
        })
        .run();

    // Build runtime
    let mut runtime: Runtime<SubscribedWrapper> = Runtime::new(config.clone(), filter).unwrap();

    // Extract and store PortIds
    if let Some(online) = &config.online {
        let port_ids: Vec<PortId> = online
            .ports
            .iter()
            .map(|port| {
                println!("Device: {}", port.device);
                PortId::new_from_device(port.device.clone())
            })
            .collect();

        for pid in &port_ids {
            println!("Port ID: {:?}", pid);
        }

        if let Some(&rx_core) = config.get_all_rx_core_ids().first() {
            let num_flows = args.num_flows;
            runtime.on_ports_started(move || {
                match FlowTable::new(flow_mode, port_ids, split_queues, num_flows, rx_core) {
                    Ok(table) => {
                        TABLE
                            .set(Mutex::new(table))
                            .map_err(|_| "Failed to set flow table")
                            .unwrap();
                    }
                    Err(InstallError::NoSplitQueue(core)) => {
                        eprintln!(
                            "flow table not created: no split queue mapped for core {core:?}"
                        );
                    }
                    Err(e) => eprintln!("flow table not created: {e}"),
                }
            });
        }
    }

    // Run packet processing
    runtime.run();

    // Graceful shutdown
    let final_stats = worker_handle.shutdown(None);

    println!("{}", iris_core::lcore::datapath_budget::current());

    for p in iris_core::multicore::worker_budget::pools() {
        let w = p.budget;
        let tsc_hz = unsafe { iris_core::rte_get_tsc_hz() };
        println!(
            "Rule-install workers ({}): {:.4} cores busy over {} thread(s), {:.2}% mean \
             utilization, {} offloads handled, {:.0} offloads/s sustainable at one core",
            p.label,
            w.cores_busy(tsc_hz),
            w.threads,
            100.0 * w.busy_fraction(tsc_hz),
            w.items,
            w.sustainable_item_rate(),
        );
    }

    if let Some(table) = TABLE.get() {
        table.lock().unwrap().query_resident();
        // Not called: runtime.run() already ran rte_flow_flush in Port::stop, so these rules are gone.
        // table.lock().unwrap().uninstall_all();
    }

    let discarded_packets = DISCARDED_PACKETS.load(std::sync::atomic::Ordering::Relaxed);
    let discarded_bytes = DISCARDED_BYTES.load(std::sync::atomic::Ordering::Relaxed);
    println!("{discarded_packets} packets and {discarded_bytes} bytes discarded");

    println!("=== Offload by protocol ===");
    println!(
        "{:<12}{:>12}{:>12}{:>10}",
        "proto", "dispatched", "installed", "enabled"
    );
    for (proto, stats) in &STATS {
        println!(
            "{:<12}{:>12}{:>12}{:>10}",
            <&str>::from(proto),
            stats.dispatched.load(Ordering::Relaxed),
            stats.installed.load(Ordering::Relaxed),
            offload_enabled(proto),
        );
    }

    if *MODE.read().unwrap() == FlowMode::Standard {
        println!("=== On-wire bytes by encrypted protocol (Standard mode) ===");
        println!("{:<12}{:>16}", "proto", "bytes");
        let mut total = 0;
        for (proto, stats) in &STATS {
            let bytes = stats.wire_bytes.load(Ordering::Relaxed);
            total += bytes;
            println!("{:<12}{:>16}", <&str>::from(proto), bytes);
        }
        println!("{:<12}{:>16}", "total", total);
    }

    if args.show_stats
        && let Some(flow_stats) = final_stats.first()
    {
        println!("=== FLOW Stats ===");
        println!("{flow_stats}");
    }
}
