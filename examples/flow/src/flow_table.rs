//! A FIFO-bounded table of installed rte_flow rules, one entry per offloaded 5-tuple.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use iris_core::dpdk::{rte_flow, rte_flow_action_handle};
use iris_core::{
    CoreId, FiveTuple,
    config::FlowMode,
    filter::flow_drop::{
        SplitQueueMap, install_drop_flow, install_split_flow, query_resident_flow, uninstall_flow,
    },
    port::PortId,
    protocols::packet::tcp::TCP_PROTOCOL,
};

/// One offloaded 5-tuple's rules; dropping it uninstalls them from every port.
struct FlowEntry {
    tuple: FiveTuple,
    ports: Arc<[PortId]>,
    flows: Vec<*mut rte_flow>,
    handles: Vec<*mut rte_flow_action_handle>,
}

// SAFETY: the rte_flow pointers are opaque handles owned solely by this entry, and rte_flow calls on them are thread-safe.
unsafe impl Send for FlowEntry {}

impl Drop for FlowEntry {
    fn drop(&mut self) {
        let flows = std::mem::take(&mut self.flows);
        let handles = std::mem::take(&mut self.handles);
        if let Err(e) = uninstall_flow(self.ports.to_vec(), flows, handles) {
            eprintln!("Failed to uninstall flow: {:?}", e);
        }
    }
}

/// Why a rule was not installed.
#[derive(Debug)]
pub enum InstallError {
    /// The mode is `Standard` or the capacity is zero, so no rules are installed.
    Disabled,
    /// A rule for this 5-tuple is already in the table.
    AlreadyInstalled,
    /// The mode uses split queues but the core has no entry in the split-queue map.
    NoSplitQueue(CoreId),
    /// rte_flow rejected the rule; holds the driver error text.
    Rte(String),
}

impl fmt::Display for InstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InstallError::Disabled => write!(f, "flow installation disabled"),
            InstallError::AlreadyInstalled => write!(f, "flow already installed"),
            InstallError::NoSplitQueue(core) => {
                write!(f, "no split queue mapped for core {core:?}")
            }
            InstallError::Rte(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for InstallError {}

impl From<String> for InstallError {
    fn from(e: String) -> Self {
        InstallError::Rte(e)
    }
}

/// The rte_flow rules installed on every port, oldest first, capped at `capacity` entries.
///
/// After construction the table is always full, so every `install` evicts the oldest entry.
pub struct FlowTable {
    mode: FlowMode,
    ports: Arc<[PortId]>,
    split_queues: Option<SplitQueueMap>,
    capacity: usize,
    installed: VecDeque<FlowEntry>,
    tuples: HashSet<FiveTuple>,
}

impl FlowTable {
    /// Creates a table that installs `mode` rules on `ports`, holding at most `capacity`.
    ///
    /// The table is filled to capacity with dummy rules that match no traffic (steered to
    /// `rx_core`'s split queues if needed), so every later `install` evicts the oldest entry.
    /// The fill's outcome is printed; a rule error stops it early but is not returned as `Err`.
    /// The ports must be ready for rte_flow rules (typically started) before calling this.
    pub fn new(
        mode: FlowMode,
        ports: Vec<PortId>,
        split_queues: Option<SplitQueueMap>,
        capacity: usize,
        rx_core: CoreId,
    ) -> Result<Self, InstallError> {
        let mut table = Self {
            mode,
            ports: ports.into(),
            split_queues,
            capacity,
            installed: VecDeque::with_capacity(capacity),
            tuples: HashSet::new(),
        };
        match table.prepare(rx_core) {
            Ok(queues) => {
                table.prefill(queues.as_deref());
                Ok(table)
            }
            Err(InstallError::Disabled) => Ok(table),
            Err(e) => Err(e),
        }
    }

    /// Installs rules for `tuple` on every port, steering to `rx_core`'s split queues if needed.
    ///
    /// A tuple already in the table is rejected with `AlreadyInstalled`. The table is full after
    /// construction, so each install first evicts the oldest entry (dummies first, then real
    /// flows). A failed install still evicts, losing that entry; the next successful install
    /// refills the slot. `NoSplitQueue` means the split-queue map has no queues for `rx_core`.
    pub fn install(&mut self, tuple: FiveTuple, rx_core: CoreId) -> Result<(), InstallError> {
        if self.tuples.contains(&tuple) {
            return Err(InstallError::AlreadyInstalled);
        }
        let split_queues = self.prepare(rx_core)?;

        if self.installed.len() >= self.capacity {
            self.evict_one();
        }

        let entry = install_entry(self.mode, &self.ports, &tuple, split_queues.as_deref())?;
        self.tuples.insert(tuple);
        self.installed.push_back(entry);
        debug_assert!(self.installed.len() <= self.capacity);
        Ok(())
    }

    /// Uninstalls every rule in the table, oldest first, leaving it empty; it is not refilled.
    ///
    /// Entries also uninstall on drop, so the table must be dropped or cleared before EAL/port
    /// teardown.
    pub fn uninstall_all(&mut self) {
        self.installed.clear();
        self.tuples.clear();
    }

    /// Fills the empty table to capacity with dummy rules; callers must have passed `prepare`.
    ///
    /// Dummies count toward capacity and are evicted like real entries, but they are not
    /// recorded for dedup.
    fn prefill(&mut self, split_queues: Option<&[u16]>) {
        let start = Instant::now();
        for i in 0..self.capacity {
            match install_entry(self.mode, &self.ports, &dummy_tuple(i), split_queues) {
                Ok(entry) => self.installed.push_back(entry),
                Err(e) => {
                    eprintln!("prefill stopped after {i} rules: {e}");
                    break;
                }
            }
        }
        debug_assert!(self.installed.len() <= self.capacity);
        println!(
            "prefilled {} of {} dummy flows in {:?}",
            self.installed.len(),
            self.capacity,
            start.elapsed()
        );
    }

    /// Queries every resident rule on the NIC and prints any query failure to stderr.
    pub fn query_resident(&self) {
        for entry in self.installed.iter() {
            if let Err(e) = query_resident_flow(&entry.ports, &entry.flows, &entry.handles) {
                eprintln!("resident flow query failed: {e:?}");
            }
        }
    }

    /// Checks the table can install rules and resolves `rx_core`'s split queues, one per port.
    fn prepare(&self, rx_core: CoreId) -> Result<Option<Vec<u16>>, InstallError> {
        if self.mode == FlowMode::Standard || self.capacity == 0 {
            return Err(InstallError::Disabled);
        }
        self.mode
            .uses_split_queues()
            .then(|| {
                self.split_queues
                    .as_ref()
                    .and_then(|m| m.queues_for(rx_core))
                    .ok_or(InstallError::NoSplitQueue(rx_core))
            })
            .transpose()
    }

    fn evict_one(&mut self) {
        if let Some(oldest) = self.installed.pop_front() {
            self.tuples.remove(&oldest.tuple);
        }
    }
}

/// Install one flow's rules for `mode` on every port. Callers must have passed `prepare`.
fn install_entry(
    mode: FlowMode,
    ports: &Arc<[PortId]>,
    tuple: &FiveTuple,
    split_queues: Option<&[u16]>,
) -> Result<FlowEntry, String> {
    let result = match mode {
        FlowMode::Drop => install_drop_flow(ports.to_vec(), tuple),
        FlowMode::Split | FlowMode::TrimNativeDpdk => install_split_flow(
            ports.to_vec(),
            tuple,
            split_queues.expect("split modes resolve queues in prepare"),
        ),
        FlowMode::Standard => unreachable!("Standard mode is rejected by prepare"),
    };
    let (flows, handles) = result.map_err(|e| format!("{e:?}"))?;
    Ok(FlowEntry {
        tuple: *tuple,
        ports: Arc::clone(ports),
        flows,
        handles,
    })
}

fn dummy_tuple(i: usize) -> FiveTuple {
    let orig_ip = Ipv4Addr::new(198, 18, (i >> 8) as u8, i as u8);
    let orig_port = 1024 + (i >> 16) as u16;
    FiveTuple {
        orig: SocketAddr::new(IpAddr::V4(orig_ip), orig_port),
        resp: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 19, 0, 1)), 9),
        proto: TCP_PROTOCOL,
    }
}
