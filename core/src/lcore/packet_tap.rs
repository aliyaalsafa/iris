//! A per-packet observation hook for the receive datapath.
//!
//! Iris scopes every subscription to a connection, so an application cannot see the
//! packets connection tracking discards: mid-stream TCP (a connection is only built
//! from a pure SYN), anything that is not IPv4/IPv6 + TCP/UDP, and flows arriving once
//! `max_connections` is reached. A tap sits ahead of all of that -- it is handed every
//! mbuf the processing datapath receives, before the software flow table and before the
//! generated packet filter.
//!
//! Two things a tap still cannot see, both by construction: packets steered to a sink
//! queue, since `rx_sink` is a drain rather than part of the pipeline, and packets a
//! hardware `rte_flow` rule dropped, which never reach `rte_eth_rx_burst` at all.
//!
//! # Cost when unused
//!
//! [`installed`] is read once per RX core at loop entry, never per packet. A run with
//! no tap therefore pays one predictable branch on a register-resident `Option<fn>`,
//! not an atomic load per packet.

use crate::lcore::CoreId;
use crate::memory::mbuf::Mbuf;

use std::sync::OnceLock;
use std::time::Instant;

/// Observer invoked for every packet the receive datapath is handed.
///
/// `now` is the datapath's coarse clock, refreshed about once per RX burst rather than
/// per packet. It is accurate to well under a millisecond, which is as much as the
/// datapath can afford and far more than per-second accounting needs.
///
/// Runs inline on the RX core, so anything expensive belongs on a worker thread --
/// see [`crate::multicore`].
pub type PacketTapFn = fn(&Mbuf, &CoreId, Instant);

static TAP: OnceLock<PacketTapFn> = OnceLock::new();

/// Install the process-wide tap, returning `Err(tap)` if one is already installed.
///
/// Must be called before [`Runtime::run`](crate::Runtime::run): each RX core reads the
/// tap once when its loop starts, so a later install is never picked up.
pub fn install(tap: PacketTapFn) -> Result<(), PacketTapFn> {
    TAP.set(tap)
}

/// The installed tap, if any.
///
/// Call once, at RX-loop entry, and keep the result in a local -- see the note on cost
/// in the module documentation.
pub fn installed() -> Option<PacketTapFn> {
    TAP.get().copied()
}
