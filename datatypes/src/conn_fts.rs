//! Various individual connection-level subscribable types for TCP and/or UDP
//! connection information, statistics, and state history.

#[allow(unused_imports)]
use iris_compiler::{datatype, datatype_fn};
use iris_core::subscription::Tracked;
use iris_core::L4Pdu;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::time::{Duration, Instant};

/// Tracks the start (first packet seen) and end (last packet seen)
/// times of a connection
#[cfg_attr(not(feature = "skip_expand"), datatype)]
#[derive(Debug, Clone)]
pub struct ConnDuration {
    pub start_ts: Instant,
    pub last_ts: Instant,
}

impl Serialize for ConnDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("ConnDuration", 1)?;

        let duration = self.last_ts - self.start_ts;
        state.serialize_field("duration", &duration.as_millis())?;
        state.end()
    }
}

impl ConnDuration {
    /// The duration of the connection in milliseconds
    pub fn duration_ms(&self) -> u128 {
        (self.last_ts - self.start_ts).as_millis()
    }

    /// The duration of the connection as std::time::Duration
    pub fn duration(&self) -> Duration {
        self.last_ts - self.start_ts
    }
}

impl ConnDuration {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("ConnDuration,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        self.last_ts = pdu.ts;
    }
}

impl Tracked for ConnDuration {
    fn new(_first_pkt: &L4Pdu) -> Self {
        let now = Instant::now();
        Self {
            start_ts: now,
            last_ts: now,
        }
    }

    #[inline]
    fn clear(&mut self) {}
}

/// The number of packets observed in a connection
#[derive(Debug, serde::Serialize, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct PktCount {
    pub orig: usize,
    pub resp: usize,
}

impl PktCount {
    pub fn total(&self) -> usize {
        self.orig + self.resp
    }

    pub fn orig(&self) -> usize {
        self.orig
    }

    pub fn resp(&self) -> usize {
        self.resp
    }
}

impl PktCount {
    #[inline]
    #[cfg_attr(not(feature = "skip_expand"), datatype_fn("PktCount,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            self.orig += 1;
        } else {
            self.resp += 1;
        }
    }
}

impl Tracked for PktCount {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { orig: 0, resp: 0 }
    }

    #[inline]
    fn clear(&mut self) {}
}

/// The number of bytes, excluding packet headers, in each
/// flow in a connection connection
#[derive(Debug, serde::Serialize, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct ByteCount {
    pub orig: usize,
    pub resp: usize,
}

impl ByteCount {
    pub fn total(&self) -> usize {
        self.orig + self.resp
    }

    pub fn orig(&self) -> usize {
        self.orig
    }

    pub fn resp(&self) -> usize {
        self.resp
    }
}

impl ByteCount {
    #[inline]
    #[cfg_attr(not(feature = "skip_expand"), datatype_fn("ByteCount,level=InL4Conn"))]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            self.orig += pdu.length();
        } else {
            self.resp += pdu.length();
        }
    }
}

impl Tracked for ByteCount {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self { orig: 0, resp: 0 }
    }

    #[inline]
    fn clear(&mut self) {}
}

/// Streaming inter-arrival statistics for one direction.
///
/// Maintains running count, sum, sum-of-squares, min, and max so per-packet
/// snapshots are O(1) to update and read, avoiding a full re-scan of the
/// interarrival history.
#[derive(Debug, Clone)]
pub struct IatStats {
    count: u64,
    sum_us: f64,
    sum_sq_us: f64,
    min_us: u128,
    max_us: u128,
}

impl IatStats {
    fn new() -> Self {
        Self {
            count: 0,
            sum_us: 0.0,
            sum_sq_us: 0.0,
            min_us: 0,
            max_us: 0,
        }
    }

    #[inline]
    fn push(&mut self, dur: Duration) {
        let v = dur.as_micros();
        if self.count == 0 || v < self.min_us {
            self.min_us = v;
        }
        if self.count == 0 || v > self.max_us {
            self.max_us = v;
        }
        self.count += 1;
        self.sum_us += v as f64;
        self.sum_sq_us += (v as f64) * (v as f64);
    }

    fn clear(&mut self) {
        self.count = 0;
        self.sum_us = 0.0;
        self.sum_sq_us = 0.0;
        self.min_us = 0;
        self.max_us = 0;
    }

    /// Returns (mean, min, max, std) in microseconds.
    pub fn summary(&self) -> (f64, u64, u64, f64) {
        let n = self.count;
        if n == 0 {
            return (0.0, 0, 0, 0.0);
        }
        let mean = self.sum_us / n as f64;
        let variance = (self.sum_sq_us / n as f64) - mean * mean;
        let std_dev = variance.max(0.0).sqrt();
        (mean, self.min_us as u64, self.max_us as u64, std_dev)
    }
}

/// Tracked data for packet inter-arrival times
#[derive(Debug, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct InterArrivals {
    pkt_count_ctos: usize,
    pkt_count_stoc: usize,
    last_pkt_ctos: Instant,
    last_pkt_stoc: Instant,
    /// Interarrival statistics client-to-server (orig.) flow. Only running statistics are
    /// kept: a per-packet history grows for the life of the connection.
    pub stats_ctos: IatStats,
    /// Interarrival statistics server-to-client (resp.) flow

    pub stats_stoc: IatStats,
}

impl InterArrivals {
    pub fn new_empty() -> Self {
        let now = Instant::now();
        Self {
            pkt_count_ctos: 0,
            pkt_count_stoc: 0,
            last_pkt_ctos: now,
            last_pkt_stoc: now,
            stats_ctos: IatStats::new(),
            stats_stoc: IatStats::new(),
        }
    }
}

impl InterArrivals {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("InterArrivals,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        let now = Instant::now();
        if pdu.dir {
            self.pkt_count_ctos += 1;
            if self.pkt_count_ctos > 1 {
                self.stats_ctos.push(now - self.last_pkt_ctos);
            }
            self.last_pkt_ctos = now;
        } else {
            self.pkt_count_stoc += 1;
            if self.pkt_count_stoc > 1 {
                self.stats_stoc.push(now - self.last_pkt_stoc);
            }
            self.last_pkt_stoc = now;
        }
    }
}

impl Tracked for InterArrivals {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self::new_empty()
    }

    #[inline]
    fn clear(&mut self) {
        self.stats_ctos.clear();
        self.stats_stoc.clear();
    }
}

/// (mean, min, max, std) in microseconds; see [`IatStats::summary`].
struct IatSummary<'a>(&'a IatStats);
impl Serialize for IatSummary<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let (mean, min, max, std) = self.0.summary();
        let mut state = serializer.serialize_struct("IatSummary", 4)?;
        state.serialize_field("mean_us", &mean)?;
        state.serialize_field("min_us", &min)?;
        state.serialize_field("max_us", &max)?;
        state.serialize_field("std_us", &std)?;
        state.end()
    }
}

impl Serialize for InterArrivals {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("InterArrivals", 2)?;
        state.serialize_field("interarrivals_ctos", &IatSummary(&self.stats_ctos))?;
        state.serialize_field("interarrivals_stoc", &IatSummary(&self.stats_stoc))?;
        state.end()
    }
}

use crate::connection::update_history;

/// Connection history.
///
/// This represents a summary of the connection history in the order the packets were observed,
/// with letters encoded as a vector of bytes. This is a simplified version of [state history in
/// Zeek](https://docs.zeek.org/en/v5.0.0/scripts/base/protocols/conn/main.zeek.html), and the
/// meanings of each letter are similar: If the event comes from the originator, the letter is
/// uppercase; if the event comes from the responder, the letter is lowercase.
/// - S: a pure SYN with only the SYN bit set (may have payload)
/// - H: a pure SYNACK with only the SYN and ACK bits set (may have payload)
/// - A: a pure ACK with only the ACK bit set and no payload
/// - D: segment contains non-zero payload length
/// - F: the segment has the FIN bit set (may have other flags and/or payload)
/// - R: segment has the RST bit set (may have other flags and/or payload)
///
/// Each letter is recorded a maximum of once in either direction.
#[derive(Default, Debug, serde::Serialize, Clone)]
#[cfg_attr(not(feature = "skip_expand"), datatype)]
pub struct ConnHistory {
    pub history: Vec<u8>,
}

impl ConnHistory {
    #[inline]
    #[cfg_attr(
        not(feature = "skip_expand"),
        datatype_fn("ConnHistory,level=InL4Conn")
    )]
    pub fn update(&mut self, pdu: &L4Pdu) {
        if pdu.dir {
            update_history(&mut self.history, pdu, 0x0);
        } else {
            update_history(&mut self.history, pdu, 0x20);
        }
    }
}

impl Tracked for ConnHistory {
    fn new(_first_pkt: &L4Pdu) -> Self {
        Self {
            history: Vec::with_capacity(16),
        }
    }

    #[inline]
    fn clear(&mut self) {}
}
