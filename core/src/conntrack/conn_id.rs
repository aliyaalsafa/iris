//! Bidirectional connection identifiers.
//!
//! Provides endpoint-specific (distinguishes originator and responder) and generic identifiers for bi-directional connections.
//! Iris defines a "connection" by five tuple (source/destination addresses, ports, and transport protocol).

use crate::conntrack::L4Context;

use crate::protocols::packet::tcp::TCP_PROTOCOL;
use crate::protocols::packet::udp::UDP_PROTOCOL;
use std::cmp;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddr::V4, SocketAddr::V6};

use serde::Serialize;

/// Connection 5-tuple.
///
/// The sender of the first observed packet in the connection becomes the originator `orig`, and the
/// recipient becomes the responder `resp`.
#[derive(Debug, Copy, Clone, Hash, Eq, PartialEq, Serialize)]
pub struct FiveTuple {
    /// The originator connection endpoint.
    pub orig: SocketAddr,
    /// The responder connection endpoint.
    pub resp: SocketAddr,
    /// The layer-4 protocol.
    pub proto: usize,
}

const FNV_OFFSET: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;

/// Fold `v`'s bytes into the FNV-1a accumulator `h`.
#[inline]
fn mix(mut h: u64, v: u64) -> u64 {
    for byte in v.to_le_bytes() {
        h ^= byte as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

/// Collapse an endpoint to one word. IPv6 is folded in half, so v6 addresses
/// differing only in the halves' xor collide -- acceptable for a non-unique hash.
#[inline]
fn hash_sockaddr(sa: SocketAddr) -> u64 {
    let ip: u64 = match sa {
        V4(a) => a.ip().to_bits() as u64,
        V6(a) => {
            let n = a.ip().to_bits();
            (n as u64) ^ ((n >> 64) as u64)
        }
    };
    (ip << 16) ^ (sa.port() as u64)
}

impl FiveTuple {
    /// Creates a new 5-tuple from `ctxt`.
    pub fn from_ctxt(ctxt: &L4Context) -> Self {
        FiveTuple {
            orig: ctxt.src,
            resp: ctxt.dst,
            proto: ctxt.proto,
        }
    }

    /// Converts a 5-tuple to a non-directional connection identifier.
    pub fn conn_id(&self) -> ConnId {
        ConnId::new(self.orig, self.resp, self.proto)
    }

    /// Non-bucketed u64 hash of the canonicalized five-tuple, i.e. the same value for
    /// both directions of a connection.
    ///
    /// Paired downstream with `first_seen_ts` to form
    /// the composite connection key; `conn_hash` alone is NOT unique.
    ///
    /// See [`FiveTuple::dir_hash`] for the direction-sensitive counterpart.
    pub fn conn_hash(&self) -> u64 {
        let (hi, lo) = (
            cmp::max(self.orig, self.resp),
            cmp::min(self.orig, self.resp),
        );
        let mut h = FNV_OFFSET;
        h = mix(h, hash_sockaddr(hi));
        h = mix(h, hash_sockaddr(lo));
        h = mix(h, self.proto as u64);
        h
    }

    /// Non-bucketed u64 hash of the five-tuple as observed on the wire.
    ///
    /// Unlike [`FiveTuple::conn_hash`] the endpoints are not sorted, so the two
    /// directions of a connection hash differently. Use this to count distinct
    /// `(src, sport, dst, dport, proto)` tuples; use `conn_hash` to count distinct
    /// connections.
    ///
    /// Like `conn_hash`, this is not unique on its own.
    pub fn dir_hash(&self) -> u64 {
        let mut h = FNV_OFFSET;
        h = mix(h, hash_sockaddr(self.orig));
        h = mix(h, hash_sockaddr(self.resp));
        h = mix(h, self.proto as u64);
        h
    }

    /// Utility for returning a string representation of the dst. subnet
    /// /24 for IPv4, /64 for IPv6; no mask for broadcast
    pub fn dst_subnet_str(&self) -> String {
        if let V4(_) = self.orig {
            if let V4(dst) = self.resp {
                if dst.ip().is_broadcast() || dst.ip().is_multicast() {
                    return dst.ip().to_string();
                } else {
                    let mask = !0u32 << (32 - 24); // Convert to a /24
                    return Ipv4Addr::from(dst.ip().to_bits() & mask).to_string();
                }
            }
        } else if let V6(_) = self.orig {
            if let V6(dst) = self.resp {
                let mask = !0u128 << (128 - 64); // Convert to a /64
                return Ipv6Addr::from(dst.ip().to_bits() & mask).to_string();
            }
        }
        String::new()
    }

    /// Utility for returning a string representation of the dst. IP
    pub fn dst_ip_str(&self) -> String {
        if let V4(dst) = self.resp {
            return dst.ip().to_string();
        }
        if let V6(dst) = self.resp {
            return dst.ip().to_string();
        }
        String::new()
    }

    pub fn src_ip_str(&self) -> String {
        if let V4(src) = self.orig {
            return src.ip().to_string();
        } else if let V6(src) = self.orig {
            return src.ip().to_string();
        }
        String::new()
    }

    /// Utility for returning a string representation of the transport
    /// protocol and source/destination ports
    pub fn transp_proto_str(&self) -> String {
        let src_port = self.orig.port();
        let dst_port = self.resp.port();
        let proto = match self.proto {
            UDP_PROTOCOL => "udp",
            TCP_PROTOCOL => "tcp",
            _ => "none",
        };
        format!(
            "{{ \"proto\": \"{}\", \"src\": \"{}\", \"dst\": \"{}\" }}",
            proto, src_port, dst_port
        )
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> ", self.orig)?;
        write!(f, "{}", self.resp)?;
        write!(f, " protocol {}", self.proto)?;
        Ok(())
    }
}

/// A generic connection identifier.
///
/// Identifies a connection independent of the source and destination socket address order. Does not
/// distinguish between the originator and responder of the connection.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct ConnId(SocketAddr, SocketAddr, usize);

impl ConnId {
    /// Returns the connection ID of a packet with `src` and `dst` IP/port pairs.
    pub(super) fn new(src: SocketAddr, dst: SocketAddr, protocol: usize) -> Self {
        ConnId(cmp::max(src, dst), cmp::min(src, dst), protocol)
    }
}

impl fmt::Display for ConnId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} <> ", self.0)?;
        write!(f, "{}", self.1)?;
        write!(f, " protocol {}", self.2)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn tuple(src: (&str, u16), dst: (&str, u16), proto: usize) -> FiveTuple {
        let sock =
            |(ip, port): (&str, u16)| SocketAddr::new(ip.parse::<IpAddr>().expect("addr"), port);
        FiveTuple {
            orig: sock(src),
            resp: sock(dst),
            proto,
        }
    }

    /// Swap the endpoints, as the reverse direction of the same connection would.
    fn reversed(t: &FiveTuple) -> FiveTuple {
        FiveTuple {
            orig: t.resp,
            resp: t.orig,
            proto: t.proto,
        }
    }

    #[test]
    fn conn_hash_is_symmetric_dir_hash_is_not() {
        for t in [
            tuple(("10.0.0.1", 1234), ("10.0.0.2", 443), TCP_PROTOCOL),
            tuple(("2001:db8::1", 53), ("2001:db8::2", 9999), UDP_PROTOCOL),
        ] {
            let r = reversed(&t);
            assert_eq!(t.conn_hash(), r.conn_hash(), "conn_hash must canonicalize");
            assert_ne!(t.dir_hash(), r.dir_hash(), "dir_hash must be directional");
        }
    }

    #[test]
    fn both_hashes_separate_distinct_tuples() {
        let base = tuple(("10.0.0.1", 1234), ("10.0.0.2", 443), TCP_PROTOCOL);
        // One field different in each: port, address, protocol.
        for other in [
            tuple(("10.0.0.1", 1235), ("10.0.0.2", 443), TCP_PROTOCOL),
            tuple(("10.0.0.1", 1234), ("10.0.0.3", 443), TCP_PROTOCOL),
            tuple(("10.0.0.1", 1234), ("10.0.0.2", 443), UDP_PROTOCOL),
        ] {
            assert_ne!(base.conn_hash(), other.conn_hash());
            assert_ne!(base.dir_hash(), other.dir_hash());
        }
    }

    #[test]
    fn conn_hash_has_not_moved() {
        // `conn_hash` is half of a composite connection key downstream, so its value is
        // part of the API, not an implementation detail. These are computed from the
        // FNV-1a definition by a separate implementation; they pin the hash against an
        // accidental change when its helpers are edited.
        let t = tuple(("10.0.0.1", 1234), ("10.0.0.2", 443), TCP_PROTOCOL);
        assert_eq!(t.conn_hash(), 0x0205_0803_386e_1236);
        assert_eq!(t.dir_hash(), 0x3714_856c_d9ff_16ce);
    }

    #[test]
    fn hashes_are_deterministic() {
        let t = tuple(("192.0.2.7", 80), ("198.51.100.9", 51000), TCP_PROTOCOL);
        assert_eq!(t.conn_hash(), t.conn_hash());
        assert_eq!(t.dir_hash(), t.dir_hash());
    }

    #[test]
    fn v4_and_v6_endpoints_are_distinguished() {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 80);
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 80);
        assert_ne!(hash_sockaddr(v4), hash_sockaddr(v6));
    }
}
