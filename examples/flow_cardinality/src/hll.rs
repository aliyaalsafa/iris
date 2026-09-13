//! A small HyperLogLog, shaped for the per-core x per-second grid in `main`.
//!
//! Vendored rather than pulled in as a dependency because the storage layout *is* the
//! design here. Every HLL crate owns a private `Vec<u8>` mutated through `&mut self`;
//! what the grid needs is a shared `[AtomicU8]` carved out of one preallocated
//! allocation, written single-writer from an RX core and read concurrently by the
//! reporter thread. Wrapping a crate to fake that would mean either allocating on the
//! datapath or taking a lock. The repo also has no sketch dependency today.
//!
//! What is given up by not using HLL++: the empirical bias-correction table and the
//! sparse representation. Neither is missed -- [`estimate`] uses Flajolet's original
//! `2.5m` switch, which avoids the band the bias table exists to fix, and the grid
//! deliberately preallocates fixed-size dense slots.
//!
//! A sketch here is just `2^p` single-byte registers, so it is passed around as a
//! `&[AtomicU8]` rather than wrapped in a type. That is what lets every sketch in the
//! grid be a slice of one big per-core allocation -- see [`zeroed`] -- and `p` is
//! recovered from the slice length, which costs one instruction.
//!
//! Registers are `AtomicU8` read and written `Relaxed`, which on x86-64 and aarch64
//! emits the same plain byte load/store as a non-atomic access. The cost is zero and it
//! makes the concurrent reporter-thread read well-defined rather than UB -- the same
//! trade [`transport_meter`](iris_core::lcore::transport_meter) makes for its counters.

use std::sync::atomic::{AtomicU8, Ordering};

/// Smallest and largest precision we accept. Below 4 the estimator's constants stop
/// applying; above 18 a single sketch is a quarter-megabyte.
pub const MIN_PRECISION: u32 = 4;
pub const MAX_PRECISION: u32 = 18;

/// Relative standard error of an HLL with `2^p` registers.
pub fn std_error(p: u32) -> f64 {
    1.04 / ((1u64 << p) as f64).sqrt()
}

/// murmur3's 64-bit finalizer.
///
/// A bijection, so it adds no entropy -- it redistributes the entropy already there so
/// every output bit depends on every input bit. This is not optional dressing.
/// [`FiveTuple::conn_hash`](iris_core::FiveTuple::conn_hash) and its `dir_hash` sibling
/// are FNV-1a, whose last step is a multiply, so output bit *i* depends only on input
/// bits `0..=i` -- the low bits we slice off for the register index are a very
/// low-degree function of the input. On structured traffic (sequential clients to one
/// server, or a horizontal scan) that drives the index distribution far from uniform
/// and the estimate off by tens of percent in either direction. Uniformly random
/// tuples hide the problem completely, which is exactly why it is worth a comment.
#[inline]
pub fn fmix64(mut z: u64) -> u64 {
    z ^= z >> 33;
    z = z.wrapping_mul(0xff51_afd7_ed55_8ccd);
    z ^= z >> 33;
    z = z.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    z ^= z >> 33;
    z
}

/// `n` zeroed registers.
///
/// Allocate the whole grid in one call, not a sketch at a time. `vec![0u8; n]` lowers to
/// `alloc_zeroed`, but glibc only serves that from a fresh `mmap` above its 128 KiB
/// threshold; below it the request comes from the heap arena and is `memset`, touching
/// every page. A single 4 KiB sketch is therefore fully resident the moment it is
/// created, whereas one multi-megabyte slab per core is handed back as untouched
/// anonymous pages and only becomes resident as seconds are actually written. Measured:
/// per-sketch allocation put 1190 MiB resident against a 1250 MiB reservation; one slab
/// per core keeps it near zero until the run fills it.
pub fn zeroed(n: usize) -> Box<[AtomicU8]> {
    let bytes: Box<[u8]> = vec![0u8; n].into_boxed_slice();
    // `AtomicU8` is guaranteed to have the same representation as `u8`, so a zeroed byte
    // allocation is already a valid array of zeroed atomics.
    unsafe { Box::from_raw(Box::into_raw(bytes) as *mut [AtomicU8]) }
}

/// Fold one 64-bit key into a sketch.
///
/// The key must already be well-distributed -- pass it through [`fmix64`] first.
///
/// Only the RX core owning this slot ever stores here, so the load/compare/store is
/// atomic as a whole without a CAS or `fetch_max`. A concurrent reader sees either the
/// old or the new value, and either is a valid sketch of a real subset of the stream.
/// The store is conditional so that a register which has already saturated costs no
/// write at all, which after the first few thousand packets in a second is the
/// overwhelmingly common case.
#[inline]
pub fn add(regs: &[AtomicU8], key: u64) {
    let p = regs.len().trailing_zeros();
    let idx = (key & (regs.len() as u64 - 1)) as usize;
    // Rank is the 1-based position of the leftmost set bit in the remaining `64 - p`
    // bits. `w` carries `p` leading padding zeros from the shift, so subtract them back
    // off. `w == 0` needs no special case: `leading_zeros()` returns 64, giving
    // `64 - p + 1`, which is exactly the textbook maximum.
    let w = key >> p;
    let rank = (w.leading_zeros() - p + 1) as u8;

    let reg = &regs[idx];
    if rank > reg.load(Ordering::Relaxed) {
        reg.store(rank, Ordering::Relaxed);
    }
}

/// Fold a sketch's registers into `acc` (register-wise max).
///
/// Exact, not approximate: a register holds a max over the keys landing in it, and a max
/// over a union is the max of the maxes, so the result is bit-identical to a sketch built
/// over the concatenated streams. This is what makes summing cores correct even when
/// non-symmetric RSS puts a flow's two directions on different ones.
pub fn merge_into(regs: &[AtomicU8], acc: &mut [u8]) {
    assert_eq!(acc.len(), regs.len(), "precision mismatch on merge");
    for (dst, reg) in acc.iter_mut().zip(regs.iter()) {
        *dst = (*dst).max(reg.load(Ordering::Relaxed));
    }
}

/// Cardinality estimate from a merged register array.
///
/// Merge first, then estimate. Estimating per core and summing would double-count every
/// flow more than one core saw and stack each core's small-range bias.
pub fn estimate(regs: &[u8]) -> f64 {
    let m = regs.len();
    debug_assert!(m.is_power_of_two());
    let mf = m as f64;

    let mut z = 0.0f64;
    let mut zeros = 0usize;
    for &r in regs {
        z += (-(r as f64)).exp2();
        if r == 0 {
            zeros += 1;
        }
    }

    let alpha = match m {
        16 => 0.673,
        32 => 0.697,
        64 => 0.709,
        _ => 0.7213 / (1.0 + 1.079 / mf),
    };
    let raw = alpha * mf * mf / z;

    // Small range: linear counting whenever the raw estimate is under 2.5m and some
    // register is still empty. This is where the per-second buckets actually live -- 0,
    // 1, a handful of flows -- and where raw HLL is worst: an empty second would read
    // as `alpha * m`, some thousands of flows, rather than zero. Linear counting is
    // near-exact here (n=1 gives 1.0001 at p=12) and degrades gracefully up to the
    // switch, where its error crosses HLL's.
    //
    // Deliberately Flajolet's 2.5m and *not* HLL++'s threshold table: those thresholds
    // presuppose HLL++'s empirical bias correction over the band above them, and
    // without that table the band carries up to +20% bias.
    if raw <= 2.5 * mf && zeros > 0 {
        return mf * (mf / zeros as f64).ln();
    }

    // No large-range correction. The classic `-2^32 * ln(1 - E/2^32)` term undoes
    // saturation of a *32-bit* hash space; with 64-bit keys it is not just unnecessary
    // but wrong, and it would start distorting estimates around 143M.
    raw
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    const P: u32 = 12;
    const M: usize = 1 << P;

    fn sketch_of(keys: impl IntoIterator<Item = u64>) -> Box<[AtomicU8]> {
        let h = zeroed(M);
        for k in keys {
            add(&h, fmix64(k));
        }
        h
    }

    fn registers(h: &[AtomicU8]) -> Vec<u8> {
        let mut acc = vec![0u8; h.len()];
        merge_into(h, &mut acc);
        acc
    }

    fn estimate_of(h: &[AtomicU8]) -> f64 {
        estimate(&registers(h))
    }

    /// Relative standard error of whichever estimator is actually in play at `n`.
    ///
    /// Below the `2.5m` switch that is linear counting, whose error is
    /// `sqrt(e^t - t - 1) / (t * sqrt(m))` with `t = n/m`; above it, HLL's constant
    /// `1.04/sqrt(m)`. The two cross at the switch by construction -- 1.81% against
    /// 1.63% at p=12 -- so a test that assumed HLL's figure everywhere would be too
    /// tight just below the boundary, which is where most of these cases sit.
    fn sigma_at(n: f64) -> f64 {
        let m = M as f64;
        if n > 2.5 * m {
            return std_error(P);
        }
        let t = n / m;
        if t == 0.0 {
            return 0.0;
        }
        (t.exp() - t - 1.0).sqrt() / (t * m.sqrt())
    }

    #[test]
    fn empty_estimates_exactly_zero() {
        // The bug this guards: raw HLL reports `alpha * m` ~= 2954 for an untouched
        // second, so a quiet window would look like thousands of flows.
        assert_eq!(estimate_of(&zeroed(M)), 0.0);
    }

    #[test]
    fn rank_is_bounded_and_uses_the_full_range() {
        let h = zeroed(M);
        // key = 0 puts rank at its maximum, 64 - p + 1.
        add(&h, 0);
        let regs = registers(&h);
        assert_eq!(regs[0], (64 - P + 1) as u8);

        // Every rank a key can produce must fit a u8 and be at least 1.
        for bit in 0..64 {
            let h = zeroed(M);
            add(&h, 1u64 << bit);
            assert!(registers(&h).iter().all(|&r| r <= (64 - P + 1) as u8));
        }
    }

    #[test]
    fn merge_equals_union() {
        // The strongest available assertion: byte-for-byte, not within a tolerance.
        let a = sketch_of(0..1000);
        let b = sketch_of(500..1500);
        let union = sketch_of(0..1500);

        let mut merged = vec![0u8; M];
        merge_into(&a, &mut merged);
        merge_into(&b, &mut merged);
        assert_eq!(merged, registers(&union));
    }

    #[test]
    fn merge_is_idempotent_and_commutative() {
        let a = sketch_of(0..5000);
        let b = sketch_of(3000..9000);

        let mut ab = vec![0u8; M];
        merge_into(&a, &mut ab);
        merge_into(&b, &mut ab);

        let mut ba = vec![0u8; M];
        merge_into(&b, &mut ba);
        merge_into(&a, &mut ba);
        assert_eq!(ab, ba);

        let mut aa = vec![0u8; M];
        merge_into(&a, &mut aa);
        merge_into(&a, &mut aa);
        assert_eq!(aa, registers(&a));
    }

    #[test]
    fn insertion_order_does_not_matter() {
        let forward = sketch_of(0..4000);
        let backward = sketch_of((0..4000).rev());
        assert_eq!(registers(&forward), registers(&backward));
    }

    #[test]
    fn tiny_cardinalities_are_near_exact() {
        // Deep in the linear-counting regime, which is where most per-second buckets
        // live. Below a handful of keys the estimator is effectively exact; past that
        // it still has sampling error, so allow 3 sigma once that exceeds one flow.
        for n in [0u64, 1, 2, 3, 5, 10, 64] {
            let est = estimate_of(&sketch_of(0..n));
            let tol = (3.0 * sigma_at(n as f64) * n as f64).max(1.0);
            assert!(
                (est - n as f64).abs() <= tol,
                "n={n} estimated {est}, want within {tol:.2}"
            );
        }
    }

    #[test]
    fn error_stays_within_three_sigma() {
        // n = 5000 is deliberately included: it is the cardinality where using HLL++'s
        // threshold without its bias table reads +20%, so this pins the estimator
        // choice, not just the arithmetic. n = 10000 sits just under the 2.5m switch
        // and n = 20000 just over, bracketing the crossover.
        for n in [1_000u64, 5_000, 10_000, 20_000, 100_000] {
            let sigma = sigma_at(n as f64);
            let mut errors = Vec::new();
            for trial in 0..16u64 {
                // Disjoint key ranges stand in for independent trials; fmix64 makes
                // them independent in the only way that matters here.
                let base = trial * 10_000_000;
                let est = estimate_of(&sketch_of(base..base + n));
                errors.push(est / n as f64 - 1.0);
            }
            let worst = errors.iter().cloned().fold(0.0f64, |a, e| a.max(e.abs()));
            let mean = errors.iter().sum::<f64>() / errors.len() as f64;
            assert!(
                worst < 3.0 * sigma,
                "n={n}: worst error {worst:.4} > 3 sigma ({:.4})",
                3.0 * sigma
            );
            // The estimator should be unbiased, so the mean over trials must shrink
            // well inside a single trial's error.
            assert!(mean.abs() < sigma, "n={n}: mean error {mean:.4} is biased");
        }
    }

    #[test]
    fn structured_traffic_stays_uniform() {
        // The test this whole fmix64 business exists for. Sequential client addresses
        // and sequential ephemeral ports to one server is the shape that makes a raw
        // FNV index collapse; here we assert both the index distribution and the
        // resulting estimate.
        const N: u64 = 80_000;
        let key = |i: u64| {
            // (client_ip, client_port) -> fixed server, packed the way an endpoint hash
            // would pack it, then finalized.
            let client = 0x0a00_0000u64 + (i >> 8);
            let port = 1024 + (i & 0xff);
            fmix64(((client << 16) | port).wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ 443)
        };

        let mut hist = vec![0u32; M];
        for i in 0..N {
            hist[(key(i) & (M as u64 - 1)) as usize] += 1;
        }
        // Chi-square on the register index. Expected M-1 df, sd = sqrt(2*(M-1)) ~= 90.
        let expected = N as f64 / M as f64;
        let chi2: f64 = hist
            .iter()
            .map(|&c| {
                let d = c as f64 - expected;
                d * d / expected
            })
            .sum();
        let df = (M - 1) as f64;
        let sd = (2.0 * df).sqrt();
        assert!(
            (chi2 - df).abs() < 4.0 * sd,
            "chi2 {chi2} is {} sd from {df}; index is not uniform",
            (chi2 - df).abs() / sd
        );

        let h = zeroed(M);
        for i in 0..N {
            add(&h, key(i));
        }
        let est = estimate_of(&h);
        assert!(
            (est / N as f64 - 1.0).abs() < 0.05,
            "structured traffic estimated {est}, want ~{N}"
        );
    }

    #[test]
    fn agrees_with_an_exact_set() {
        // Same comparison the app's --exact mode makes, in miniature.
        let keys: Vec<u64> = (0..30_000).map(|i| fmix64(i * 2_654_435_761)).collect();
        let exact: HashSet<u64> = keys.iter().copied().collect();

        let h = zeroed(M);
        for k in &keys {
            add(&h, *k);
        }
        let est = estimate_of(&h);
        let truth = exact.len() as f64;
        assert!(
            (est / truth - 1.0).abs() < 3.0 * std_error(P),
            "estimated {est} against exact {truth}"
        );
    }
}
