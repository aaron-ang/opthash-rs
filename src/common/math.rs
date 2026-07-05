use super::config::{
    DEFAULT_RESERVE_FRACTION, GROUP_SIZE, MAX_RESERVE_FRACTION, MIN_RESERVE_FRACTION,
};

/// `f64 ↔ usize` casts with the truncation/sign lints we accept here.
pub(crate) mod cast {
    #[cfg(not(feature = "std"))]
    use crate::common::float::FloatExt as _;

    #[allow(clippy::cast_precision_loss)]
    #[inline]
    pub(crate) fn usize_to_f64(value: usize) -> f64 {
        value as f64
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    #[inline]
    pub(crate) fn floor_to_usize(value: f64) -> usize {
        value.floor() as usize
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    #[inline]
    pub(crate) fn ceil_to_usize(value: f64) -> usize {
        value.ceil() as usize
    }

    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    #[inline]
    pub(crate) fn round_to_usize(value: f64) -> usize {
        value.round() as usize
    }
}

/// Capacity + reserve-fraction arithmetic.
pub(crate) mod capacity {
    use super::cast::{floor_to_usize, usize_to_f64};
    use super::{DEFAULT_RESERVE_FRACTION, MAX_RESERVE_FRACTION, MIN_RESERVE_FRACTION};

    #[inline]
    pub(crate) fn max_insertions(capacity: usize, reserve_fraction: f64) -> usize {
        capacity.saturating_sub(floor_to_usize(reserve_fraction * usize_to_f64(capacity)))
    }

    /// Smallest capacity `>= start` (doubling) whose `max_insertions` fits
    /// `needed`. `None` if doubling overflows before reaching it.
    #[inline]
    pub(crate) fn capacity_for(
        start: usize,
        needed: usize,
        reserve_fraction: f64,
    ) -> Option<usize> {
        let mut cap = start;
        while max_insertions(cap, reserve_fraction) < needed {
            cap = cap.checked_mul(2)?;
        }
        Some(cap)
    }

    pub(crate) fn sanitize_reserve_fraction(reserve_fraction: f64) -> f64 {
        if reserve_fraction.is_finite() {
            reserve_fraction.clamp(MIN_RESERVE_FRACTION, MAX_RESERVE_FRACTION)
        } else {
            DEFAULT_RESERVE_FRACTION
        }
    }

    pub(crate) fn ceil_three_quarters(value: usize) -> usize {
        (value.saturating_mul(3).saturating_add(3)) / 4
    }

    pub(crate) fn floor_half_reserve_slots(reserve_fraction: f64, value: usize) -> usize {
        floor_to_usize((reserve_fraction * usize_to_f64(value)) / 2.0)
    }

    #[inline]
    pub(crate) fn tombstone_cleanup_threshold(capacity: usize) -> usize {
        let half = capacity / 2;
        let cap_three_quarters = capacity.saturating_mul(3) / 4;
        let hysteresis = half.saturating_add(super::GROUP_SIZE.saturating_mul(4));
        hysteresis.min(cap_three_quarters).max(half)
    }
}

/// Slot/group-count rounding for layout alignment.
pub(crate) mod align {
    use super::GROUP_SIZE;

    #[inline]
    pub(crate) fn round_up_to_group(value: usize) -> usize {
        if value == 0 {
            0
        } else {
            value.div_ceil(GROUP_SIZE) * GROUP_SIZE
        }
    }

    /// Round `slots` up so `group_count = ceil(slots / GROUP_SIZE)` is pow2 —
    /// required for `(idx + delta) & (group_count - 1)` to wrap the full range.
    #[inline]
    pub(crate) fn round_up_to_pow2_groups(slots: usize) -> usize {
        if slots == 0 {
            return 0;
        }
        let groups = slots.div_ceil(GROUP_SIZE).max(1).next_power_of_two();
        groups * GROUP_SIZE
    }
}

/// Probe-limit and hash-to-index helpers shared across maps.
pub(crate) mod probe {
    #[cfg(not(feature = "std"))]
    use crate::common::float::FloatExt as _;

    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss
    )]
    #[inline]
    #[must_use]
    pub(crate) fn log_log_probe_limit(capacity: usize) -> usize {
        let n = capacity.max(4) as f64;
        n.log2().max(2.0).log2().ceil().max(1.0) as usize
    }

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    #[must_use]
    pub(crate) fn hash_to_usize(hash: u64) -> usize {
        hash as usize
    }

    /// Triangular probe over a pow2-sized group count. Visits every group
    /// exactly once (same scheme as hashbrown / `SwissTable`).
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct TriangularProbe {
        pub(crate) pos: usize,
        delta: usize,
    }

    impl TriangularProbe {
        #[inline]
        pub(crate) fn new(start: usize) -> Self {
            Self {
                pos: start,
                delta: 0,
            }
        }

        #[inline]
        pub(crate) fn advance(&mut self, mask: usize) {
            self.delta += 1;
            self.pos = (self.pos + self.delta) & mask;
        }
    }
}

/// Knuth multiplicative-hash constant (golden ratio * 2^64, odd).
const GOLDEN_RATIO_U64: u64 = 0x9E37_79B9_7F4A_7C15;
/// Low 32 bits of [`GOLDEN_RATIO_U64`].
const GOLDEN_RATIO_U32: u32 = 0x7F4A_7C15;

/// Per-level hash salt: mixes the level index into the hash to decorrelate
/// bucket distributions across levels.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn level_salt(level_idx: usize) -> u32 {
    // Level counts are tiny in practice; wrapping keeps the helper total for
    // theoretical oversized descriptors.
    GOLDEN_RATIO_U32.wrapping_mul((level_idx as u32).wrapping_add(1))
}

/// Wide per-level salt for code paths whose layout/codegen depends on `u64`.
#[inline]
pub(crate) fn level_salt_wide(level_idx: usize) -> u64 {
    // usize fits in u64 on every Rust target (max 64-bit pointer width).
    GOLDEN_RATIO_U64.wrapping_mul((level_idx as u64).wrapping_add(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Only exact binary fractions (0.25, 0.5) are used so `floor`/`div` land
    // deterministically across platforms.
    #[test]
    fn max_insertions_reserves_floor_fraction() {
        assert_eq!(capacity::max_insertions(0, 0.25), 0);
        assert_eq!(capacity::max_insertions(16, 0.25), 12); // 16 - floor(4)
        assert_eq!(capacity::max_insertions(100, 0.5), 50);
        // Full reserve saturates at zero rather than underflowing.
        assert_eq!(capacity::max_insertions(10, 1.0), 0);
    }

    #[test]
    fn capacity_for_finds_smallest_doubling_fit() {
        // 16 already reserves headroom for 12 at rf=0.25.
        assert_eq!(capacity::capacity_for(16, 12, 0.25), Some(16));
        // 13 forces the next doubling: 32 reserves headroom for 24.
        assert_eq!(capacity::capacity_for(16, 13, 0.25), Some(32));
        assert_eq!(capacity::capacity_for(16, 0, 0.25), Some(16));
    }

    #[test]
    fn capacity_for_returns_none_on_overflow() {
        // No representable capacity reserves headroom for usize::MAX.
        assert_eq!(capacity::capacity_for(1, usize::MAX, 0.5), None);
    }

    #[test]
    // `sanitize` returns its inputs verbatim (clamp bounds / the default const),
    // so these are exact bit-for-bit comparisons, not approximate float math.
    #[allow(clippy::float_cmp)]
    fn sanitize_reserve_fraction_clamps_and_defaults() {
        assert_eq!(capacity::sanitize_reserve_fraction(0.5), 0.5);
        assert_eq!(
            capacity::sanitize_reserve_fraction(-1.0),
            MIN_RESERVE_FRACTION
        );
        assert_eq!(
            capacity::sanitize_reserve_fraction(2.0),
            MAX_RESERVE_FRACTION
        );
        assert_eq!(
            capacity::sanitize_reserve_fraction(f64::NAN),
            DEFAULT_RESERVE_FRACTION
        );
        assert_eq!(
            capacity::sanitize_reserve_fraction(f64::INFINITY),
            DEFAULT_RESERVE_FRACTION
        );
    }

    #[test]
    fn ceil_three_quarters_rounds_up() {
        assert_eq!(capacity::ceil_three_quarters(0), 0);
        assert_eq!(capacity::ceil_three_quarters(1), 1); // ceil(0.75)
        assert_eq!(capacity::ceil_three_quarters(2), 2); // ceil(1.5)
        assert_eq!(capacity::ceil_three_quarters(4), 3); // ceil(3.0)
        assert_eq!(capacity::ceil_three_quarters(5), 4); // ceil(3.75)
    }

    #[test]
    fn floor_half_reserve_slots_floors() {
        assert_eq!(capacity::floor_half_reserve_slots(0.25, 16), 2); // floor(4/2)
        assert_eq!(capacity::floor_half_reserve_slots(0.5, 10), 2); // floor(5/2)
    }

    #[test]
    fn tombstone_cleanup_threshold_stays_between_half_and_three_quarters() {
        for &cap in &[0usize, GROUP_SIZE, 128, 1024, 1_000_000] {
            let t = capacity::tombstone_cleanup_threshold(cap);
            assert!(t >= cap / 2, "threshold {t} below half of {cap}");
            assert!(
                t <= cap * 3 / 4 || cap == 0,
                "threshold {t} above 3/4 of {cap}"
            );
        }
        // At large capacity the hysteresis band (half + 4 groups) binds.
        let cap = 1_000_000;
        let expected = (cap / 2 + 4 * GROUP_SIZE).min(cap * 3 / 4).max(cap / 2);
        assert_eq!(capacity::tombstone_cleanup_threshold(cap), expected);
    }

    #[test]
    fn round_up_to_group_snaps_to_group_multiple() {
        assert_eq!(align::round_up_to_group(0), 0);
        assert_eq!(align::round_up_to_group(1), GROUP_SIZE);
        assert_eq!(align::round_up_to_group(GROUP_SIZE), GROUP_SIZE);
        assert_eq!(align::round_up_to_group(GROUP_SIZE + 1), 2 * GROUP_SIZE);
    }

    #[test]
    fn round_up_to_pow2_groups_yields_pow2_group_count() {
        assert_eq!(align::round_up_to_pow2_groups(0), 0);
        for slots in [
            1,
            GROUP_SIZE,
            GROUP_SIZE * 3,
            GROUP_SIZE * 5,
            GROUP_SIZE * 9,
        ] {
            let rounded = align::round_up_to_pow2_groups(slots);
            assert!(rounded >= slots);
            let groups = rounded / GROUP_SIZE;
            assert!(groups.is_power_of_two(), "group count {groups} not pow2");
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Miri's per-call `log2` jitter flakes the exact/monotone checks.
    fn log_log_probe_limit_at_least_one_and_monotone() {
        assert_eq!(probe::log_log_probe_limit(0), 1);
        assert_eq!(probe::log_log_probe_limit(4), 1);
        let mut prev = 0;
        for shift in 0..40 {
            let l = probe::log_log_probe_limit(1usize << shift);
            assert!(l >= 1);
            assert!(l >= prev, "not monotone at 2^{shift}");
            prev = l;
        }
    }

    #[test]
    fn triangular_probe_visits_every_group_once() {
        let group_count = 8usize;
        let mask = group_count - 1;
        for start in 0..group_count {
            let mut p = probe::TriangularProbe::new(start);
            let mut seen = vec![p.pos];
            for _ in 1..group_count {
                p.advance(mask);
                seen.push(p.pos);
            }
            seen.sort_unstable();
            assert_eq!(
                seen,
                (0..group_count).collect::<Vec<_>>(),
                "start {start} is not a full permutation"
            );
        }
    }

    #[test]
    fn level_salt_is_deterministic_and_decorrelated() {
        assert_eq!(level_salt(3), level_salt(3));
        assert_ne!(level_salt(0), level_salt(1));
        assert_eq!(level_salt_wide(3), level_salt_wide(3));
        assert_ne!(level_salt_wide(0), level_salt_wide(1));
    }
}
