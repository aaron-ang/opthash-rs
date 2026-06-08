use super::config::{
    DEFAULT_RESERVE_FRACTION, GROUP_SIZE, MAX_RESERVE_FRACTION, MIN_RESERVE_FRACTION,
};

/// `f64 ↔ usize` casts with the truncation/sign lints we accept here.
pub(crate) mod cast {
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
