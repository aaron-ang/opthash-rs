//! Capacity and reserve-fraction arithmetic shared by both maps.

use crate::ReserveFraction;
use crate::raw::config::GROUP_SIZE;

#[inline]
pub(crate) const fn max_insertions(capacity: usize, reserve: ReserveFraction) -> usize {
    capacity.saturating_sub(reserve.floor_reserved(capacity))
}

#[inline]
pub(crate) fn capacity_for(start: usize, needed: usize, reserve: ReserveFraction) -> Option<usize> {
    let mut cap = start;
    while max_insertions(cap, reserve) < needed {
        cap = cap.checked_mul(2)?;
    }
    Some(cap)
}

/// Smallest slot count whose insertion budget holds `needed` entries:
/// inverts `n - floor(n / 2^d) >= needed` exactly, where the closed form
/// `ceil(needed * 2^d / (2^d - 1))` overshoots at many floor boundaries.
/// `None` on overflow.
#[inline]
pub(crate) fn exact_capacity_for(needed: usize, reserve: ReserveFraction) -> Option<usize> {
    if needed == 0 {
        return Some(0);
    }
    let exponent = reserve.exponent();
    if exponent >= usize::BITS {
        return Some(needed);
    }
    needed.checked_add((needed - 1) / ((1_usize << exponent) - 1))
}

#[inline]
pub(crate) fn tombstone_cleanup_threshold(capacity: usize) -> usize {
    let half = capacity / 2;
    let cap_three_quarters = capacity.saturating_mul(3) / 4;
    let hysteresis = half.saturating_add(GROUP_SIZE.saturating_mul(4));
    hysteresis.min(cap_three_quarters).max(half)
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn reserve(reserve_exponent: u32) -> crate::ReserveFraction {
        match crate::ReserveFraction::from_exponent(reserve_exponent) {
            Ok(reserve) => reserve,
            Err(_) => panic!("test exponent must be positive"),
        }
    }

    #[test]
    fn max_insertions_reserves_floor_fraction() {
        assert_eq!(max_insertions(0, reserve(2)), 0);
        assert_eq!(max_insertions(16, reserve(2)), 12);
        assert_eq!(max_insertions(100, reserve(1)), 50);
    }

    #[test]
    fn capacity_for_finds_smallest_doubling_fit() {
        assert_eq!(capacity_for(16, 12, reserve(2)), Some(16));
        assert_eq!(capacity_for(16, 13, reserve(2)), Some(32));
        assert_eq!(capacity_for(16, 0, reserve(2)), Some(16));
    }

    #[test]
    fn capacity_for_returns_none_on_overflow() {
        assert_eq!(capacity_for(1, usize::MAX, reserve(1)), None);
    }

    #[test]
    fn exact_capacity_for_is_the_smallest_fit() {
        for exponent in [1, 2, 3, 5, 8, 64, 70] {
            let reserve = reserve(exponent);
            for needed in 1..3_000 {
                let slots = exact_capacity_for(needed, reserve).unwrap();
                assert!(
                    max_insertions(slots, reserve) >= needed,
                    "d={exponent} {needed}"
                );
                assert!(
                    max_insertions(slots - 1, reserve) < needed,
                    "d={exponent} {needed}"
                );
            }
        }
        assert_eq!(exact_capacity_for(0, reserve(3)), Some(0));
        assert_eq!(exact_capacity_for(usize::MAX, reserve(1)), None);
    }

    #[test]
    fn tombstone_cleanup_threshold_stays_between_half_and_three_quarters() {
        for &cap in &[0usize, GROUP_SIZE, 128, 1024, 1_000_000] {
            let threshold = tombstone_cleanup_threshold(cap);
            assert!(threshold >= cap / 2);
            assert!(threshold <= cap * 3 / 4 || cap == 0);
        }
    }
}
