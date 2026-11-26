use super::config::GROUP_SIZE;
use super::simd;

pub(crate) type BitMaskWord = u64;

/// Bits per slot in [`BitMask`]: 8 for NEON/SWAR-8, 1 elsewhere.
#[cfg(any(opthash_neon_group, opthash_scalar_group))]
pub(crate) const BITMASK_STRIDE: u32 = 8;
#[cfg(opthash_x86_16_group)]
pub(crate) const BITMASK_STRIDE: u32 = 1;

/// A bit of each slot's stride that every group mask sets for a matching
/// slot: the lowest where a match fills the stride, so the bit index of a
/// match is a multiple of the stride.
#[cfg(opthash_scalar_group)]
pub(crate) const BITMASK_SLOT_BIT: u32 = BITMASK_STRIDE - 1;
#[cfg(not(opthash_scalar_group))]
pub(crate) const BITMASK_SLOT_BIT: u32 = 0;

/// Zero bits above the last lane of a group mask.
#[allow(clippy::cast_possible_truncation)]
const BITMASK_UNUSED_BITS: u32 = u64::BITS - GROUP_SIZE as u32 * BITMASK_STRIDE;

/// The lane a lead walk measures from: the group's last when the backend
/// leads with the highest match, its first when it leads with the lowest.
pub(crate) const LEAD_ORIGIN: usize = if simd::LEADS_FROM_LAST_LANE {
    GROUP_SIZE - 1
} else {
    0
};

/// Per-slot match mask over a control group.
#[derive(Debug, Clone)]
pub(crate) struct BitMask(pub(crate) BitMaskWord);

impl BitMask {
    /// How far the lead match lies from [`LEAD_ORIGIN`], in mask bits. The
    /// lead is the match at the end of the mask the group backend locates
    /// cheapest; a walk that only needs some match, not the lowest, takes it.
    ///
    /// # Safety
    ///
    /// The mask is a non-empty group mask, or what [`Self::without_lead`]
    /// leaves of one: each set lane fills its stride from the slot bit.
    #[inline]
    // The stride is one where a group mask holds one bit per slot.
    #[allow(clippy::modulo_one)]
    unsafe fn lead_distance(&self) -> u32 {
        debug_assert_ne!(self.0, 0);
        let distance = if simd::LEADS_FROM_LAST_LANE {
            self.0.leading_zeros() - BITMASK_UNUSED_BITS
        } else {
            self.0.trailing_zeros() - BITMASK_SLOT_BIT
        };
        debug_assert!(distance.is_multiple_of(BITMASK_STRIDE));
        // SAFETY: the caller's contract. Stating it lets the division by the
        // stride fold into the scaling of whatever the lane indexes.
        unsafe { core::hint::assert_unchecked(distance.is_multiple_of(BITMASK_STRIDE)) };
        distance
    }

    /// The byte offset from the element of lane [`LEAD_ORIGIN`] to the lead
    /// match's, in an array of `size`-byte elements, one per lane.
    ///
    /// # Safety
    ///
    /// As for [`Self::lead_distance`].
    #[inline]
    #[must_use]
    pub(crate) unsafe fn lead_offset(&self, size: usize) -> isize {
        // SAFETY: the caller's contract.
        let distance = unsafe { self.lead_distance() } as usize;
        let offset = (distance * size / BITMASK_STRIDE as usize).cast_signed();
        if simd::LEADS_FROM_LAST_LANE {
            -offset
        } else {
            offset
        }
    }

    /// The mask without its lead lane.
    ///
    /// # Safety
    ///
    /// As for [`Self::lead_distance`].
    #[inline]
    #[must_use]
    pub(crate) unsafe fn without_lead(&self) -> Self {
        // SAFETY: the caller's contract.
        let distance = unsafe { self.lead_distance() };
        // The lane is cleared at the end of the word it leads from, where its
        // mask is one constant for every lane.
        Self(if simd::LEADS_FROM_LAST_LANE {
            let above = distance + BITMASK_UNUSED_BITS;
            ((self.0 << above) & (u64::MAX >> BITMASK_STRIDE)) >> above
        } else {
            ((self.0 >> distance) & (u64::MAX << BITMASK_STRIDE)) << distance
        })
    }
}

impl Iterator for BitMask {
    type Item = usize;

    #[inline]
    /// Yields the index of the lowest set slot, then clears it, until empty.
    fn next(&mut self) -> Option<usize> {
        if self.0 == 0 {
            return None;
        }
        let bit = self.0.trailing_zeros();
        let slot = (bit / BITMASK_STRIDE) as usize;
        // NEON stores each set slot as a full byte.
        #[cfg(opthash_neon_group)]
        {
            let byte = (0xFFu64).wrapping_shl(bit);
            self.0 &= !byte;
        }
        #[cfg(not(opthash_neon_group))]
        {
            self.0 &= self.0.wrapping_sub(1);
        }
        Some(slot)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use super::*;
    use crate::raw::control::CTRL_EMPTY;

    /// For every set of matching lanes, the lead walk visits the lanes the
    /// mask's own iterator yields, from the backend's leading end, and each
    /// lead's offset is a whole number of lanes from [`LEAD_ORIGIN`].
    #[test]
    fn a_lead_walk_visits_the_matches_from_the_leading_end() {
        const FP: u8 = 0x80 | 7;
        // One bit of `chosen` per lane. Miri takes the sets of eight lanes,
        // and repeats each in the upper half of a wider group.
        let sets = if cfg!(miri) {
            1 << u8::BITS
        } else {
            1_u32 << GROUP_SIZE
        };
        for set in 0..sets {
            let chosen = if cfg!(miri) {
                set | set << u8::BITS
            } else {
                set
            };
            let controls: [u8; GROUP_SIZE] = core::array::from_fn(|lane| {
                if chosen >> lane & 1 == 1 {
                    FP
                } else {
                    CTRL_EMPTY
                }
            });
            // SAFETY: `controls` is one whole group.
            let mask = unsafe { simd::eq_mask_group(controls.as_ptr(), FP) };
            let mut expected: Vec<usize> = mask.clone().collect();
            if simd::LEADS_FROM_LAST_LANE {
                expected.reverse();
            }
            let mut walked = Vec::new();
            let mut matches = mask;
            while matches.0 != 0 {
                // SAFETY: `matches` is a group mask less lead lanes, and not
                // empty.
                let (lane, entry, rest) = unsafe {
                    (
                        matches.lead_offset(1),
                        matches.lead_offset(24),
                        matches.without_lead(),
                    )
                };
                assert_eq!(entry, lane * 24, "{controls:02x?}");
                walked.push(LEAD_ORIGIN.wrapping_add_signed(lane));
                assert!(rest.0 < matches.0, "{controls:02x?}");
                matches = rest;
            }
            assert_eq!(walked, expected, "{controls:02x?}");
        }
    }
}
