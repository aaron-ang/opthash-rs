//! Control-group scans. Exactly one backend module is compiled, selected by the
//! `opthash_*_group` cfg that `build.rs` derives from the target architecture;
//! the ladder at the bottom re-exports its three mask functions.
//!
//! Every mask function is `unsafe`: `ptr` must be valid to read `GROUP_SIZE`
//! control bytes.

use super::bitmask::BitMask;

/// Eight-lane NEON scan; each lane's match fills its byte of the `u64` mask.
#[cfg(opthash_neon_group)]
mod neon {
    use core::arch::aarch64;

    use super::BitMask;
    use crate::raw::control::OCCUPIED_BIT;

    /// Collapses an 8-lane compare into its `BitMask` bit pattern.
    #[inline]
    #[must_use]
    unsafe fn lane_mask(cmp: aarch64::uint8x8_t) -> BitMask {
        // SAFETY: NEON is baseline on aarch64; lane 0 of a 1-lane vector exists.
        BitMask(unsafe { aarch64::vget_lane_u64(aarch64::vreinterpret_u64_u8(cmp), 0) })
    }

    #[inline]
    #[must_use]
    pub(crate) unsafe fn eq_mask_group(ptr: *const u8, target: u8) -> BitMask {
        // SAFETY: caller guarantees `GROUP_SIZE` (8) readable bytes at `ptr`.
        unsafe {
            let bytes = aarch64::vld1_u8(ptr);
            lane_mask(aarch64::vceq_u8(bytes, aarch64::vdup_n_u8(target)))
        }
    }

    #[inline]
    #[must_use]
    pub(crate) unsafe fn free_mask_group(ptr: *const u8) -> BitMask {
        // SAFETY: caller guarantees `GROUP_SIZE` (8) readable bytes at `ptr`.
        unsafe {
            let bytes = aarch64::vld1_u8(ptr);
            // `OCCUPIED_BIT` is the sign bit of each lane.
            lane_mask(aarch64::vcgez_s8(aarch64::vreinterpret_s8_u8(bytes)))
        }
    }

    /// The slot bits of `lanes` whose control is free. Read as one word, so
    /// a caller that only tests and locates the lowest free lane keeps the
    /// group out of the vector registers.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn free_lanes_group(ptr: *const u8, lanes: u64) -> BitMask {
        // SAFETY: caller guarantees `GROUP_SIZE` (8) readable bytes at `ptr`;
        // a byte array has no alignment to meet.
        let word = u64::from_le_bytes(unsafe { ptr.cast::<[u8; 8]>().read() });
        // `OCCUPIED_BIT` is the top bit of each lane; the shift brings it to
        // the lane's slot bit.
        BitMask(lanes & !(word >> OCCUPIED_BIT.trailing_zeros()))
    }

    /// Bitmask of occupied slots; padding and tombstones are excluded.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn occupied_mask_group(ptr: *const u8) -> BitMask {
        // SAFETY: caller guarantees `GROUP_SIZE` (8) readable bytes at `ptr`.
        unsafe {
            let bytes = aarch64::vld1_u8(ptr);
            lane_mask(aarch64::vcltz_s8(aarch64::vreinterpret_s8_u8(bytes)))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::raw::control::{CTRL_EMPTY, CTRL_TOMBSTONE};

        /// One slot bit per lane of a group.
        const ALL_LANES: u64 = 0x0101_0101_0101_0101;

        #[test]
        fn free_lanes_are_the_free_mask_cut_to_the_asked_lanes() {
            // Every pair of control bytes, in every pair of adjacent lanes,
            // so a lane's answer is seen not to leak into its neighbour.
            for low in 0..=u8::MAX {
                for high in [CTRL_EMPTY, CTRL_TOMBSTONE, 0x7f, OCCUPIED_BIT, u8::MAX] {
                    for lane in 0..7 {
                        let mut controls = [OCCUPIED_BIT | 0x2a; 8];
                        controls[lane] = low;
                        controls[lane + 1] = high;
                        // SAFETY: `controls` holds exactly one 8-byte group.
                        let free = unsafe { free_mask_group(controls.as_ptr()) }.0;
                        for lanes in [ALL_LANES, ALL_LANES >> 16, 1 << (8 * lane), 0] {
                            // SAFETY: as above.
                            let cut = unsafe { free_lanes_group(controls.as_ptr(), lanes) }.0;
                            assert_eq!(cut, free & lanes, "{controls:02x?} lanes={lanes:#x}");
                        }
                    }
                }
            }
        }

        #[test]
        fn eight_lane_masks_preserve_control_order() {
            let controls = [
                CTRL_EMPTY,
                CTRL_TOMBSTONE,
                OCCUPIED_BIT,
                OCCUPIED_BIT | 7,
                CTRL_EMPTY,
                OCCUPIED_BIT | 7,
                CTRL_TOMBSTONE,
                u8::MAX,
            ];

            // SAFETY: `controls` holds exactly one 8-byte group.
            let matches: alloc::vec::Vec<_> =
                unsafe { eq_mask_group(controls.as_ptr(), OCCUPIED_BIT | 7) }.collect();
            // SAFETY: as above.
            let free: alloc::vec::Vec<_> = unsafe { free_mask_group(controls.as_ptr()) }.collect();
            // SAFETY: as above.
            let occupied: alloc::vec::Vec<_> =
                unsafe { occupied_mask_group(controls.as_ptr()) }.collect();

            assert_eq!(matches, [3, 5]);
            assert_eq!(free, [0, 1, 4, 6]);
            assert_eq!(occupied, [2, 3, 5, 7]);
        }
    }
}

/// Sixteen-lane SSE2 scan; `movemask` packs one bit per lane.
#[cfg(opthash_x86_16_group)]
mod sse2 {
    // x86 unaligned loads require alignment casts that clippy cannot prove safe.
    #![allow(clippy::cast_ptr_alignment)]

    use core::arch::x86_64::{self, __m128i};

    use super::BitMask;

    /// One bit per lane, set where the control byte carries `OCCUPIED_BIT`
    /// (the sign bit `movemask` extracts).
    #[inline]
    #[must_use]
    unsafe fn occupied_bits(ptr: *const u8) -> u32 {
        // SAFETY: SSE2 is baseline on x86_64; caller guarantees 16 readable
        // bytes and `loadu` has no alignment requirement.
        unsafe {
            let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
            x86_64::_mm_movemask_epi8(data).cast_unsigned() & 0xFFFF
        }
    }

    /// Collapses a 16-lane compare into its `BitMask` bit pattern.
    #[inline]
    #[must_use]
    unsafe fn lane_mask(cmp: __m128i) -> BitMask {
        // SAFETY: SSE2 is baseline on x86_64.
        let bits = unsafe { x86_64::_mm_movemask_epi8(cmp) }.cast_unsigned() & 0xFFFF;
        BitMask(u64::from(bits))
    }

    #[inline]
    #[must_use]
    pub(crate) unsafe fn eq_mask_group(ptr: *const u8, target: u8) -> BitMask {
        // SAFETY: SSE2 is baseline on x86_64; caller guarantees 16 readable
        // bytes and `loadu` has no alignment requirement.
        unsafe {
            let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
            let target_vec = x86_64::_mm_set1_epi8(target.cast_signed());
            lane_mask(x86_64::_mm_cmpeq_epi8(data, target_vec))
        }
    }

    #[inline]
    #[must_use]
    pub(crate) unsafe fn free_mask_group(ptr: *const u8) -> BitMask {
        // SAFETY: caller guarantees 16 readable bytes.
        BitMask(u64::from(unsafe { occupied_bits(ptr) } ^ 0xFFFF))
    }

    /// The slot bits of `lanes` whose control is free.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn free_lanes_group(ptr: *const u8, lanes: u64) -> BitMask {
        // SAFETY: caller guarantees 16 readable bytes.
        BitMask(unsafe { free_mask_group(ptr) }.0 & lanes)
    }

    /// Bitmask of occupied slots; padding and tombstones are excluded.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn occupied_mask_group(ptr: *const u8) -> BitMask {
        // SAFETY: caller guarantees 16 readable bytes.
        BitMask(u64::from(unsafe { occupied_bits(ptr) }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::raw::control::{CTRL_EMPTY, CTRL_TOMBSTONE, OCCUPIED_BIT};

        /// One slot bit per lane of a group.
        const ALL_LANES: u64 = 0xFFFF;

        #[test]
        fn free_lanes_are_the_free_lanes_among_the_asked_ones() {
            for low in (0..=u8::MAX).step_by(if cfg!(miri) { 15 } else { 1 }) {
                for high in [CTRL_EMPTY, CTRL_TOMBSTONE, 0x7f, OCCUPIED_BIT, u8::MAX] {
                    for lane in 0..15 {
                        let mut controls = [OCCUPIED_BIT | 0x2a; 16];
                        controls[lane] = low;
                        controls[lane + 1] = high;
                        let free = controls
                            .iter()
                            .enumerate()
                            .filter(|(_, control)| *control & OCCUPIED_BIT == 0)
                            .fold(0_u64, |free, (lane, _)| free | 1 << lane);
                        for lanes in [ALL_LANES, ALL_LANES >> 6, 1 << lane, 0] {
                            // SAFETY: `controls` holds exactly one 16-byte
                            // group.
                            let cut = unsafe { free_lanes_group(controls.as_ptr(), lanes) }.0;
                            assert_eq!(cut, free & lanes, "{controls:02x?} lanes={lanes:#x}");
                        }
                    }
                }
            }
        }
    }
}

/// Portable SWAR-8 fallback control scan: 8 control bytes packed into one
/// `u64`, matched with exact borrow-free masks. Lane `i`'s match is flagged by
/// its high bit at bit `8*i + 7` (`BITMASK_STRIDE` 8).
#[cfg(opthash_scalar_group)]
mod swar {
    use super::BitMask;

    const LO7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
    const HI: u64 = 0x8080_8080_8080_8080;
    const ONES: u64 = 0x0101_0101_0101_0101;

    /// Load eight control bytes as one little-endian word (lane `i` = bits `[8*i, 8*i+7]`).
    ///
    /// # Safety
    ///
    /// `ptr` must be valid to read 8 bytes.
    #[inline]
    unsafe fn word(ptr: *const u8) -> u64 {
        #[allow(clippy::cast_ptr_alignment)]
        // SAFETY: caller guarantees 8 readable bytes; the read is unaligned.
        let raw = unsafe { ptr.cast::<u64>().read_unaligned() };
        raw.to_le()
    }

    /// 0x80 in each lane equal to `target`. Exact: matching `CTRL_EMPTY` never
    /// flags a tombstone or an occupied byte.
    #[inline]
    fn eq_mask(word: u64, target: u8) -> u64 {
        let cmp = word ^ (u64::from(target).wrapping_mul(ONES));
        let ne = (((cmp & LO7).wrapping_add(LO7)) | cmp) & HI; // 0x80 where != target
        ne ^ HI
    }

    /// 0x80 in each occupied lane (`OCCUPIED_BIT` set).
    #[inline]
    fn occupied_mask(word: u64) -> u64 {
        word & HI
    }

    /// 0x80 in each EMPTY|TOMBSTONE lane.
    #[inline]
    fn free_mask(word: u64) -> u64 {
        occupied_mask(word) ^ HI
    }

    #[inline]
    #[must_use]
    pub(crate) unsafe fn eq_mask_group(ptr: *const u8, target: u8) -> BitMask {
        // SAFETY: caller guarantees `GROUP_SIZE` (8) readable bytes at `ptr`.
        BitMask(eq_mask(unsafe { word(ptr) }, target))
    }

    #[inline]
    #[must_use]
    pub(crate) unsafe fn free_mask_group(ptr: *const u8) -> BitMask {
        // SAFETY: caller guarantees `GROUP_SIZE` (8) readable bytes at `ptr`.
        BitMask(free_mask(unsafe { word(ptr) }))
    }

    /// The slot bits of `lanes` whose control is free.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn free_lanes_group(ptr: *const u8, lanes: u64) -> BitMask {
        // SAFETY: caller guarantees `GROUP_SIZE` (8) readable bytes at `ptr`.
        BitMask(free_mask(unsafe { word(ptr) }) & lanes)
    }

    /// Bitmask of occupied slots; padding and tombstones are excluded.
    #[inline]
    #[must_use]
    pub(crate) unsafe fn occupied_mask_group(ptr: *const u8) -> BitMask {
        // SAFETY: caller guarantees `GROUP_SIZE` (8) readable bytes at `ptr`.
        BitMask(occupied_mask(unsafe { word(ptr) }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::raw::control::{CTRL_EMPTY, CTRL_TOMBSTONE, OCCUPIED_BIT};

        fn word(bytes: [u8; 8]) -> u64 {
            u64::from_le_bytes(bytes)
        }
        // Naive per-byte references in the SWAR encoding: 0x80 in lane `i` (bit
        // `8*i + 7`) when the predicate holds for byte `i`.
        fn ref_eq(bytes: [u8; 8], target: u8) -> u64 {
            let mut m = 0u64;
            for (i, &b) in bytes.iter().enumerate() {
                if b == target {
                    m |= 0x80u64 << (8 * i);
                }
            }
            m
        }
        fn ref_occupied(bytes: [u8; 8]) -> u64 {
            let mut m = 0u64;
            for (i, &b) in bytes.iter().enumerate() {
                if b & OCCUPIED_BIT != 0 {
                    m |= 0x80u64 << (8 * i);
                }
            }
            m
        }

        // Representative and adversarial words: cross-byte borrow adjacencies
        // (0x00/0x01/0x80) and the full 0..=255 range, not just real control bytes.
        fn sample_words() -> [[u8; 8]; 10] {
            [
                [CTRL_EMPTY; 8],
                [CTRL_TOMBSTONE; 8],
                [0x2a; 8],
                [1, 2, 3, 4, 5, 6, 7, 8],
                [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
                [0x80, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                [0x7f, 0x80, 0x00, 0x01, 0x7f, 0x80, 0x00, 0x01],
                [0xff, 0xfe, 0xfd, 0xfc, 0x80, 0x7f, 0x01, 0x00],
                [0x00, 0x80, 0x00, 0x80, 0x00, 0x80, 0x00, 0x80],
            ]
        }

        #[test]
        fn eq_matches_reference_for_every_target() {
            for bytes in sample_words() {
                for target in 0..=u8::MAX {
                    assert_eq!(
                        eq_mask(word(bytes), target),
                        ref_eq(bytes, target),
                        "word={bytes:02x?} target={target:#04x}"
                    );
                }
            }
        }

        #[test]
        fn eq_empty_flags_only_exact_zero() {
            // Matching CTRL_EMPTY must never false-positive against a tombstone or
            // occupied byte: that would terminate a present key's probe early.
            for bytes in sample_words() {
                assert_eq!(eq_mask(word(bytes), CTRL_EMPTY), ref_eq(bytes, CTRL_EMPTY));
            }
            assert_eq!(eq_mask(word([CTRL_TOMBSTONE; 8]), CTRL_EMPTY), 0);
            assert_eq!(eq_mask(word([0x2a; 8]), CTRL_EMPTY), 0);
        }

        #[test]
        fn free_and_occupied_partition_all_lanes() {
            for bytes in sample_words() {
                let f = free_mask(word(bytes));
                let o = occupied_mask(word(bytes));
                assert_eq!(o, ref_occupied(bytes), "occupied mismatch: {bytes:02x?}");
                assert_eq!(f & o, 0, "free/occupied overlap: {bytes:02x?}");
                assert_eq!(f | o, HI, "free|occupied != all lanes: {bytes:02x?}");
            }
        }

        #[test]
        fn free_is_empty_or_tombstone() {
            assert_eq!(free_mask(word([CTRL_EMPTY; 8])), HI);
            assert_eq!(free_mask(word([CTRL_TOMBSTONE; 8])), HI);
            assert_eq!(occupied_mask(word([CTRL_EMPTY; 8])), 0);
            assert_eq!(occupied_mask(word([CTRL_TOMBSTONE; 8])), 0);
            for fp in OCCUPIED_BIT..=u8::MAX {
                assert_eq!(occupied_mask(word([fp; 8])), HI, "fp {fp:#04x}");
                assert_eq!(free_mask(word([fp; 8])), 0, "fp {fp:#04x}");
            }
        }

        #[test]
        fn free_lanes_are_the_free_lanes_among_the_asked_ones() {
            const ALL_LANES: u64 = HI;
            for bytes in sample_words() {
                let free = ref_occupied(bytes) ^ HI;
                for lanes in [ALL_LANES, ALL_LANES >> 16, 0x80 << 24, 0] {
                    // SAFETY: `bytes` holds exactly one 8-byte group.
                    let cut = unsafe { free_lanes_group(bytes.as_ptr(), lanes) }.0;
                    assert_eq!(cut, free & lanes, "{bytes:02x?} lanes={lanes:#x}");
                }
            }
        }

        #[test]
        fn no_cross_byte_borrow() {
            // A lone occupied byte among empties flags exactly its own lane.
            let bytes = [0x00, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            assert_eq!(occupied_mask(word(bytes)), 0x80u64 << 8);
            assert_eq!(eq_mask(word(bytes), 0x81), 0x80u64 << 8);
            // Ascending distinct bytes: eq to byte i flags only lane i.
            let asc = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
            for (i, &b) in asc.iter().enumerate() {
                assert_eq!(eq_mask(word(asc), b), 0x80u64 << (8 * i), "byte {b:#04x}");
            }
        }

        #[test]
        fn match_lands_in_lane_high_bit() {
            assert_eq!(eq_mask(word([9; 8]), 9), HI);
            assert_eq!(
                eq_mask(word([0, 0, 0, 9, 0, 0, 0, 0]), 9),
                0x80u64 << (8 * 3)
            );
        }
    }
}

#[cfg(opthash_neon_group)]
use neon as backend;
#[cfg(opthash_x86_16_group)]
use sse2 as backend;
#[cfg(opthash_scalar_group)]
use swar as backend;

pub(crate) use backend::{eq_mask_group, free_lanes_group, free_mask_group, occupied_mask_group};
