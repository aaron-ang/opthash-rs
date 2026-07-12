#[cfg(target_arch = "aarch64")]
use core::arch::aarch64;
#[cfg(opthash_neon_group)]
use core::arch::aarch64::uint8x16_t;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64;
#[cfg(opthash_x86_16_group)]
use core::arch::x86_64::__m128i;
#[cfg(opthash_avx512_group)]
use core::arch::x86_64::__m512i;

use super::bitmask::BitMask;
#[cfg(opthash_scalar_group)]
use super::config::GROUP_SIZE;
#[cfg(any(opthash_neon_group, opthash_x86_16_group, opthash_avx512_group))]
use super::control::FINGERPRINT_MASK;

// Portable SWAR-8 control scan (hashbrown's "generic" backend): 8 control bytes
// packed into one u64, matched with exact borrow-free masks. Lane `i`'s match is
// flagged by its high bit at bit `8*i + 7` (BITMASK_STRIDE 8).
#[cfg(opthash_scalar_group)]
const SWAR_LO7: u64 = 0x7f7f_7f7f_7f7f_7f7f;
#[cfg(opthash_scalar_group)]
const SWAR_HI: u64 = 0x8080_8080_8080_8080;
#[cfg(opthash_scalar_group)]
const SWAR_ONES: u64 = 0x0101_0101_0101_0101;

/// Load eight control bytes as one little-endian word (lane `i` = bits `[8*i, 8*i+7]`).
///
/// # Safety
///
/// `ptr` must be valid to read 8 bytes.
#[cfg(opthash_scalar_group)]
#[inline]
unsafe fn swar_word(ptr: *const u8) -> u64 {
    #[allow(clippy::cast_ptr_alignment)]
    let raw = unsafe { ptr.cast::<u64>().read_unaligned() };
    raw.to_le()
}

/// 0x80 in each lane equal to `target`. Exact: matching `CTRL_EMPTY` (0x00) never
/// flags a tombstone (0x80) or an occupied byte.
#[cfg(opthash_scalar_group)]
#[inline]
fn swar_eq_mask(word: u64, target: u8) -> u64 {
    let cmp = word ^ (u64::from(target).wrapping_mul(SWAR_ONES));
    let ne = (((cmp & SWAR_LO7).wrapping_add(SWAR_LO7)) | cmp) & SWAR_HI; // 0x80 where != target
    ne ^ SWAR_HI
}

/// 0x80 in each occupied lane (fingerprint bits nonzero).
#[cfg(opthash_scalar_group)]
#[inline]
fn swar_occupied_mask(word: u64) -> u64 {
    ((word & SWAR_LO7).wrapping_add(SWAR_LO7)) & SWAR_HI
}

/// 0x80 in each EMPTY|TOMBSTONE lane.
#[cfg(opthash_scalar_group)]
#[inline]
fn swar_free_mask(word: u64) -> u64 {
    swar_occupied_mask(word) ^ SWAR_HI
}

/// # Safety
///
/// `ptr` must be valid to read `GROUP_SIZE` bytes.
#[inline]
#[must_use]
pub(crate) unsafe fn eq_mask_group(ptr: *const u8, target: u8) -> BitMask {
    #[cfg(opthash_neon_group)]
    let mask = unsafe { eq_mask_16_neon(ptr, target) };
    #[cfg(opthash_avx512_group)]
    let mask = unsafe { eq_mask_64_avx512(ptr, target) };
    #[cfg(opthash_x86_16_group)]
    let mask = unsafe { eq_mask_16_sse2(ptr, target) };
    #[cfg(opthash_scalar_group)]
    let mask = unsafe { BitMask(swar_eq_mask(swar_word(ptr), target)) };
    mask
}

/// # Safety
///
/// `ptr` must be valid to read `GROUP_SIZE` bytes.
#[inline]
#[must_use]
pub(crate) unsafe fn free_mask_group(ptr: *const u8) -> BitMask {
    #[cfg(opthash_neon_group)]
    let mask = unsafe { free_mask_16_neon(ptr) };
    #[cfg(opthash_avx512_group)]
    let mask = unsafe { free_mask_64_avx512(ptr) };
    #[cfg(opthash_x86_16_group)]
    let mask = unsafe { free_mask_16_sse2(ptr) };
    #[cfg(opthash_scalar_group)]
    let mask = unsafe { BitMask(swar_free_mask(swar_word(ptr))) };
    mask
}

/// Bitmask of occupied slots; padding and tombstones are excluded.
///
/// # Safety
///
/// `ptr` must be valid to read `GROUP_SIZE` bytes.
#[inline]
#[must_use]
pub(crate) unsafe fn occupied_mask_group(ptr: *const u8) -> BitMask {
    #[cfg(opthash_neon_group)]
    let mask = unsafe { occupied_mask_16_neon(ptr) };
    #[cfg(opthash_avx512_group)]
    let mask = unsafe { occupied_mask_64_avx512(ptr) };
    #[cfg(opthash_x86_16_group)]
    let mask = unsafe { occupied_mask_16_sse2(ptr) };
    #[cfg(opthash_scalar_group)]
    let mask = unsafe { BitMask(swar_occupied_mask(swar_word(ptr))) };
    mask
}

// Backend helpers. Numeric suffixes are the number of control bytes scanned.

#[cfg(opthash_neon_group)]
#[inline]
unsafe fn nibble_mask_from_cmp(cmp: uint8x16_t) -> BitMask {
    // NEON narrows compare bytes into one nibble per slot.
    unsafe {
        let narrowed = aarch64::vshrn_n_u16(aarch64::vreinterpretq_u16_u8(cmp), 4);
        BitMask(aarch64::vget_lane_u64(
            aarch64::vreinterpret_u64_u8(narrowed),
            0,
        ))
    }
}

#[cfg(opthash_neon_group)]
#[inline]
unsafe fn eq_mask_16_neon(ptr: *const u8, target: u8) -> BitMask {
    unsafe {
        let bytes = aarch64::vld1q_u8(ptr);
        let cmp = aarch64::vceqq_u8(bytes, aarch64::vdupq_n_u8(target));
        nibble_mask_from_cmp(cmp)
    }
}

#[cfg(opthash_neon_group)]
#[inline]
unsafe fn free_mask_16_neon(ptr: *const u8) -> BitMask {
    unsafe {
        let bytes = aarch64::vld1q_u8(ptr);
        let masked = aarch64::vandq_u8(bytes, aarch64::vdupq_n_u8(FINGERPRINT_MASK));
        let free_cmp = aarch64::vceqq_u8(masked, aarch64::vdupq_n_u8(0));
        nibble_mask_from_cmp(free_cmp)
    }
}

#[cfg(opthash_neon_group)]
#[inline]
unsafe fn occupied_mask_16_neon(ptr: *const u8) -> BitMask {
    unsafe {
        let bytes = aarch64::vld1q_u8(ptr);
        let occ_cmp = aarch64::vtstq_u8(bytes, aarch64::vdupq_n_u8(FINGERPRINT_MASK));
        nibble_mask_from_cmp(occ_cmp)
    }
}

// x86 unaligned loads require alignment casts that clippy cannot prove safe.
#[allow(clippy::cast_ptr_alignment)]
#[cfg(opthash_x86_16_group)]
#[inline]
unsafe fn eq_mask_16_sse2(ptr: *const u8, target: u8) -> BitMask {
    unsafe {
        let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
        let target_vec = x86_64::_mm_set1_epi8(target.cast_signed());
        let cmp = x86_64::_mm_cmpeq_epi8(data, target_vec);
        let bits = x86_64::_mm_movemask_epi8(cmp).cast_unsigned() & 0xFFFF;
        BitMask(u64::from(bits))
    }
}

#[allow(clippy::cast_ptr_alignment)]
#[cfg(opthash_avx512_group)]
#[inline]
unsafe fn eq_mask_64_avx512(ptr: *const u8, target: u8) -> BitMask {
    unsafe {
        let data = x86_64::_mm512_loadu_si512(ptr.cast::<__m512i>());
        let target_vec = x86_64::_mm512_set1_epi8(target.cast_signed());
        BitMask(x86_64::_mm512_cmpeq_epi8_mask(data, target_vec))
    }
}

#[allow(clippy::cast_ptr_alignment)]
#[cfg(opthash_avx512_group)]
#[inline]
unsafe fn free_mask_64_avx512(ptr: *const u8) -> BitMask {
    unsafe {
        let data = x86_64::_mm512_loadu_si512(ptr.cast::<__m512i>());
        let fingerprint_bits = x86_64::_mm512_set1_epi8(FINGERPRINT_MASK.cast_signed());
        BitMask(x86_64::_mm512_testn_epi8_mask(data, fingerprint_bits))
    }
}

#[allow(clippy::cast_ptr_alignment)]
#[cfg(opthash_avx512_group)]
#[inline]
unsafe fn occupied_mask_64_avx512(ptr: *const u8) -> BitMask {
    unsafe {
        let data = x86_64::_mm512_loadu_si512(ptr.cast::<__m512i>());
        let fingerprint_bits = x86_64::_mm512_set1_epi8(FINGERPRINT_MASK.cast_signed());
        BitMask(x86_64::_mm512_test_epi8_mask(data, fingerprint_bits))
    }
}

#[allow(clippy::cast_ptr_alignment)]
#[cfg(opthash_x86_16_group)]
#[inline]
unsafe fn free_mask_16_sse2(ptr: *const u8) -> BitMask {
    unsafe {
        let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
        let masked =
            x86_64::_mm_and_si128(data, x86_64::_mm_set1_epi8(FINGERPRINT_MASK.cast_signed()));
        let free = x86_64::_mm_cmpeq_epi8(masked, x86_64::_mm_setzero_si128());
        let bits = x86_64::_mm_movemask_epi8(free).cast_unsigned() & 0xFFFF;
        BitMask(u64::from(bits))
    }
}

#[allow(clippy::cast_ptr_alignment)]
#[cfg(opthash_x86_16_group)]
#[inline]
unsafe fn occupied_mask_16_sse2(ptr: *const u8) -> BitMask {
    unsafe {
        let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
        let masked =
            x86_64::_mm_and_si128(data, x86_64::_mm_set1_epi8(FINGERPRINT_MASK.cast_signed()));
        let occ = x86_64::_mm_cmpgt_epi8(masked, x86_64::_mm_setzero_si128());
        let bits = x86_64::_mm_movemask_epi8(occ).cast_unsigned() & 0xFFFF;
        BitMask(u64::from(bits))
    }
}

#[cfg(all(test, opthash_scalar_group))]
mod swar_tests {
    use super::*;
    use crate::common::control::{CTRL_EMPTY, CTRL_TOMBSTONE, FINGERPRINT_MASK};

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
            if b & FINGERPRINT_MASK != 0 {
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
                    swar_eq_mask(word(bytes), target),
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
            assert_eq!(
                swar_eq_mask(word(bytes), CTRL_EMPTY),
                ref_eq(bytes, CTRL_EMPTY)
            );
        }
        assert_eq!(swar_eq_mask(word([CTRL_TOMBSTONE; 8]), CTRL_EMPTY), 0);
        assert_eq!(swar_eq_mask(word([0x2a; 8]), CTRL_EMPTY), 0);
    }

    #[test]
    fn free_and_occupied_partition_all_lanes() {
        for bytes in sample_words() {
            let f = swar_free_mask(word(bytes));
            let o = swar_occupied_mask(word(bytes));
            assert_eq!(o, ref_occupied(bytes), "occupied mismatch: {bytes:02x?}");
            // free and occupied are exact complements over the 8 sentinel bits.
            assert_eq!(f & o, 0, "free/occupied overlap: {bytes:02x?}");
            assert_eq!(f | o, SWAR_HI, "free|occupied != all lanes: {bytes:02x?}");
        }
    }

    #[test]
    fn free_is_empty_or_tombstone() {
        assert_eq!(swar_free_mask(word([CTRL_EMPTY; 8])), SWAR_HI);
        assert_eq!(swar_free_mask(word([CTRL_TOMBSTONE; 8])), SWAR_HI);
        assert_eq!(swar_occupied_mask(word([CTRL_EMPTY; 8])), 0);
        assert_eq!(swar_occupied_mask(word([CTRL_TOMBSTONE; 8])), 0);
        // Every occupied fingerprint (1..=127) reads occupied, never free.
        for fp in 1..=FINGERPRINT_MASK {
            assert_eq!(swar_occupied_mask(word([fp; 8])), SWAR_HI, "fp {fp:#04x}");
            assert_eq!(swar_free_mask(word([fp; 8])), 0, "fp {fp:#04x}");
        }
    }

    #[test]
    fn no_cross_byte_borrow() {
        // A lone occupied byte among empties flags exactly its own lane.
        let bytes = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(swar_occupied_mask(word(bytes)), 0x80u64 << 8);
        assert_eq!(swar_eq_mask(word(bytes), 0x01), 0x80u64 << 8);
        // Ascending distinct bytes: eq to byte i flags only lane i.
        let asc = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
        for (i, &b) in asc.iter().enumerate() {
            assert_eq!(
                swar_eq_mask(word(asc), b),
                0x80u64 << (8 * i),
                "byte {b:#04x}"
            );
        }
    }

    #[test]
    fn match_lands_in_lane_high_bit() {
        // Lane `i`'s sentinel is bit `8*i + 7`.
        assert_eq!(swar_eq_mask(word([9; 8]), 9), SWAR_HI);
        assert_eq!(
            swar_eq_mask(word([0, 0, 0, 9, 0, 0, 0, 0]), 9),
            0x80u64 << (8 * 3)
        );
    }
}
