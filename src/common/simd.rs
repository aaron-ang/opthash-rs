#[cfg(target_arch = "aarch64")]
use core::arch::aarch64;
#[cfg(opthash_neon_group)]
use core::arch::aarch64::uint8x16_t;
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64;
#[cfg(all(target_arch = "x86_64", opthash_eq_bits_16))]
use core::arch::x86_64::__m128i;
#[cfg(opthash_avx2)]
use core::arch::x86_64::__m256i;
#[cfg(opthash_avx512_group)]
use core::arch::x86_64::__m512i;

use super::bitmask::BitMask;
#[cfg(opthash_scalar_group)]
use super::config::GROUP_SIZE;
use super::control::FINGERPRINT_MASK;
#[cfg(opthash_scalar_group)]
use super::control::{CTRL_EMPTY, CTRL_TOMBSTONE};

// Fixed 16-byte equality scan used by 16-byte groups and non-AVX2 cold scans.
#[inline]
#[cfg(opthash_eq_bits_16)]
unsafe fn eq_bits_16(ptr: *const u8, target: u8) -> u64 {
    // _mm_loadu_si128 is unaligned despite taking `*const __m128i`.
    #[allow(clippy::cast_ptr_alignment)]
    #[cfg(target_arch = "x86_64")]
    unsafe {
        let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
        let cmp = x86_64::_mm_cmpeq_epi8(data, x86_64::_mm_set1_epi8(target.cast_signed()));
        u64::from(x86_64::_mm_movemask_epi8(cmp).cast_unsigned() & 0xFFFF)
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let mut m = 0u64;
        for i in 0..16 {
            if unsafe { *ptr.add(i) } == target {
                m |= 1 << i;
            }
        }
        m
    }
}

/// # Safety
///
/// `ptr` must be valid to read `GROUP_SIZE` bytes.
#[inline]
pub(super) unsafe fn eq_bits_group(ptr: *const u8, target: u8) -> u64 {
    #[cfg(opthash_avx512_group)]
    unsafe {
        eq_mask_64_avx512(ptr, target).0
    }

    #[cfg(not(opthash_wide_group))]
    {
        unsafe { eq_bits_16(ptr, target) }
    }
}

/// # Safety
///
/// `ptr` must be valid to read `GROUP_SIZE` bytes.
#[inline]
#[must_use]
pub(crate) unsafe fn eq_mask_group(ptr: *const u8, target: u8) -> BitMask {
    #[cfg(opthash_neon_group)]
    unsafe {
        eq_mask_16_neon(ptr, target)
    }
    #[cfg(opthash_avx512_group)]
    unsafe {
        eq_mask_64_avx512(ptr, target)
    }
    #[cfg(opthash_x86_16_group)]
    unsafe {
        eq_mask_16_sse2(ptr, target)
    }
    #[cfg(opthash_scalar_group)]
    {
        let mut m = 0u64;
        for i in 0..GROUP_SIZE {
            if unsafe { *ptr.add(i) } == target {
                m |= 1 << i;
            }
        }
        BitMask(m)
    }
}

/// # Safety
///
/// `ptr` must be valid to read `GROUP_SIZE` bytes.
#[inline]
#[must_use]
pub(crate) unsafe fn free_mask_group(ptr: *const u8) -> BitMask {
    #[cfg(opthash_neon_group)]
    unsafe {
        free_mask_16_neon(ptr)
    }
    #[cfg(opthash_avx512_group)]
    unsafe {
        free_mask_64_avx512(ptr)
    }
    #[cfg(opthash_x86_16_group)]
    unsafe {
        free_mask_16_sse2(ptr)
    }
    #[cfg(opthash_scalar_group)]
    {
        let mut m = 0u64;
        for i in 0..GROUP_SIZE {
            let b = unsafe { *ptr.add(i) };
            if b == CTRL_EMPTY || b == CTRL_TOMBSTONE {
                m |= 1 << i;
            }
        }
        BitMask(m)
    }
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
    unsafe {
        occupied_mask_16_neon(ptr)
    }
    #[cfg(opthash_avx512_group)]
    unsafe {
        occupied_mask_64_avx512(ptr)
    }
    #[cfg(opthash_x86_16_group)]
    unsafe {
        occupied_mask_16_sse2(ptr)
    }
    #[cfg(opthash_scalar_group)]
    {
        let mut m = 0u64;
        for i in 0..GROUP_SIZE {
            let b = unsafe { *ptr.add(i) };
            if (b & FINGERPRINT_MASK) != 0 {
                m |= 1 << i;
            }
        }
        BitMask(m)
    }
}

/// # Safety
///
/// `ptr` must be valid to read 32 bytes.
#[inline]
#[must_use]
pub(crate) unsafe fn eq_bits_32(ptr: *const u8, target: u8) -> u64 {
    #[cfg(opthash_avx2)]
    unsafe {
        eq_bits_32_avx2(ptr, target)
    }
    #[cfg(not(opthash_avx2))]
    unsafe {
        let lo = eq_bits_16(ptr, target);
        let hi = eq_bits_16(ptr.add(16), target);
        lo | (hi << 16)
    }
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

#[allow(clippy::cast_ptr_alignment)]
#[cfg(opthash_avx2)]
#[inline]
unsafe fn eq_bits_32_avx2(ptr: *const u8, target: u8) -> u64 {
    unsafe {
        let data = x86_64::_mm256_loadu_si256(ptr.cast::<__m256i>());
        let target_vec = x86_64::_mm256_set1_epi8(target.cast_signed());
        let cmp = x86_64::_mm256_cmpeq_epi8(data, target_vec);
        u64::from(x86_64::_mm256_movemask_epi8(cmp).cast_unsigned())
    }
}
