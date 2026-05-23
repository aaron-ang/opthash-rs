#[cfg(target_arch = "aarch64")]
use core::arch::aarch64::{
    uint8x16_t, vandq_u8, vceqq_u8, vdupq_n_u8, vget_lane_u64, vld1q_u8, vreinterpret_u64_u8,
    vreinterpretq_u16_u8, vshrn_n_u16,
};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{
    __m128i, __m256i, _mm_and_si128, _mm_cmpeq_epi8, _mm_cmpgt_epi8, _mm_loadu_si128,
    _mm_movemask_epi8, _mm_set1_epi8, _mm_setzero_si128, _mm256_cmpeq_epi8, _mm256_loadu_si256,
    _mm256_movemask_epi8, _mm256_set1_epi8,
};

use super::bitmask::BitMask;
use super::config::GROUP_SIZE;
#[allow(unused_imports)]
use super::control::{CTRL_EMPTY, CTRL_TOMBSTONE, FINGERPRINT_MASK};

/// 1-bit-per-byte u32 mask over a 16-byte chunk
#[inline]
pub(super) fn match_fingerprint_group_u32(ptr: *const u8, target: u8) -> u32 {
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        let data = _mm_loadu_si128(ptr.cast::<__m128i>());
        #[allow(clippy::cast_possible_wrap)]
        let cmp = _mm_cmpeq_epi8(data, _mm_set1_epi8(target as i8));
        #[allow(clippy::cast_sign_loss)]
        {
            (_mm_movemask_epi8(cmp) as u32) & 0xFFFF
        }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        let mut m = 0u32;
        for i in 0..GROUP_SIZE {
            if unsafe { *ptr.add(i) } == target {
                m |= 1 << i;
            }
        }
        m
    }
}

// ---------------------------------------------------------------------------
// SIMD mask functions
// ---------------------------------------------------------------------------

/// # Safety
///
/// `ptr` must be valid to read `GROUP_SIZE` bytes.
#[inline]
#[must_use]
pub(crate) unsafe fn eq_mask_16(ptr: *const u8, target: u8) -> BitMask {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        eq_mask_16_neon(ptr, target)
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        eq_mask_16_sse2(ptr, target)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let mut m: u16 = 0;
        for i in 0..GROUP_SIZE {
            if unsafe { *ptr.add(i) } == target {
                m |= 1u16 << i;
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
pub(crate) unsafe fn free_mask_16(ptr: *const u8) -> BitMask {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        free_mask_16_neon(ptr)
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        free_mask_16_sse2(ptr)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let mut m: u16 = 0;
        for i in 0..GROUP_SIZE {
            let b = unsafe { *ptr.add(i) };
            if b == CTRL_EMPTY || b == CTRL_TOMBSTONE {
                m |= 1u16 << i;
            }
        }
        BitMask(m)
    }
}

/// Bitmask of occupied slots (low-7-bit fingerprint set, high bit clear).
/// Padding and tombstones are excluded.
///
/// # Safety
///
/// `ptr` must be valid to read `GROUP_SIZE` bytes.
#[inline]
#[must_use]
pub(crate) unsafe fn occupied_mask_16(ptr: *const u8) -> BitMask {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        occupied_mask_16_neon(ptr)
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        occupied_mask_16_sse2(ptr)
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let mut m: u16 = 0;
        for i in 0..GROUP_SIZE {
            let b = unsafe { *ptr.add(i) };
            if (b & FINGERPRINT_MASK) != 0 {
                m |= 1u16 << i;
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
pub(crate) unsafe fn eq_mask_32(ptr: *const u8, target: u8) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::is_x86_feature_detected!("avx2") {
            unsafe { return eq_mask_32_avx2(ptr, target) };
        }
    }

    let lo = match_fingerprint_group_u32(ptr, target);
    let hi = match_fingerprint_group_u32(unsafe { ptr.add(GROUP_SIZE) }, target);
    lo | (hi << GROUP_SIZE)
}

// ---------------------------------------------------------------------------
// Prefetch
// ---------------------------------------------------------------------------

/// # Safety
///
/// `ptr` must be a valid, aligned pointer to readable memory (or null, in which
/// case the prefetch is silently ignored by the hardware).
#[inline]
pub(crate) unsafe fn prefetch_read(ptr: *const u8) {
    // aarch64 arm gated off Miri: it can't model inline asm.
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    unsafe {
        core::arch::asm!("prfm pldl1keep, [{}]", in(reg) ptr, options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        _mm_prefetch(ptr.cast::<i8>(), _MM_HINT_T0);
    }
    let _ = ptr;
}

// ---------------------------------------------------------------------------
// Platform-specific SIMD implementations
// ---------------------------------------------------------------------------

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn nibble_mask_from_cmp(cmp: uint8x16_t) -> BitMask {
    // vshrn narrows 16×u8 → 8 bytes: each source byte of 0xFF becomes a nibble
    // of 0xF in the output, 0x00 becomes 0x0. Result u64 has 4 bits per slot.
    unsafe {
        let narrowed = vshrn_n_u16(vreinterpretq_u16_u8(cmp), 4);
        BitMask(vget_lane_u64(vreinterpret_u64_u8(narrowed), 0))
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn eq_mask_16_neon(ptr: *const u8, target: u8) -> BitMask {
    unsafe {
        let bytes = vld1q_u8(ptr);
        let cmp = vceqq_u8(bytes, vdupq_n_u8(target));
        nibble_mask_from_cmp(cmp)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn free_mask_16_neon(ptr: *const u8) -> BitMask {
    unsafe {
        let bytes = vld1q_u8(ptr);
        let masked = vandq_u8(bytes, vdupq_n_u8(FINGERPRINT_MASK));
        let free_cmp = vceqq_u8(masked, vdupq_n_u8(0));
        nibble_mask_from_cmp(free_cmp)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn occupied_mask_16_neon(ptr: *const u8) -> BitMask {
    // vtstq_u8(a, b) gives 0xFF where (a AND b) != 0 — with b = 0x7F that's
    // exactly the occupied set.
    unsafe {
        let bytes = vld1q_u8(ptr);
        let occ_cmp = core::arch::aarch64::vtstq_u8(bytes, vdupq_n_u8(FINGERPRINT_MASK));
        nibble_mask_from_cmp(occ_cmp)
    }
}

#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_ptr_alignment
)]
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn eq_mask_16_sse2(ptr: *const u8, target: u8) -> BitMask {
    unsafe {
        let data = _mm_loadu_si128(ptr.cast::<__m128i>());
        let target_vec = _mm_set1_epi8(target as i8);
        let cmp = _mm_cmpeq_epi8(data, target_vec);
        #[allow(clippy::cast_possible_truncation)]
        {
            BitMask(_mm_movemask_epi8(cmp) as u16)
        }
    }
}

#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_ptr_alignment
)]
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn free_mask_16_sse2(ptr: *const u8) -> BitMask {
    unsafe {
        let data = _mm_loadu_si128(ptr.cast::<__m128i>());
        let masked = _mm_and_si128(data, _mm_set1_epi8(FINGERPRINT_MASK as i8));
        let free = _mm_cmpeq_epi8(masked, _mm_setzero_si128());
        #[allow(clippy::cast_possible_truncation)]
        {
            BitMask(_mm_movemask_epi8(free) as u16)
        }
    }
}

#[allow(
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_ptr_alignment
)]
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn occupied_mask_16_sse2(ptr: *const u8) -> BitMask {
    // cmpgt against zero on the low-7-bit mask yields 0xFF for occupied lanes.
    unsafe {
        let data = _mm_loadu_si128(ptr.cast::<__m128i>());
        let masked = _mm_and_si128(data, _mm_set1_epi8(FINGERPRINT_MASK as i8));
        let occ = _mm_cmpgt_epi8(masked, _mm_setzero_si128());
        #[allow(clippy::cast_possible_truncation)]
        {
            BitMask(_mm_movemask_epi8(occ) as u16)
        }
    }
}

#[allow(clippy::cast_possible_wrap, clippy::cast_ptr_alignment)]
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn eq_mask_32_avx2(ptr: *const u8, target: u8) -> u32 {
    unsafe {
        let data = _mm256_loadu_si256(ptr.cast::<__m256i>());
        let target_vec = _mm256_set1_epi8(target as i8);
        let cmp = _mm256_cmpeq_epi8(data, target_vec);
        #[allow(clippy::cast_sign_loss)]
        {
            _mm256_movemask_epi8(cmp) as u32
        }
    }
}
