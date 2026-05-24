#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::{self, uint8x16_t};
#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::{self, __m128i, __m256i, _MM_HINT_T0};

use super::bitmask::BitMask;
use super::config::GROUP_SIZE;
use super::control::FINGERPRINT_MASK;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
use super::control::{CTRL_EMPTY, CTRL_TOMBSTONE};

/// 1-bit-per-byte u32 mask over a 16-byte chunk
#[inline]
pub(super) fn match_fingerprint_group_u32(ptr: *const u8, target: u8) -> u32 {
    #[cfg(target_arch = "x86_64")]
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
        #[allow(clippy::cast_possible_wrap)]
        let cmp = x86_64::_mm_cmpeq_epi8(data, x86_64::_mm_set1_epi8(target as i8));
        #[allow(clippy::cast_sign_loss)]
        {
            (x86_64::_mm_movemask_epi8(cmp) as u32) & 0xFFFF
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
#[allow(dead_code)]
#[inline]
pub(crate) unsafe fn prefetch_read(ptr: *const u8) {
    // aarch64 arm gated off Miri: it can't model inline asm.
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    unsafe {
        std::arch::asm!("prfm pldl1keep, [{}]", in(reg) ptr, options(nostack, preserves_flags));
    }
    #[cfg(target_arch = "x86_64")]
    unsafe {
        x86_64::_mm_prefetch(ptr.cast::<i8>(), _MM_HINT_T0);
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
        let narrowed = aarch64::vshrn_n_u16(aarch64::vreinterpretq_u16_u8(cmp), 4);
        BitMask(aarch64::vget_lane_u64(
            aarch64::vreinterpret_u64_u8(narrowed),
            0,
        ))
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn eq_mask_16_neon(ptr: *const u8, target: u8) -> BitMask {
    unsafe {
        let bytes = aarch64::vld1q_u8(ptr);
        let cmp = aarch64::vceqq_u8(bytes, aarch64::vdupq_n_u8(target));
        nibble_mask_from_cmp(cmp)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn free_mask_16_neon(ptr: *const u8) -> BitMask {
    unsafe {
        let bytes = aarch64::vld1q_u8(ptr);
        let masked = aarch64::vandq_u8(bytes, aarch64::vdupq_n_u8(FINGERPRINT_MASK));
        let free_cmp = aarch64::vceqq_u8(masked, aarch64::vdupq_n_u8(0));
        nibble_mask_from_cmp(free_cmp)
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
unsafe fn occupied_mask_16_neon(ptr: *const u8) -> BitMask {
    // vtstq_u8(a, b) gives 0xFF where (a AND b) != 0 — with b = 0x7F that's
    // exactly the occupied set.
    unsafe {
        let bytes = aarch64::vld1q_u8(ptr);
        let occ_cmp = aarch64::vtstq_u8(bytes, aarch64::vdupq_n_u8(FINGERPRINT_MASK));
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
        let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
        let target_vec = x86_64::_mm_set1_epi8(target as i8);
        let cmp = x86_64::_mm_cmpeq_epi8(data, target_vec);
        #[allow(clippy::cast_possible_truncation)]
        {
            BitMask(x86_64::_mm_movemask_epi8(cmp) as u16)
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
        let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
        let masked = x86_64::_mm_and_si128(data, x86_64::_mm_set1_epi8(FINGERPRINT_MASK as i8));
        let free = x86_64::_mm_cmpeq_epi8(masked, x86_64::_mm_setzero_si128());
        #[allow(clippy::cast_possible_truncation)]
        {
            BitMask(x86_64::_mm_movemask_epi8(free) as u16)
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
        let data = x86_64::_mm_loadu_si128(ptr.cast::<__m128i>());
        let masked = x86_64::_mm_and_si128(data, x86_64::_mm_set1_epi8(FINGERPRINT_MASK as i8));
        let occ = x86_64::_mm_cmpgt_epi8(masked, x86_64::_mm_setzero_si128());
        #[allow(clippy::cast_possible_truncation)]
        {
            BitMask(x86_64::_mm_movemask_epi8(occ) as u16)
        }
    }
}

#[allow(clippy::cast_possible_wrap, clippy::cast_ptr_alignment)]
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn eq_mask_32_avx2(ptr: *const u8, target: u8) -> u32 {
    unsafe {
        let data = x86_64::_mm256_loadu_si256(ptr.cast::<__m256i>());
        let target_vec = x86_64::_mm256_set1_epi8(target as i8);
        let cmp = x86_64::_mm256_cmpeq_epi8(data, target_vec);
        #[allow(clippy::cast_sign_loss)]
        {
            x86_64::_mm256_movemask_epi8(cmp) as u32
        }
    }
}
