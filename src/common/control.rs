use super::config::GROUP_SIZE;
use super::simd;

/// Empty-slot sentinel control byte.
pub(crate) const CTRL_EMPTY: u8 = 0;
/// Tombstone sentinel; high bit set distinguishes a deleted slot from occupied.
pub(crate) const CTRL_TOMBSTONE: u8 = 0x80;
/// Low 7 bits hold the fingerprint; high bit distinguishes occupied (0) from
/// the tombstone sentinel (`CTRL_TOMBSTONE`).
pub(crate) const FINGERPRINT_MASK: u8 = 0x7F;
/// Shift that pulls the 7 high bits of a 64-bit hash into bits [6:0].
const FINGERPRINT_SHIFT: u32 = 57;

pub(crate) trait ControlByte {
    fn is_occupied(&self) -> bool;
    fn is_free(&self) -> bool;
}

impl ControlByte for u8 {
    #[inline]
    fn is_occupied(&self) -> bool {
        (*self & FINGERPRINT_MASK) != 0
    }

    #[inline]
    fn is_free(&self) -> bool {
        (*self & FINGERPRINT_MASK) == 0
    }
}

#[inline]
#[must_use]
pub(crate) fn control_fingerprint(hash: u64) -> u8 {
    // Masking with FINGERPRINT_MASK (0x7F) bounds the value to [0, 127];
    // try_from succeeds unconditionally so the unwrap is unreachable.
    let masked = (hash >> FINGERPRINT_SHIFT) & u64::from(FINGERPRINT_MASK);
    u8::try_from(masked).unwrap_or(0).max(1)
}

#[inline]
#[must_use]
pub(crate) fn find_next_fingerprint_in_controls(
    controls: &[u8],
    fingerprint: u8,
    start: usize,
) -> Option<usize> {
    if start >= controls.len() {
        return None;
    }

    if controls.len() - start < GROUP_SIZE {
        return controls[start..]
            .iter()
            .position(|&control| control == fingerprint)
            .map(|offset| start + offset);
    }

    let mut index = start;
    while WIDE_SCAN_WIDTH > GROUP_SIZE && index + WIDE_SCAN_WIDTH <= controls.len() {
        let mask =
            control_match_fingerprint_group(&controls[index..index + WIDE_SCAN_WIDTH], fingerprint);
        if mask != 0 {
            return Some(index + mask.trailing_zeros() as usize);
        }
        index += WIDE_SCAN_WIDTH;
    }

    while index + GROUP_SIZE <= controls.len() {
        let mask =
            control_match_fingerprint_group(&controls[index..index + GROUP_SIZE], fingerprint);
        if mask != 0 {
            return Some(index + mask.trailing_zeros() as usize);
        }
        index += GROUP_SIZE;
    }

    controls[index..]
        .iter()
        .position(|&control| control == fingerprint)
        .map(|offset| index + offset)
}

/// Cold fallback scan width: AVX2 scans 32 bytes, others one group.
#[cfg(opthash_avx2)]
const WIDE_SCAN_WIDTH: usize = 32;
#[cfg(not(opthash_avx2))]
const WIDE_SCAN_WIDTH: usize = GROUP_SIZE;

/// Cold fallback equality mask. Hot callers should use `eq_mask_group`.
///
/// # Panics
///
/// `chunk.len()` must be `GROUP_SIZE` or 32.
#[inline]
#[must_use]
pub(crate) fn control_match_fingerprint_group(chunk: &[u8], target: u8) -> u64 {
    match chunk.len() {
        GROUP_SIZE => unsafe { simd::eq_bits_group(chunk.as_ptr(), target) },
        32 => unsafe { simd::eq_bits_32(chunk.as_ptr(), target) },
        _ => panic!("group matching requires GROUP_SIZE or 32-byte chunks"),
    }
}
