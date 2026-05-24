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
    // Masking with FINGERPRINT_MASK (0x7F) bounds the value to [0, 127],
    // so the truncating `as u8` cast is lossless.
    #[allow(clippy::cast_possible_truncation)]
    let high = ((hash >> FINGERPRINT_SHIFT) & u64::from(FINGERPRINT_MASK)) as u8;
    high.max(1)
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

    let wide = preferred_group_width();
    let mut index = start;
    while wide > GROUP_SIZE && index + wide <= controls.len() {
        let mask = control_match_fingerprint_group(&controls[index..index + wide], fingerprint);
        if mask != 0 {
            return Some(index + mask.trailing_zeros() as usize);
        }
        index += wide;
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

#[inline]
#[must_use]
fn preferred_group_width() -> usize {
    #[cfg(target_arch = "x86_64")]
    {
        use std::sync::OnceLock;
        static WIDTH: OnceLock<usize> = OnceLock::new();
        *WIDTH.get_or_init(|| {
            if std::is_x86_feature_detected!("avx2") {
                32
            } else {
                GROUP_SIZE
            }
        })
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        GROUP_SIZE
    }
}

/// Cold-path 1-bit-per-byte `u32` mask. Hot callers should use `eq_mask_16`.
///
/// # Panics
///
/// `chunk.len()` must be 16 or 32.
#[inline]
#[must_use]
pub(crate) fn control_match_fingerprint_group(chunk: &[u8], target: u8) -> u32 {
    match chunk.len() {
        GROUP_SIZE => simd::match_fingerprint_group_u32(chunk.as_ptr(), target),
        32 => unsafe { simd::eq_mask_32(chunk.as_ptr(), target) },
        _ => panic!("group matching requires 16 or 32 byte chunks"),
    }
}
