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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_fingerprint_never_zero_and_in_range() {
        // The `.max(1)` guarantees a non-zero fingerprint even for a zero hash,
        // so an occupied slot never collides with the EMPTY sentinel.
        assert_eq!(control_fingerprint(0), 1);
        // Bit 63 of the hash lands in bit 6 of the fingerprint.
        assert_eq!(control_fingerprint(1 << 63), 64);
        for hash in [0u64, 1, 42, u64::MAX, 0x8000_0000_0000_0000, 12_345_678] {
            let fp = control_fingerprint(hash);
            assert!(
                (1..=FINGERPRINT_MASK).contains(&fp),
                "fp {fp} out of [1,127]"
            );
        }
    }

    #[test]
    fn control_byte_occupied_vs_free() {
        assert!(CTRL_EMPTY.is_free());
        assert!(!CTRL_EMPTY.is_occupied());
        // Tombstone's fingerprint bits are zero: free, not occupied.
        assert!(CTRL_TOMBSTONE.is_free());
        assert!(!CTRL_TOMBSTONE.is_occupied());
        for fp in 1..=FINGERPRINT_MASK {
            assert!(fp.is_occupied(), "fp byte {fp} should read occupied");
            assert!(!fp.is_free());
        }
    }

    #[test]
    fn find_next_fingerprint_scans_across_groups() {
        let fp = 42u8;
        // Longer than one group to drive the wide + group scan paths.
        let len = GROUP_SIZE * 3 + 5;
        let mut controls = vec![CTRL_EMPTY; len];
        let target = GROUP_SIZE * 2 + 3;
        controls[target] = fp;

        assert_eq!(
            find_next_fingerprint_in_controls(&controls, fp, 0),
            Some(target)
        );
        // Starting past the only match finds nothing.
        assert_eq!(
            find_next_fingerprint_in_controls(&controls, fp, target + 1),
            None
        );
        // Start beyond the slice returns None rather than panicking.
        assert_eq!(find_next_fingerprint_in_controls(&controls, fp, len), None);
        // A fingerprint that is absent is not found.
        assert_eq!(find_next_fingerprint_in_controls(&controls, 7, 0), None);
    }

    #[test]
    fn find_next_fingerprint_short_tail() {
        // A slice shorter than a group takes the scalar tail path.
        let fp = 9u8;
        let mut controls = vec![CTRL_EMPTY; GROUP_SIZE - 1];
        controls[GROUP_SIZE - 2] = fp;
        assert_eq!(
            find_next_fingerprint_in_controls(&controls, fp, 0),
            Some(GROUP_SIZE - 2)
        );
    }

    #[test]
    fn control_match_fingerprint_group_locates_byte() {
        let fp = 5u8;
        let mut chunk = vec![CTRL_EMPTY; GROUP_SIZE];
        chunk[2] = fp;
        let mask = control_match_fingerprint_group(&chunk, fp);
        assert_ne!(mask, 0);
        assert_eq!(mask.trailing_zeros() as usize, 2);
        // Absent fingerprint yields no match bits.
        assert_eq!(control_match_fingerprint_group(&chunk, 6), 0);
    }

    #[test]
    #[should_panic(expected = "GROUP_SIZE or 32-byte")]
    fn control_match_fingerprint_group_panics_on_bad_len() {
        let chunk = vec![CTRL_EMPTY; 7];
        let _ = control_match_fingerprint_group(&chunk, 1);
    }
}
