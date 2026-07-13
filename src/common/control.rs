/// Empty-slot sentinel control byte.
pub(crate) const CTRL_EMPTY: u8 = 0xFF;
/// Tombstone sentinel; high bit set distinguishes a deleted slot from occupied.
pub(crate) const CTRL_TOMBSTONE: u8 = 0x80;
/// Low 7 bits hold occupied fingerprints; the high bit marks free controls.
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
        *self & 0x80 == 0
    }

    #[inline]
    fn is_free(&self) -> bool {
        *self & 0x80 != 0
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
        assert_ne!(CTRL_EMPTY & 0x80, 0, "empty must carry the free high bit");
        assert!(CTRL_EMPTY.is_free());
        assert!(!CTRL_EMPTY.is_occupied());
        // Both sentinels carry the high free bit.
        assert!(CTRL_TOMBSTONE.is_free());
        assert!(!CTRL_TOMBSTONE.is_occupied());
        for fp in 1..=FINGERPRINT_MASK {
            assert!(fp.is_occupied(), "fp byte {fp} should read occupied");
            assert!(!fp.is_free());
        }
    }

    #[test]
    fn high_bit_partitions_every_control_byte() {
        for control in 0..=u8::MAX {
            assert_eq!(control.is_free(), control & 0x80 != 0);
            assert_eq!(control.is_occupied(), control & 0x80 == 0);
        }
    }
}
