/// Empty-slot sentinel control byte.
pub(crate) const CTRL_EMPTY: u8 = 0;
/// Tombstone sentinel; like `CTRL_EMPTY` it leaves `OCCUPIED_BIT` clear.
pub(crate) const CTRL_TOMBSTONE: u8 = 0x01;
/// Set on every occupied control byte and on neither sentinel, so a group
/// scan tells live slots from free ones by the sign bit alone.
pub(crate) const OCCUPIED_BIT: u8 = 0x80;
/// Shift by which [`control_fingerprint`] pulls the 7 high bits of a 64-bit
/// hash into bits [6:0].
const FINGERPRINT_SHIFT: u32 = 57;

/// True when the control byte carries a fingerprint (slot holds a live entry).
#[inline]
#[must_use]
pub(crate) fn is_occupied(byte: u8) -> bool {
    byte & OCCUPIED_BIT != 0
}

/// True for `CTRL_EMPTY` and `CTRL_TOMBSTONE`: the slot holds no live entry.
#[inline]
#[must_use]
pub(crate) fn is_free(byte: u8) -> bool {
    byte & OCCUPIED_BIT == 0
}

/// Occupied control byte for `hash`: its top seven bits under `OCCUPIED_BIT`.
#[inline]
#[must_use]
pub(crate) fn control_fingerprint(hash: u64) -> u8 {
    // Seven bits remain after the shift, so the narrowing cast keeps them all.
    #[allow(clippy::cast_possible_truncation)]
    let fingerprint = (hash >> FINGERPRINT_SHIFT) as u8;
    fingerprint | OCCUPIED_BIT
}

/// Occupied control byte for a word that is already mixed: its low seven
/// bits under `OCCUPIED_BIT`.
#[inline]
#[must_use]
pub(crate) const fn control_fingerprint_low(word: u64) -> u8 {
    #[allow(clippy::cast_possible_truncation)]
    let low = word as u8;
    low | OCCUPIED_BIT
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_fingerprint_is_occupied_and_keeps_the_top_hash_bits() {
        assert_eq!(control_fingerprint(0), OCCUPIED_BIT);
        assert_eq!(control_fingerprint(u64::MAX), u8::MAX);
        // Bit 63 of the hash lands in bit 6 of the control byte.
        assert_eq!(control_fingerprint(1 << 63), OCCUPIED_BIT | 0x40);
        assert_eq!(control_fingerprint(1 << 57), OCCUPIED_BIT | 0x01);
        // Bits below the shift do not reach the control byte.
        assert_eq!(control_fingerprint((1 << 57) - 1), OCCUPIED_BIT);
    }

    #[test]
    fn control_fingerprint_low_is_occupied_and_keeps_the_low_word_bits() {
        assert_eq!(control_fingerprint_low(0), OCCUPIED_BIT);
        assert_eq!(control_fingerprint_low(u64::MAX), u8::MAX);
        assert_eq!(control_fingerprint_low(0x7F), u8::MAX);
        assert_eq!(control_fingerprint_low(0x2A), OCCUPIED_BIT | 0x2A);
        // Bits above the low seven do not reach the control byte.
        assert_eq!(control_fingerprint_low(!0x7F), OCCUPIED_BIT);
    }

    #[test]
    fn control_byte_occupied_vs_free() {
        for sentinel in [CTRL_EMPTY, CTRL_TOMBSTONE] {
            assert!(is_free(sentinel));
            assert!(!is_occupied(sentinel));
        }
        for byte in OCCUPIED_BIT..=u8::MAX {
            assert!(is_occupied(byte), "byte {byte:#04x} should read occupied");
            assert!(!is_free(byte));
        }
    }
}
