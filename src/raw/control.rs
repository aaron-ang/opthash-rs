/// Empty-slot sentinel control byte.
pub(crate) const CTRL_EMPTY: u8 = 0;
/// Tombstone sentinel; like `CTRL_EMPTY` it leaves `OCCUPIED_BIT` clear.
pub(crate) const CTRL_TOMBSTONE: u8 = 0x01;
/// Set on every occupied control byte and on neither sentinel, so a group
/// scan tells live slots from free ones by the sign bit alone.
pub(crate) const OCCUPIED_BIT: u8 = 0x80;

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

/// Occupied control byte from `word`'s low seven bits, under
/// `OCCUPIED_BIT`.
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
