pub(crate) type BitMaskWord = u64;

/// Bits per slot in [`BitMask`]: 4 for NEON's nibble mask, 8 for the SWAR-8
/// fallback (one `0x80` sentinel per control byte), 1 elsewhere.
#[cfg(opthash_neon_group)]
pub(crate) const BITMASK_STRIDE: u32 = 4;
#[cfg(opthash_scalar_group)]
pub(crate) const BITMASK_STRIDE: u32 = 8;
#[cfg(any(opthash_x86_16_group, opthash_avx512_group))]
pub(crate) const BITMASK_STRIDE: u32 = 1;

/// Per-slot match mask over a control group.
#[derive(Debug, Clone)]
pub(crate) struct BitMask(pub(crate) BitMaskWord);

impl BitMask {
    #[inline]
    /// True if any slot is set.
    pub(crate) fn any(self) -> bool {
        self.0 != 0
    }

    /// Index of the lowest set slot, or `None` if empty.
    #[inline]
    pub(crate) fn lowest(self) -> Option<usize> {
        if self.0 == 0 {
            None
        } else {
            Some((self.0.trailing_zeros() / BITMASK_STRIDE) as usize)
        }
    }
}

impl Iterator for BitMask {
    type Item = usize;

    #[inline]
    /// Yields the index of the lowest set slot, then clears it, until empty.
    fn next(&mut self) -> Option<usize> {
        if self.0 == 0 {
            return None;
        }
        let bit = self.0.trailing_zeros();
        let slot = (bit / BITMASK_STRIDE) as usize;
        // NEON stores each set slot as a full nibble.
        #[cfg(opthash_neon_group)]
        {
            let nibble = (0xFu64).wrapping_shl(bit);
            self.0 &= !nibble;
        }
        #[cfg(not(opthash_neon_group))]
        {
            self.0 &= self.0.wrapping_sub(1);
        }
        Some(slot)
    }
}
