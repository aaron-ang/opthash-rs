pub(crate) type BitMaskWord = u64;

/// Bits per slot in [`BitMask`]: 8 for NEON/SWAR-8, 1 elsewhere.
#[cfg(any(opthash_neon_group, opthash_scalar_group))]
pub(crate) const BITMASK_STRIDE: u32 = 8;
#[cfg(opthash_x86_16_group)]
pub(crate) const BITMASK_STRIDE: u32 = 1;

/// Per-slot match mask over a control group.
#[derive(Debug, Clone)]
pub(crate) struct BitMask(pub(crate) BitMaskWord);

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
        // NEON stores each set slot as a full byte.
        #[cfg(opthash_neon_group)]
        {
            let byte = (0xFFu64).wrapping_shl(bit);
            self.0 &= !byte;
        }
        #[cfg(not(opthash_neon_group))]
        {
            self.0 &= self.0.wrapping_sub(1);
        }
        Some(slot)
    }
}
