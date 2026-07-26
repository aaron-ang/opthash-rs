//! Bloom-style membership filter shared by both table backends.
//!
//! Each backend appends filter words to its arena tail and gates lookups on
//! them. Bits are set on insert and never cleared, so a missing bit proves no
//! insert ever recorded that key and the lookup can skip probing; the filter
//! reports false positives, never false negatives.
//!
//! It is an accelerator, not paper geometry: candidate order is unchanged, only
//! whether the candidates are worth visiting.

/// Logical slots covered by one filter word. Ten keeps the tail under a byte per
/// slot while leaving words sparse enough for two bits per key to stay selective.
pub(crate) const SLOTS_PER_WORD: usize = 10;

/// Filter words needed to cover `total_slots` logical slots.
#[inline]
pub(crate) fn word_count(total_slots: usize) -> usize {
    total_slots.div_ceil(SLOTS_PER_WORD)
}

/// One key's filter bits, derived once per operation.
#[derive(Clone, Copy)]
pub(crate) struct MembershipKey {
    bits: u64,
}

impl MembershipKey {
    /// Two bits of one word, from disjoint signature fields. Two rather than
    /// four: at ten keys per word false positives rise 5% → 7%, a fraction of a
    /// probe walk, and every insert and gated lookup drops two shifted adds.
    #[inline]
    pub(crate) fn from_signature(signature: u64) -> Self {
        let first = signature & 63;
        let second = (signature >> 32) & 63;
        Self {
            bits: (1_u64 << first) | (1_u64 << second),
        }
    }

    #[inline]
    pub(crate) const fn bits(self) -> u64 {
        self.bits
    }

    /// Multiply-high reduction of `signature` into `word_count` words. The high
    /// half is below `word_count`, so the cast cannot lose bits and needs no
    /// checked path in front of the load it feeds.
    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn word(signature: u64, word_count: usize) -> usize {
        let product = u128::from(signature) * word_count as u128;
        (product >> 64) as usize
    }
}

/// Cached position of a filter tail inside its arena. The gate is a lookup's
/// first dependent load, so deriving its address per call would put a `div_ceil`
/// chain and alignment math in front of it. Moves only on reallocation.
#[derive(Clone, Copy)]
pub(crate) struct MembershipRegion {
    /// Byte offset from the arena base.
    pub(crate) offset: usize,
    pub(crate) words: usize,
}

impl MembershipRegion {
    pub(crate) const EMPTY: Self = Self {
        offset: 0,
        words: 0,
    };
}
