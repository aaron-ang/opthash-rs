//! Bloom-style membership filter shared by both table backends.
//!
//! Each backend appends filter words to its arena tail and gates lookups on
//! them. Bits are set on insert and never cleared, so a missing bit proves no
//! insert ever recorded that key and the lookup can skip probing; the filter
//! reports false positives, never false negatives.
//!
//! It is an accelerator, not paper geometry: candidate order is unchanged, only
//! whether the candidates are worth visiting.

use core::ptr;

use allocator_api2::alloc::Layout;

use crate::common::error::TryReserveError;

/// Logical slots covered by one filter word. Ten keeps the tail under a byte per
/// slot while leaving words sparse enough for two bits per key to stay selective.
pub(crate) const SLOTS_PER_WORD: usize = 10;

/// Filter words needed to cover `total_slots` logical slots.
#[inline]
pub(crate) fn word_count(total_slots: usize) -> usize {
    total_slots.div_ceil(SLOTS_PER_WORD)
}

/// Deletes a filter tolerates before it is re-recorded from the live entries.
///
/// Bits are never cleared per key, so departed keys raise the filter's load
/// until nearly every gate passes. One capacity's worth of departures doubles
/// the load; re-recording then costs one hash per live entry, amortised to a
/// few instructions per delete.
#[inline]
#[must_use]
pub(crate) const fn refresh_deletes(max_insertions: usize) -> usize {
    max_insertions
}

/// One key's filter bits, derived once per operation.
#[derive(Clone, Copy)]
pub(crate) struct MembershipKey {
    bits: u64,
}

impl MembershipKey {
    /// Two bits of one word, from disjoint signature fields. Two rather than
    /// four: at ten keys per word the extra false positives cost a fraction of
    /// a probe walk, and every insert and gated lookup drops two shifted adds.
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

    /// Appends a `W`-word tail covering `total_slots` to `base`, returning the
    /// padded arena layout and where the tail sits inside it. An empty geometry
    /// keeps `base` unchanged and yields [`Self::EMPTY`].
    pub(crate) fn extend<W>(
        base: Layout,
        total_slots: usize,
    ) -> Result<(Layout, Self), TryReserveError> {
        let words = word_count(total_slots);
        if words == 0 {
            return Ok((base, Self::EMPTY));
        }
        let tail = Layout::array::<W>(words).map_err(|_| TryReserveError::AllocError)?;
        let (layout, offset) = base.extend(tail).map_err(|_| TryReserveError::AllocError)?;
        Ok((layout.pad_to_align(), Self { offset, words }))
    }

    /// Base of the word tail inside the arena at `base`. `Layout::extend`
    /// aligned the tail for `W`, so the cast is aligned by construction.
    ///
    /// # Safety
    ///
    /// `base` must be the arena this region was laid out for.
    #[inline]
    #[allow(clippy::cast_ptr_alignment)]
    pub(crate) unsafe fn ptr<W>(self, base: *mut u8) -> *mut W {
        unsafe { base.add(self.offset).cast::<W>() }
    }

    /// Zeroes every word, so the filter reads as "nothing recorded".
    ///
    /// # Safety
    ///
    /// As for [`Self::ptr`].
    #[inline]
    pub(crate) unsafe fn clear<W>(self, base: *mut u8) {
        if self.words != 0 {
            unsafe { ptr::write_bytes(self.ptr::<W>(base), 0, self.words) };
        }
    }

    /// Copies `source`'s words from `source_base` into this region at `base`.
    ///
    /// # Safety
    ///
    /// As for [`Self::ptr`], for both arenas; the regions must not overlap.
    #[inline]
    pub(crate) unsafe fn copy_from<W>(self, base: *mut u8, source: Self, source_base: *mut u8) {
        debug_assert_eq!(self.words, source.words);
        if self.words != 0 {
            unsafe {
                ptr::copy_nonoverlapping(
                    source.ptr::<W>(source_base),
                    self.ptr::<W>(base),
                    self.words,
                );
            };
        }
    }
}
