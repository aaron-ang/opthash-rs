//! Per-level live counts whose settled inserts are counted late.
//!
//! A settled insert raises the table's placed count and leaves the live
//! count of the level it wrote as stored. [`Uncounted`] holds the placed
//! count the stored live counts cover, so the difference is the settled
//! level's uncounted inserts. A [`LiveCount`] gives no value without it.

/// A level's live entries as stored: the settled level's lacks the settled
/// inserts since the last [`Uncounted::count_into`].
#[derive(Clone, Copy, Default)]
#[repr(transparent)]
pub(super) struct LiveCount(u32);

impl LiveCount {
    /// Counts one live entry turned into a tombstone, which raises
    /// `tombstones` by one. The stored count of the settled level may pass
    /// below zero here, and comes back with its uncounted inserts.
    ///
    /// The two counts are the halves of one word, tombstones low, so one
    /// subtraction moves both; the live count is the high half, where
    /// passing below zero borrows from nothing.
    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    pub(super) fn entomb_one(&mut self, tombstones: &mut u32) {
        let both = u64::from(*tombstones) | u64::from(self.0) << 32;
        debug_assert!(*tombstones < u32::MAX);
        let both = both.wrapping_sub(u64::from(u32::MAX));
        *tombstones = both as u32;
        self.0 = (both >> 32) as u32;
    }
}

/// The placed count every stored [`LiveCount`] covers.
#[derive(Clone, Copy, Default)]
pub(super) struct Uncounted {
    covered: usize,
}

impl Uncounted {
    /// Stored counts that cover a table at `placed`.
    #[inline]
    pub(super) fn none_at(placed: usize) -> Self {
        Self { covered: placed }
    }

    /// The settled inserts of a table at `placed` that no stored count
    /// holds, all of them into the settled level.
    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    pub(super) fn pending(self, placed: usize) -> u32 {
        // A level holds fewer than `u32::MAX` slots.
        (placed - self.covered) as u32
    }

    /// The live entries of the level `stored` counts, in a table at
    /// `placed`. `settled` tells the settled level from the others.
    #[inline]
    pub(super) fn live(self, placed: usize, stored: LiveCount, settled: bool) -> u32 {
        if settled {
            stored.0.wrapping_add(self.pending(placed))
        } else {
            stored.0
        }
    }

    /// Moves the uncounted inserts of a table at `placed` into the settled
    /// level's stored count.
    #[inline]
    pub(super) fn count_into(&mut self, placed: usize, settled: &mut LiveCount) {
        settled.0 = settled.0.wrapping_add(self.pending(placed));
        self.covered = placed;
    }

    /// Counts an insert that raises the placed count by one into `stored`.
    #[inline]
    pub(super) fn count_one(&mut self, stored: &mut LiveCount) {
        stored.0 = stored.0.wrapping_add(1);
        self.covered += 1;
    }

    /// Follows a placed count that fell by one with a stored count.
    #[inline]
    pub(super) fn uncover_one(&mut self) {
        self.covered -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::LiveCount;

    #[test]
    fn entombing_moves_each_count_by_one_at_every_edge() {
        let edges = [0, 1, 2, u32::MAX / 2, u32::MAX - 1, u32::MAX];
        for live in edges {
            for tombstones in edges {
                if tombstones == u32::MAX {
                    continue;
                }
                let mut count = LiveCount(live);
                let mut entombed = tombstones;
                count.entomb_one(&mut entombed);
                assert_eq!(count.0, live.wrapping_sub(1));
                assert_eq!(entombed, tombstones + 1);
            }
        }
    }
}
