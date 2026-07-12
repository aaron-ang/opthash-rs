const GENERATION_MASK: u64 = u32::MAX as u64;
const RECOVERY_SHIFT: u32 = 32;
const RECOVERY_MASK: u64 = ((1_u64 << 28) - 1) << RECOVERY_SHIFT;
const TRANSITION_SHIFT: u32 = 60;
const TRANSITION_MASK: u64 = 0b111 << TRANSITION_SHIFT;
const HAD_DELETE_MASK: u64 = 1_u64 << 63;

/// Cause of the current allocation epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u8)]
pub enum EpochTransition {
    /// Initial construction.
    Initial,
    /// Automatic growth after an absent insertion exceeded live capacity.
    Growth,
    /// Same-size rebuild that removed tombstones.
    TombstoneCleanup,
    /// Explicit reserve, shrink, or backend resize.
    ExplicitResize,
    /// `clear` or a draining operation reset the retained allocation.
    Clear,
    /// A placement failure below live capacity forced exceptional recovery.
    PlacementRecovery,
}

/// Snapshot of the current allocation epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EpochSnapshot {
    /// Monotonic epoch number; initial construction is generation zero.
    pub generation: u64,
    /// Distinct insertions represented in this epoch, including survivors
    /// reinserted at its boundary. Deletes do not decrement this count.
    pub distinct_insertions: usize,
    /// Whether this epoch has observed a delete since its last boundary.
    pub had_delete: bool,
    /// Cumulative exceptional placement recoveries across the map's lifetime.
    pub placement_recoveries: u64,
    /// Cause of the current epoch.
    pub transition: EpochTransition,
}

/// Compact lifecycle state kept off the lookup path.
///
/// Distinct insertions are derived as `live entries + deletions` so successful
/// inserts add no epoch-specific write to the mutation hot path.
#[derive(Clone, Copy, Debug)]
pub(crate) struct EpochState {
    deletions: usize,
    lifecycle: u64,
}

impl EpochState {
    pub(crate) const fn initial() -> Self {
        Self {
            deletions: 0,
            lifecycle: 0,
        }
    }

    #[inline]
    pub(crate) fn note_delete(&mut self) {
        self.deletions = self.deletions.saturating_add(1);
        self.lifecycle |= HAD_DELETE_MASK;
    }

    pub(crate) fn start(&mut self, transition: EpochTransition, _survivor_insertions: usize) {
        let generation = self.generation().saturating_add(1);
        self.lifecycle = (self.lifecycle & RECOVERY_MASK)
            | u64::from(generation)
            | (transition_bits(transition) << TRANSITION_SHIFT);
        self.deletions = 0;
    }

    pub(crate) fn start_placement_recovery(&mut self, survivor_insertions: usize) {
        self.start_with_placement_recovery(EpochTransition::PlacementRecovery, survivor_insertions);
    }

    pub(crate) fn start_with_placement_recovery(
        &mut self,
        transition: EpochTransition,
        survivor_insertions: usize,
    ) {
        let recoveries = self.placement_recoveries().saturating_add(1);
        self.lifecycle =
            (self.lifecycle & !RECOVERY_MASK) | (u64::from(recoveries) << RECOVERY_SHIFT);
        self.start(transition, survivor_insertions);
    }

    pub(crate) const fn snapshot(self, live_entries: usize) -> EpochSnapshot {
        EpochSnapshot {
            generation: self.generation() as u64,
            distinct_insertions: live_entries.saturating_add(self.deletions),
            had_delete: self.lifecycle & HAD_DELETE_MASK != 0,
            placement_recoveries: self.placement_recoveries() as u64,
            transition: transition_from_bits(
                (self.lifecycle & TRANSITION_MASK) >> TRANSITION_SHIFT,
            ),
        }
    }

    const fn generation(self) -> u32 {
        (self.lifecycle & GENERATION_MASK) as u32
    }

    const fn placement_recoveries(self) -> u32 {
        ((self.lifecycle & RECOVERY_MASK) >> RECOVERY_SHIFT) as u32
    }
}

const fn transition_bits(transition: EpochTransition) -> u64 {
    match transition {
        EpochTransition::Initial => 0,
        EpochTransition::Growth => 1,
        EpochTransition::TombstoneCleanup => 2,
        EpochTransition::ExplicitResize => 3,
        EpochTransition::Clear => 4,
        EpochTransition::PlacementRecovery => 5,
    }
}

const fn transition_from_bits(bits: u64) -> EpochTransition {
    match bits {
        1 => EpochTransition::Growth,
        2 => EpochTransition::TombstoneCleanup,
        3 => EpochTransition::ExplicitResize,
        4 => EpochTransition::Clear,
        5 => EpochTransition::PlacementRecovery,
        _ => EpochTransition::Initial,
    }
}
