use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::mem::{self, MaybeUninit};
use core::ptr;

use alloc::boxed::Box;
use alloc::vec::Vec;
use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::ReserveFraction;
use crate::capacity;
use crate::epoch::{EpochSnapshot, EpochState, EpochTransition};
use crate::error::{TryBuildError, TryReserveError};
use crate::exact::geometry::PaperConfig;
use crate::exact::probe::{self, CounterPrf, PreparedElasticProbe};
use crate::hasher::DefaultHashBuilder;
use crate::macros;
use crate::map;
use crate::membership::{self, MembershipRegion};
use crate::raw::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::raw::config::INITIAL_CAPACITY;
use crate::raw::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE};
use crate::raw::iter::OccupiedIndices;
use crate::raw::prefetch;
use crate::raw::rebuild::{self, Rebuildable};

mod live_count;
mod schedule;

use live_count::{LiveCount, Uncounted};
use schedule::{PhiRoute, ProbeSchedule, ProbeScheduleRoom, SENTINEL_BIT, SENTINEL_LEVEL};

/// `(slot pointer, location)` yielded by the scan cursor: the pointer is read
/// by iterators, the `(level, slot)` location backs removal.
type ElasticScanItem<K, V> = (*mut SlotEntry<K, V>, (usize, usize));

/// Fixed construction seed shared by placement, lookup, and membership.
/// Zero keeps the routing signature the key's hash itself; the probe words
/// are keyed by their fold multiplier.
const ELASTIC_PROBE_SEED: u64 = 0;
/// The paper's constant `c` in the per-level probe budget
/// `c * min(log2(1/eps)^2, log2(1/delta))`; the paper only asks that it be
/// sufficiently large.
const ELASTIC_PROBE_BUDGET_C: u32 = 8;
/// Most probe indices any level's search visits. The paper's fallback search
/// is unbounded; this caps it so the lookup schedule stays finite.
const UNIFORM_SEARCH_CAP: u64 = 4_096;
/// Largest paper query position a placement may take. The lookup schedule
/// covers every position up to it, so a vacancy past it counts as a failed
/// probe.
const QUERY_POSITION_CAP: u128 = 1_000_000;
/// Bit of `probe_high_water` set once this epoch placed an entry outside
/// its probe routes; lookups that miss the schedule then fall back to a full
/// scan.
const EXCEPTIONAL_PLACEMENT_FLAG: u32 = 1 << 30;
/// Top bit of `probe_high_water`: a walk that finds no key leaves it
/// unresolved. Set with [`EXCEPTIONAL_PLACEMENT_FLAG`], and for its whole
/// life on a table that never settles, whose routes probe nothing.
const WALK_UNRESOLVED_FLAG: u32 = 1 << 31;
/// The bits of `probe_high_water` that are not the high-water mark.
const HIGH_WATER_FLAGS: u32 = EXCEPTIONAL_PLACEMENT_FLAG | WALK_UNRESOLVED_FLAG;
const _: () = assert!(QUERY_POSITION_CAP < EXCEPTIONAL_PLACEMENT_FLAG as u128);

/// `probe_high_water` of a table that has placed nothing, under a scheduler
/// with `settled_limit`.
const fn empty_high_water(settled_limit: usize) -> u32 {
    if settled_limit == 0 {
        WALK_UNRESOLVED_FLAG
    } else {
        0
    }
}
/// Bound on a level's probe index within `QUERY_POSITION_CAP`. Level one
/// reaches the most probes before its positions pass the cap.
const QUERY_PROBE_LIMIT: usize = 384;
/// Largest table: slot positions and schedule bounds are stored as `u32`.
const MAX_ELASTIC_SLOTS: u64 = 1 << u32::BITS;
/// A route summary: the levels the keys of one bin of a metadata word
/// occupy, as [`ElasticRouteFilter::summary`] reads it.
type SummaryBin = u8;
/// Bins a metadata word splits its keys over, by their
/// [`MetadataPlace::summary_bin`]. A bin's summary opens a level for every
/// key of the bin, so the fewer keys share one, the fewer levels a walk
/// visits for nothing.
const SUMMARY_BINS: usize = 8;
const _: () = assert!(SUMMARY_BINS.is_power_of_two());
/// Levels a key's route summary tracks, one bit each above the sentinel's;
/// the last bit stands for every deeper level.
const ROUTE_SUMMARY_LEVELS: usize = SummaryBin::BITS as usize - 1;

/// One word of the metadata tail: the route summaries of its bins, then the
/// membership lane. `repr(C)` keeps the lane in the second machine word.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct TailWord {
    level_bins: [SummaryBin; SUMMARY_BINS],
    membership: u64,
}
/// A stored route summary no level has recorded a key in: every level's bit
/// set, the sentinel's clear.
const NO_LEVELS_OCCUPIED: SummaryBin = !1;
/// Bits each key sets in its membership-filter word. A lookup whose bits are
/// not all set skips the probe walk, since the key cannot be present. Every
/// operation builds and tests the bits, the ones the filter passes too, so a
/// further bit costs each of them and saves only the walks of the absent
/// keys it newly rejects.
const MEMBERSHIP_BITS: usize = 1;
/// Logical slots one metadata word covers. Fewer slots a word leave the
/// filter sparser, so it passes fewer absent keys, and leave each summary
/// fewer keys, so a walk skips more levels; the metadata tail grows in
/// proportion.
const FILTER_SLOTS_PER_WORD: usize = 4;

/// Bits of a [`MetadataPlace`] that pick one bit of a membership lane.
const LANE_BIT_INDEX_BITS: u32 = u64::BITS.trailing_zeros();
/// Bits of a [`MetadataPlace`] below its word index: one lane bit index for
/// each membership bit.
#[allow(clippy::cast_possible_truncation)]
const PLACE_FRACTION_BITS: u32 = LANE_BIT_INDEX_BITS * MEMBERSHIP_BITS as u32;
// A tail has no more words than the largest table has slots, so
// `MetadataPlace::scale` shifts no word count out: the scale of a tail
// with a word is not zero.
const _: () = assert!(MAX_ELASTIC_SLOTS.leading_zeros() >= PLACE_FRACTION_BITS);
const _: () = assert!(MEMBERSHIP_BITS >= 1 && SUMMARY_BINS <= u64::BITS as usize);

/// A key's place in the metadata tail: its word, its membership bits there
/// and its summary bin, all from one multiply-high reduction of the
/// signature. The reduction reads the signature from its top down, so the
/// place shares no signature bit with the control fingerprint, which is the
/// low end, until the tail is wide enough to need them all.
///
/// The word index is the reduction's top; the bits below it, the fraction
/// the word index rounds away, hold one lane bit index for each membership
/// bit; and the summary bin is the top of that fraction.
#[derive(Clone, Copy)]
struct MetadataPlace {
    reduction: u64,
}

impl MetadataPlace {
    /// The multiplier [`Self::new`] takes for a tail of `words` words. A
    /// reduction is below its scale, so every place of the scale has its
    /// word in the tail. No table's word count shifts out, so only an
    /// empty tail has a zero scale.
    #[inline]
    const fn scale(words: usize) -> u64 {
        (words as u64) << PLACE_FRACTION_BITS
    }

    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn new(signature: u64, scale: u64) -> Self {
        Self {
            reduction: ((signature as u128 * scale as u128) >> u64::BITS) as u64,
        }
    }

    /// Index of the key's word, which is below the word count the scale
    /// was made from ([`Self::scale`]), so the cast loses nothing.
    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn word(self) -> usize {
        (self.reduction >> PLACE_FRACTION_BITS) as usize
    }

    /// The key's membership bits of its word's lane. A one-hot shift takes
    /// its distance modulo the lane's width, so each bit reads its own field
    /// of the fraction whatever sits above it.
    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn bits(self) -> u64 {
        let mut bits = 0;
        let mut field = 0;
        while field < PLACE_FRACTION_BITS {
            bits |= 1_u64.wrapping_shl((self.reduction >> field) as u32);
            field += LANE_BIT_INDEX_BITS;
        }
        bits
    }

    /// [`Self::bits`] and their pairs ([`paired_bits`]), built apart from
    /// the bits so an operation that never needs the pair builds neither.
    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn bits_with_pair(self) -> u64 {
        (1 | paired_bits(1)).rotate_left(self.reduction as u32)
    }

    /// The key's bin of its word's summaries.
    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    const fn summary_bin(self) -> usize {
        (self.reduction >> (PLACE_FRACTION_BITS - SUMMARY_BINS.trailing_zeros())) as usize
            & (SUMMARY_BINS - 1)
    }
}

/// Counter base of level zero's first probe, the schedule's direct route.
const H11_COUNTER_BASE: u32 = probe::elastic_counter_base(0, 0);

const _: () = assert!(u32::BITS as u64 <= probe::ELASTIC_LEVEL_LIMIT);
const _: () = assert!(UNIFORM_SEARCH_CAP <= probe::ELASTIC_LOGICAL_LIMIT);
const _: () = {
    let max_case1_logical_probes = ELASTIC_PROBE_BUDGET_C as u64 * (u32::BITS as u64 - 1).pow(2);
    assert!(max_case1_logical_probes <= probe::ELASTIC_LOGICAL_LIMIT);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExactPlacement {
    level: usize,
    slot: usize,
    /// One-based probe of `level` that reached the slot.
    paper_probe: u64,
}

impl ExactPlacement {
    /// Paper position of the chosen slot, `elastic_phi(level + 1, probe)`;
    /// the lookup schedule is extended to cover it.
    fn phi(self) -> u128 {
        let paper_level = u32::try_from(self.level + 1).expect("Elastic level count fits u32");
        probe::elastic_phi_bounded(paper_level, self.paper_probe)
            .map(u128::from)
            .expect("bounded Elastic query coordinate")
    }
}

const _: () = assert!(GENERAL_REDUCTION <= u8::MAX as u32);
const _: () = assert!(UNIFORM_SEARCH_CAP <= u16::MAX as u64);
const _: () = assert!(MAX_LEVELS < SENTINEL_LEVEL as usize);

/// Descriptor for one sub-array `A_i`. Holds metadata + cached pointers
/// into the map-level arena; owns no allocation. The actual ctrl bytes and
/// [`SlotEntry`] data live contiguously in [`ElasticTable::arena`].
#[repr(align(64))]
pub(crate) struct Level<T> {
    /// Cached `arena.as_ptr() + ctrl_offset`, stamped at construction.
    ctrl_ptr: *mut u8,
    /// Cached `arena.as_ptr() + data_offset`, stamped at construction.
    data_ptr: *mut MaybeUninit<T>,
    /// Exact logical slot count. Bounded by the arena layout, so the
    /// level's [`LevelCounters`] fit in `u32` too.
    capacity: u32,
    /// The words a settled insert's search reads of this level.
    search: LevelSearch,
    /// Leading paper probes of this level the lookup schedule covers: a
    /// placement within them needs no schedule extension. Zero for a level
    /// the schedule holds no routes for.
    scheduled_probes: u16,
    /// Case 2's threshold: half the reserve of `capacity`
    /// ([`ReserveFraction::floor_half_reserved`]).
    half_reserve: u32,
    /// [`probe::elastic_level_run`] of this level, beside the fields a
    /// vacancy search reads with it.
    sequence_run: (u32, u32),
}

/// What a settled insert's search reads of a level besides its pointers and
/// its run of the probe sequence. `repr(C)` keeps the two words adjacent, so
/// one paired load brings both.
#[derive(Clone, Copy)]
#[repr(C)]
struct LevelSearch {
    /// [`probe::elastic_index_shift`] of the level's capacity, or
    /// [`GENERAL_REDUCTION`] when any level of the table has no such shift.
    /// A table's levels therefore reduce all by shift or all by the general
    /// reduction, and level zero answers which for the whole table.
    index_shift: u32,
    /// A [`settled_word`].
    settled: u32,
}

/// The countdown of a settled search over `budget` probes, which is not
/// zero, of a level whose bit in a stored route summary is `summary_bit`:
/// the bit in the low half and one under the budget above it. Each probe
/// that finds no free slot takes [`SETTLED_PROBE`] off, and the one that
/// spends the budget borrows, so the search needs no separate count; the
/// low half keeps the summary bit throughout.
#[inline]
const fn settled_word(summary_bit: SummaryBin, budget: u16) -> u32 {
    debug_assert!(budget != 0);
    summary_bit as u32 | ((budget - 1) as u32) << u16::BITS
}

/// One probe of a [`settled_word`]'s budget.
const SETTLED_PROBE: u32 = 1 << u16::BITS;

/// The summary bit of a [`settled_word`], at any point of its countdown.
#[allow(clippy::cast_possible_truncation)]
#[inline]
const fn settled_summary_bit(settled: u32) -> SummaryBin {
    settled as SummaryBin
}

/// A level's live and tombstone counts, stored in the arena directly ahead of
/// the level's control bytes so a walk that holds those reaches the counts
/// without the descriptor.
#[derive(Clone, Copy, Default)]
#[repr(C)]
struct LevelCounters {
    // Ahead of the live count: on a little-endian target that is the order
    // of the halves `LiveCount::entomb_one` moves as one 64-bit value.
    // Elsewhere only its speed differs.
    tombstones: u32,
    len: LiveCount,
}

impl LevelCounters {
    /// Counts one live entry turned into a tombstone.
    #[inline]
    fn remove_one(&mut self) {
        self.len.entomb_one(&mut self.tombstones);
    }
}

/// The counters of the level whose control bytes start at `control`.
///
/// # Safety
///
/// `control` is the control pointer of a level stamped by
/// [`build_elastic_levels`].
#[inline]
unsafe fn level_counters(control: *mut u8) -> *mut LevelCounters {
    // SAFETY: the caller's contract; the counters sit in the same arena.
    #[allow(clippy::cast_ptr_alignment)]
    unsafe {
        control.sub(size_of::<LevelCounters>()).cast()
    }
}

/// A level's bit in a stored route summary.
const fn summary_bit(level: usize) -> SummaryBin {
    2 << summary_level(level)
}

/// Control-section bytes the counters of `levels` levels take at most,
/// padding included.
const fn counter_bytes(levels: usize) -> usize {
    levels * (size_of::<LevelCounters>() + align_of::<LevelCounters>() - 1)
}

/// [`Level::index_shift`] of every level in a table that has a level whose
/// probes need the general range reduction.
const GENERAL_REDUCTION: u32 = u64::BITS;

// SAFETY: the raw pointers address slots this descriptor's table owns
// exclusively, like `Box<[T]>`; no shared interior state outlives the borrow.
unsafe impl<T: Send> Send for Level<T> {}
// SAFETY: as above; `&Level` only permits reads of `T` through the pointers.
unsafe impl<T: Sync> Sync for Level<T> {}

// A level fills one cache line, so an insert reads its whole descriptor from
// one line and indexes the levels by shift.
const _: () = assert!(mem::size_of::<Level<SlotEntry<u64, u64>>>() == 64);

// SAFETY: descriptors are only stamped at offsets carved from an arena
// that `elastic_arena_layout` sized for every level's `capacity` ctrl bytes
// and slots besides its counters, whose ctrl bytes
// `try_allocate_with_ctrl_zeroed` starts EMPTY, and are dropped or
// re-stamped before that arena is freed.
unsafe impl<T> ArenaSlots<T> for Level<T> {
    #[inline]
    fn ctrl_ptr(&self) -> *mut u8 {
        self.ctrl_ptr
    }
    #[inline]
    fn data_ptr(&self) -> *mut MaybeUninit<T> {
        self.data_ptr
    }
    #[inline]
    fn capacity(&self) -> usize {
        self.capacity as usize
    }
}

impl<T> Level<T> {
    /// Stamps a fresh descriptor at the given arena ptrs.
    /// Caller advances the offset cursor.
    fn new_at(
        level: usize,
        cap_u32: u32,
        reserve_fraction: ReserveFraction,
        index_shift: u32,
        ctrl_ptr: *mut u8,
        data_ptr: *mut MaybeUninit<T>,
    ) -> Self {
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap_u32,
            search: LevelSearch {
                index_shift,
                settled: settled_word(summary_bit(level), 1),
            },
            scheduled_probes: 0,
            // At most the capacity, which fits.
            #[allow(clippy::cast_possible_truncation)]
            half_reserve: reserve_fraction.floor_half_reserved(cap_u32 as usize) as u32,
            sequence_run: probe::elastic_level_run(level),
        }
    }

    #[inline]
    fn counters(&self) -> &LevelCounters {
        // SAFETY: every level's control bytes follow its counters in the
        // arena, aligned for them, and the table that owns the arena is
        // borrowed for as long as the level.
        unsafe { &*level_counters(self.ctrl_ptr) }
    }

    #[inline]
    fn counters_mut(&mut self) -> &mut LevelCounters {
        // SAFETY: as in `counters`, and `&mut self` borrows the level alone.
        unsafe { &mut *level_counters(self.ctrl_ptr) }
    }

    #[inline]
    fn tombstones(&self) -> u32 {
        self.counters().tombstones
    }

    #[inline]
    fn index_shift(&self) -> u32 {
        self.search.index_shift
    }

    /// This level's bit in a stored route summary, one above its
    /// [`summary_level`]: clear once the level holds a key of the summary's
    /// bin.
    #[inline]
    fn summary_bit(&self) -> SummaryBin {
        settled_summary_bit(self.search.settled)
    }

    /// Slots minus the `live` entries (includes tombstones, reusable on insert).
    #[inline]
    fn free_slots(&self, live: u32) -> usize {
        (self.capacity - live) as usize
    }

    /// Case 2's test on the active pair's current level, which holds `live`
    /// entries: at most half its reserve is left, so new keys go to the next level.
    #[inline]
    fn low(&self, live: u32) -> bool {
        self.capacity - live <= self.half_reserve
    }

    /// Tombstones exceed [`capacity::tombstone_cleanup_threshold`], so the
    /// table owes a same-size cleanup epoch: at its next delete maintenance,
    /// or at the insert after one that reuses a tombstone of this level.
    #[inline]
    fn needs_cleanup(&self) -> bool {
        self.tombstones() as usize > capacity::tombstone_cleanup_threshold(self.capacity as usize)
    }

    /// Moves every live entry out through `visit` and resets the level to
    /// empty. Each moved slot becomes a counted tombstone before `visit`
    /// runs, and controls return to `EMPTY` only after the last entry, so a
    /// panic inside `visit` leaves the level as a run of removals would: the
    /// entries not yet visited stay live and counted, and no `EMPTY` slot
    /// appears ahead of one on its probe route.
    fn drain_reset(&mut self, mut visit: impl FnMut(T)) {
        let mut scan = OccupiedIndices::new();
        while let Some(slot) = scan.step(self) {
            // SAFETY: `step` yields occupied in-bounds slots; the value is
            // moved out before the slot is marked.
            let entry = unsafe { self.take(slot) };
            // SAFETY: `slot` is in bounds, as above.
            unsafe { self.mark_tombstone(slot) };
            self.counters_mut().remove_one();
            visit(entry);
        }
        self.clear_all_controls();
        self.counters_mut().tombstones = 0;
    }
}

/// Open-addressed elastic-hashing backend for the generic [`map::HashMap`]
/// shell. See [`ElasticHashMap`] for the public map type.
///
/// Splits capacity across geometrically shrinking `levels` and routes inserts
/// through a `batch_plan`: early batches concentrate on level 0; later
/// batches push toward deeper levels. Lookups walk a precomputed probe
/// schedule, skipping levels the route summary rules out.
///
/// Placement uses the paper's exact level schedule and uniform per-level
/// probes. Query positions are compressed without changing their order.
///
/// `repr(C)` fixes the field order, which puts words an operation reads or
/// writes together next to each other so one paired access covers both: the
/// settled level and the fold multiplier, the fold multiplier and the
/// schedule's direct route, the filter's word count and its first word, the
/// placed count and the settled bound.
#[repr(C)]
pub struct ElasticTable<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    /// `ctrl_L0|ctrl_L1|...`, padding, then `slots_L0|slots_L1|...`.
    arena: Arena,
    /// The level a settled insert searches, with that level's settled
    /// budget, while the scheduler's gate is open; [`Self::reopen_settled`]
    /// sets both as it opens the gate. Not read while the gate is closed.
    /// It is [`Levels::level_ptr`] of the level, so borrows of the levels
    /// leave it good to read through.
    settled_level: *mut Level<SlotEntry<K, V>>,
    /// [`probe::ELASTIC_FOLD_MULTIPLIER`], kept in the table so the hot
    /// paths load it rather than build it.
    fold_multiplier: u64,
    probe_schedule: ProbeSchedule,
    /// The level a settled insert searches after `settled_level`, with its
    /// own settled budget, or null where the plan has no such level. Set
    /// and read as `settled_level` is.
    settled_fallback: *mut Level<SlotEntry<K, V>>,
    /// Cached location of the metadata tail. See [`MembershipRegion`].
    membership: MembershipRegion,
    /// [`MetadataPlace::scale`] of the tail's word count, so the gate reads
    /// its multiplier ready made.
    metadata_scale: u64,
    /// First word of the metadata tail, so the gate's address needs one load;
    /// [`NO_METADATA`] while `membership` has no words.
    metadata_words: *mut TailWord,
    /// Live entries plus the removals the scheduler's countdown has counted,
    /// so a removal moves the countdown alone. [`Self::live`] is the live
    /// count.
    placed: usize,
    /// Schedule batch progression and epoch boundaries.
    scheduler: BatchScheduler,
    levels: LevelSlice<K, V>,
    total_slots: usize,
    /// Fixed for the allocation. The scheduler's settled limit is taken from
    /// it once, when the two are built ([`settled_limit`]).
    max_insertions: usize,
    epoch: EpochState,
    reserve_fraction: ReserveFraction,
    probe_high_water: u32,
    /// Levels the schedule holds routes for: every level up to the deepest
    /// one a placement of this epoch chose. A deeper level holds no entry, so
    /// lookups have nothing to visit there.
    scheduled_levels: u32,
    /// The settled inserts `settled_level`'s stored live count lacks.
    uncounted: Uncounted,
    hash_builder: S,
    alloc: A,
}

const _: () = {
    type Table = ElasticTable<(), ()>;
    let word = size_of::<usize>();
    assert!(
        mem::offset_of!(Table, fold_multiplier) == mem::offset_of!(Table, settled_level) + word
            && mem::offset_of!(Table, probe_schedule)
                == mem::offset_of!(Table, fold_multiplier) + size_of::<u64>()
            && mem::offset_of!(Table, metadata_words)
                == mem::offset_of!(Table, metadata_scale) + size_of::<u64>()
            && mem::offset_of!(Table, scheduler) == mem::offset_of!(Table, placed) + word
            && mem::offset_of!(BatchScheduler, settled_end) == 0
            && mem::offset_of!(BatchScheduler, deletes_left) == word
    );
};

// SAFETY: the table uniquely owns its arena and every entry in it, like
// `Box<[SlotEntry<K, V>]>`. Its raw pointers address that arena, except:
// the schedule's walk starts, which address the routes the schedule owns
// and the table of them it owns;
// `settled_level` and `settled_fallback`, which address the table's own
// levels and are read only through an exclusive borrow of the table;
// the schedule's sentinel route and, in a table without a metadata tail,
// `metadata_words`, which address the immutable statics `SENTINEL_CONTROL`
// and `NO_METADATA` and are only read; and the schedule's entry origin,
// which is an address to offset from and is never read: it lies outside
// the arena, and is null without levels.
unsafe impl<K: Send, V: Send, S: Send, A: Allocator + Clone + Send> Send
    for ElasticTable<K, V, S, A>
{
}
// SAFETY: as above; slots are mutated only under an exclusive borrow of the
// owning map, so `&ElasticTable` only reads.
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for ElasticTable<K, V, S, A>
{
}

/// A free slot of a level, with the level's words a write of it reads.
struct SettledSlot<K, V> {
    level: *mut Level<SlotEntry<K, V>>,
    control_bytes: *mut u8,
    data: *mut MaybeUninit<SlotEntry<K, V>>,
    /// [`Level::summary_bit`] of `level`.
    summary_bit: SummaryBin,
    slot: usize,
    /// The slot's control byte, sign-extended.
    control: i32,
}

/// Control byte `slot` of the bytes at `control`, sign-extended, so an
/// occupied byte is negative. On 64-bit `AArch64` the load is opaque to the
/// compiler, which then tests the bits of the register as it is.
///
/// # Safety
///
/// `slot` is in bounds of the control bytes at `control`.
#[inline]
unsafe fn signed_control(control: *const u8, slot: usize) -> i32 {
    #[cfg(all(target_arch = "aarch64", target_pointer_width = "64", not(miri)))]
    {
        let byte: i32;
        // SAFETY: the caller's contract; the load only reads.
        unsafe {
            core::arch::asm!(
                "ldrsb {byte:w}, [{control}, {slot}]",
                control = in(reg) control,
                slot = in(reg) slot,
                byte = lateout(reg) byte,
                options(pure, readonly, nostack, preserves_flags),
            );
        }
        byte
    }
    #[cfg(not(all(target_arch = "aarch64", target_pointer_width = "64", not(miri))))]
    // SAFETY: the caller's contract.
    i32::from(unsafe { control.add(slot).read() }.cast_signed())
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for ElasticTable<K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ElasticTable").finish_non_exhaustive()
    }
}

impl<K, V, S, A: Allocator + Clone> Drop for ElasticTable<K, V, S, A> {
    fn drop(&mut self) {
        let levels = &mut self.levels;
        self.arena
            .drop_table(&self.alloc, || arena::RegionSet::drop_all_values(levels));
    }
}

macros::declare_backend_aliases! {
    table = ElasticTable,
    map_no_lifetime {
        /// Open-addressed hash map using elastic hashing.
        ///
        /// # Examples
        ///
        /// ```
        /// use opthash::ElasticHashMap;
        ///
        /// let mut stock = ElasticHashMap::with_capacity(16);
        /// stock.insert("apples", 3);
        /// *stock.entry("pears").or_insert(0) += 5;
        ///
        /// assert_eq!(stock.get("apples"), Some(&3));
        /// assert_eq!(stock.remove("pears"), Some(5));
        /// assert_eq!(stock.len(), 1);
        /// ```
        ElasticHashMap => HashMap,
        /// Consuming iterator over owned `(K, V)`.
        ElasticIntoIter => IntoIter,
        /// Owned `K` iterator.
        ElasticIntoKeys => IntoKeys,
        /// Owned `V` iterator.
        ElasticIntoValues => IntoValues,
    },
    map_ref {
        /// A view into a single entry, occupied or vacant.
        ElasticEntry => Entry,
        /// View of an occupied entry.
        ElasticOccupiedEntry => OccupiedEntry,
        /// View of a vacant entry.
        ElasticVacantEntry => VacantEntry,
        /// Error returned by `try_insert` on key collision.
        ElasticOccupiedError => OccupiedError,
        /// Borrowing iterator over `(&K, &V)`.
        ElasticIter => Iter,
        /// Borrowing iterator over `(&K, &mut V)`.
        ElasticIterMut => IterMut,
        /// `&K` iterator.
        ElasticKeys => Keys,
        /// `&V` iterator.
        ElasticValues => Values,
        /// `&mut V` iterator.
        ElasticValuesMut => ValuesMut,
        /// Draining iterator that empties the map.
        ElasticDrain => Drain,
    },
    map_extract_if {
        /// Iterator yielding entries removed by `extract_if`.
        ElasticExtractIf
    },
    set_no_lifetime {
        /// Hash set using elastic hashing.
        ///
        /// # Examples
        ///
        /// ```
        /// use opthash::ElasticHashSet;
        ///
        /// let evens: ElasticHashSet<u32> = (0..10).step_by(2).collect();
        /// let small: ElasticHashSet<u32> = (0..5).collect();
        ///
        /// let mut both: Vec<_> = evens.intersection(&small).copied().collect();
        /// both.sort_unstable();
        /// assert_eq!(both, [0, 2, 4]);
        /// ```
        ElasticHashSet => HashSet,
        /// Consuming iterator over set values.
        ElasticSetIntoIter => IntoIter,
    },
    set_ref {
        /// Borrowing iterator over set values.
        ElasticSetIter => Iter,
        /// Draining iterator that empties the set.
        ElasticSetDrain => Drain,
        /// Iterator over values present only in the first set.
        ElasticDifference => Difference,
        /// Iterator over values present in both sets.
        ElasticIntersection => Intersection,
        /// Iterator over values present in exactly one set.
        ElasticSymmetricDifference => SymmetricDifference,
        /// Iterator over values present in either set.
        ElasticUnion => Union,
        /// A view into a single set entry.
        ElasticSetEntry => Entry,
        /// View of an occupied set entry.
        ElasticSetOccupiedEntry => OccupiedEntry,
        /// View of a vacant set entry.
        ElasticSetVacantEntry => VacantEntry,
    },
    set_extract_if {
        /// Iterator yielding values removed by set `extract_if`.
        ElasticSetExtractIf
    },
}

/// Boxed slice of levels for one `(K, V)` parameterization.
type LevelSlice<K, V> = Levels<SlotEntry<K, V>>;

/// A boxed slice of levels held by its raw pointer.
///
/// Every borrow of the levels is taken from that pointer and
/// [`Self::level_ptr`] is that pointer offset, so a level's address stays
/// good to read through for as long as the slice is owned here, whatever
/// borrows of the levels come and go in between.
struct Levels<T> {
    first: ptr::NonNull<Level<T>>,
    len: usize,
}

impl<T> Levels<T> {
    /// Level `index`, addressed from the pointer the slice is held by.
    #[inline]
    fn level_ptr(&self, index: usize) -> *mut Level<T> {
        assert!(index < self.len);
        // SAFETY: `index` is in bounds of the slice at `first`.
        unsafe { self.first.as_ptr().add(index) }
    }
}

impl<T> From<Box<[Level<T>]>> for Levels<T> {
    fn from(levels: Box<[Level<T>]>) -> Self {
        let len = levels.len();
        let first = ptr::NonNull::from(Box::leak(levels)).cast();
        Self { first, len }
    }
}

impl<T> Drop for Levels<T> {
    fn drop(&mut self) {
        let levels = ptr::slice_from_raw_parts_mut(self.first.as_ptr(), self.len);
        // SAFETY: `from` took these levels out of a box of this length.
        drop(unsafe { Box::from_raw(levels) });
    }
}

impl<T> core::ops::Deref for Levels<T> {
    type Target = [Level<T>];

    #[inline]
    fn deref(&self) -> &Self::Target {
        // SAFETY: `first` addresses `len` levels this owns, which nothing
        // writes while `self` is borrowed shared.
        unsafe { core::slice::from_raw_parts(self.first.as_ptr(), self.len) }
    }
}

impl<T> core::ops::DerefMut for Levels<T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: as in `deref`, and `self` is borrowed alone.
        unsafe { core::slice::from_raw_parts_mut(self.first.as_ptr(), self.len) }
    }
}

impl<'a, T> IntoIterator for &'a Levels<T> {
    type Item = &'a Level<T>;
    type IntoIter = core::slice::Iter<'a, Level<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Levels<T> {
    type Item = &'a mut Level<T>;
    type IntoIter = core::slice::IterMut<'a, Level<T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

// SAFETY: this owns its levels as the box it was made from does.
unsafe impl<T> Send for Levels<T> where Box<[Level<T>]>: Send {}
// SAFETY: as above.
unsafe impl<T> Sync for Levels<T> where Box<[Level<T>]>: Sync {}
/// A fresh arena, its level descriptors, and the metadata tail they share.
type ElasticArenaBuild<K, V> = (Arena, LevelSlice<K, V>, MembershipRegion);

struct ElasticArenaLayout {
    layout: Layout,
    data_base_off: usize,
    membership: MembershipRegion,
}

fn elastic_arena_layout<K, V>(
    total_slots: usize,
    levels: usize,
) -> Result<ElasticArenaLayout, TryReserveError> {
    let ctrl_bytes = total_slots
        .checked_add(counter_bytes(levels))
        .ok_or(TryReserveError::CapacityOverflow)?;
    let (base_layout, data_base_off) = arena::layout_for_extents::<K, V>(ctrl_bytes, ctrl_bytes)?;
    let (layout, membership) =
        MembershipRegion::extend::<TailWord>(base_layout, total_slots, FILTER_SLOTS_PER_WORD)?;
    Ok(ElasticArenaLayout {
        layout,
        data_base_off,
        membership,
    })
}

#[derive(Clone, Copy)]
struct PreparedElasticRoute {
    probe: PreparedElasticProbe,
}

impl PreparedElasticRoute {
    #[inline]
    fn new(hash: u64) -> Self {
        Self {
            probe: CounterPrf::new(ELASTIC_PROBE_SEED).prepare_elastic(hash),
        }
    }

    #[inline]
    const fn signature(self) -> u64 {
        self.probe.routing_signature()
    }

    /// The hash [`Self::new`] took, so a callee handed the route needs no
    /// second copy of it.
    #[inline]
    const fn key_hash(self) -> u64 {
        self.signature() ^ ELASTIC_PROBE_SEED
    }
}

const _: () = assert!(mem::size_of::<PreparedElasticRoute>() == 8);

/// Marks the path that reaches it as the unlikely one of its branch.
#[cold]
#[inline]
const fn unlikely_path() {}

/// The key of the entry a walk found at `entry`, read as an address that is
/// not zero, so a caller that hands the entry on tests it for nothing.
///
/// # Safety
///
/// `entry` is an occupied slot of a live level, and nothing writes its key
/// while the borrow lasts.
#[inline]
unsafe fn found_key<'k, K, V>(entry: *mut SlotEntry<K, V>) -> &'k K {
    // SAFETY: a slot of an allocation is not at address zero, and the
    // caller's contract covers the read.
    unsafe {
        core::hint::assert_unchecked(!entry.is_null());
        &(*entry).key
    }
}

/// Outcome of [`ElasticTable::walk_schedule`].
enum ScheduleSearch<R> {
    Hit(R),
    Absent,
    /// The walk could not decide: the key is where
    /// [`ElasticTable::find_by_general_schedule`] finds it, or absent.
    Unresolved,
}

/// A key's place in a table's metadata tail and its word's membership lane
/// as [`ElasticTable::route_filter`] read it, for an insert to record over
/// without reducing the key or reading the word again.
#[derive(Clone, Copy)]
struct LaneRead {
    place: MetadataPlace,
    lane: u64,
    /// The bits an insert of the key sets in the lane.
    bits: u64,
}

/// The lane bit paired with each bit of `bits`. A key recorded while its
/// bit is already set sets the pair's too, so a bit whose pair is clear
/// belongs to one live key at most, and the removal of that key may clear
/// it ([`ElasticTable::forget_membership`]).
///
/// The pairing is an involution: a bit is cleared only while its pair is
/// clear, when no live key has the pair for its own bit and so none counts
/// on the cleared bit as its mark.
#[inline]
const fn paired_bits(bits: u64) -> u64 {
    bits.rotate_right(u64::BITS / 2)
}
// One bit a key, so a key's bit and its pair are two bits of the lane.
const _: () = assert!(MEMBERSHIP_BITS == 1);

/// The metadata word of one prepared key and its membership answer.
#[derive(Clone, Copy)]
struct ElasticRouteFilter<'a> {
    /// `false` proves no insert ever recorded this key's route.
    maybe_present: bool,
    read: LaneRead,
    word: &'a TailWord,
}

impl ElasticRouteFilter<'_> {
    /// The read an insert of the key records over: the key's bit, and its
    /// pair's ([`paired_bits`]) when the lane already holds the key's.
    #[inline]
    fn recording(self) -> LaneRead {
        let LaneRead { place, lane, bits } = self.read;
        LaneRead {
            place,
            lane,
            bits: bits | paired_bits(lane & bits),
        }
    }

    /// Summary bits of the levels `route`'s bin has occupied. Bit `i` covers
    /// level `i` for `i < ROUTE_SUMMARY_LEVELS - 1`; the last bit is
    /// saturating and covers every deeper level. Read apart from the
    /// membership answer, so a lookup that ends before it narrows its levels
    /// does not load them.
    #[inline]
    fn level_mask(self) -> SummaryBin {
        !self.word.level_bins[self.read.place.summary_bin()] >> 1
    }

    /// The stored summary of the bin, which keeps the levels the bin never
    /// occupied set. A schedule walk starts from it
    /// ([`ProbeSchedule::walk_start`]) and closes its levels
    /// ([`schedule::closed_levels`]).
    #[inline]
    fn summary(self) -> SummaryBin {
        self.word.level_bins[self.read.place.summary_bin()]
    }

    /// [`Self::level_mask`] widened by [`expand_level_mask`].
    #[inline]
    fn expanded_level_mask(self) -> u64 {
        expand_level_mask(self.level_mask())
    }
}

/// Widens the saturating last summary bit over every level index it stands
/// for, so a lookup tests `1 << level` directly instead of clamping the
/// level on each schedule step.
#[inline]
const fn expand_level_mask(level_mask: SummaryBin) -> u64 {
    // The last bit moves to the sign, extends, and moves back.
    (((level_mask << 1).cast_signed() as i64) >> 1).cast_unsigned()
}

/// Maps a level index onto its route-summary bit. Levels past the summary's
/// width share the last bit, so a wide geometry still narrows every shallow
/// level instead of disabling the summary outright.
#[inline]
const fn summary_level(level: usize) -> usize {
    if level < ROUTE_SUMMARY_LEVELS - 1 {
        level
    } else {
        ROUTE_SUMMARY_LEVELS - 1
    }
}

/// Full probe-schedule length per level count, computed at compile time so
/// construction, resize, and clone size the schedule without walking every
/// level's probes.
const PROBE_SCHEDULE_CAPACITY: [usize; MAX_LEVELS + 1] = {
    let mut capacities = [0; MAX_LEVELS + 1];
    let mut level = 0;
    while level < MAX_LEVELS {
        capacities[level + 1] = capacities[level] + level_route_count(level);
        level += 1;
    }
    capacities
};

/// Paper probes a lookup can reach in each level: those with
/// `phi <= QUERY_POSITION_CAP`, within `UNIFORM_SEARCH_CAP`. Placement stops
/// there, so a vacancy past the cap counts as a failed probe.
const LEVEL_PROBE_LIMIT: [u64; MAX_LEVELS] = {
    let mut limits = [0; MAX_LEVELS];
    let mut level = 0;
    while level < MAX_LEVELS {
        // `level_route_count` skips level 0's first probe, which the
        // direct-slot fast path covers.
        let first_probe_skipped = if level == 0 { 1 } else { 0 };
        limits[level] = (level_route_count(level) + first_probe_skipped) as u64;
        level += 1;
    }
    limits
};

/// Routes a full schedule holds for `level`: its probes at positions up to
/// `QUERY_POSITION_CAP`, within `UNIFORM_SEARCH_CAP` probes, less level
/// zero's first, which is the direct slot.
const fn level_route_count(level: usize) -> usize {
    let paper_level = level as u128 + 1;
    let mut paper_probe = if level == 0 { 2 } else { 1 };
    let mut count = 0;
    while paper_probe <= UNIFORM_SEARCH_CAP as u128 {
        let Ok(phi) = probe::elastic_phi(paper_level, paper_probe) else {
            panic!("bounded Elastic query coordinate");
        };
        if phi > QUERY_POSITION_CAP {
            break;
        }
        count += 1;
        paper_probe += 1;
    }
    count
}

/// [`BatchScheduler`]'s settled limit for a table of `levels` that takes
/// `max_insertions` entries over `batches` batches and records its keys in
/// `membership`: zero unless level zero reduces by shift, every batch's
/// level pair lies inside `levels`, and the filter has a word to record in.
fn settled_limit<T>(
    levels: &[Level<T>],
    batches: usize,
    membership: MembershipRegion,
    max_insertions: usize,
) -> usize {
    match levels.first() {
        Some(level)
            if level.index_shift() != GENERAL_REDUCTION
                && batches <= levels.len()
                && membership.words != 0 =>
        {
            max_insertions
        }
        _ => 0,
    }
}

/// Schedule paper batches and allocation-epoch boundaries.
///
/// The active batch is a function of the live count alone: batch `i` covers
/// positions in `[batch_ends[i-1], batch_ends[i])`, the prefix-sum test the
/// scalar oracle applies, so under deletion it tracks occupancy rather than
/// an insert tally.
///
/// It also counts removals, in the word next to the gate a removal closes:
/// `repr(C)` keeps the two adjacent, so a removal writes both together. It
/// also keeps the gate first, next to the placed count an insert reads with
/// it.
#[derive(Clone)]
#[repr(C)]
pub(crate) struct BatchScheduler {
    /// Exclusive bound of the cached batch's settled inserts, on the table's
    /// placed count: the lower of `batch_end` and `settled_limit` plus the
    /// removals the placed count still holds, or less where the
    /// [`SettledPlan`] it opened on ends sooner, or zero since a removal or
    /// a re-sync. Every path that lowers the table's live count or changes
    /// those removals, and every insert that is not a settled one, closes it
    /// through [`Self::note_removal`] or [`Self::close`], or re-syncs the
    /// batch, and only the table raises it, to a plan's end and no further
    /// than [`Self::reopened_end`], so a placed count under this bound is a
    /// live count inside the cached batch that only settled inserts reached
    /// since the gate opened.
    settled_end: usize,
    /// Removals the table's filter still tolerates, counted down from
    /// [`membership::refresh_deletes`] less one, so the removal that
    /// spends the last one takes it negative as a signed count: maintenance
    /// is due then, and the test is its sign bit. A scan's removals may take
    /// it further down before the scan can settle.
    deletes_left: usize,
    /// Live count below which [`ElasticTable::settled_level_slot`] can place: the
    /// table's insertion limit, or zero where [`settled_limit()`] rules a
    /// settled insert out.
    settled_limit: usize,
    /// `batch_ends[current_batch_index - 1]`, or zero for the first batch.
    batch_start: usize,
    /// `batch_ends[current_batch_index]`, or `usize::MAX` for an empty plan.
    batch_end: usize,
    /// Cumulative quota through each batch: the exclusive `len` bound at
    /// which the batch ends. Zero-quota batches repeat the previous end.
    batch_ends: Box<[usize]>,
    current_batch_index: usize,
}

/// The level and probe budget the paper's insertion case gives a table's next
/// new key, and how long they stay its choice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SettledPlan {
    level: usize,
    /// Probes of `level` to search, none past its scheduled ones. Not zero.
    budget: u16,
    /// Probes of the level after `level` to search when those find no free
    /// slot, none past its scheduled ones and not zero: `Some` where the
    /// insertion case falls back to that level and `budget` is the whole of
    /// the case's own, so the search of `level` it ends is the case's.
    fallback: Option<u16>,
    /// Exclusive bound on the placed count of the inserts the plan holds
    /// for, while each of them is a settled one.
    end: usize,
}

/// The first free slot among the probes `settled` counts of `level`, in
/// probe order.
///
/// # Safety
///
/// `level` is a level of a table that is not marked
/// [`GENERAL_REDUCTION`], and `settled` is a [`settled_word`] of it.
#[allow(clippy::inline_always)]
#[inline(always)]
unsafe fn first_settled_vacancy<K, V>(
    sequence: probe::ElasticProbeSequence,
    level: *mut Level<SlotEntry<K, V>>,
    settled: u32,
) -> Option<SettledSlot<K, V>> {
    // SAFETY: the caller's contract.
    let (index_shift, control, data, run) = unsafe {
        (
            (*level).search.index_shift,
            (*level).ctrl_ptr,
            (*level).data_ptr,
            (*level).sequence_run,
        )
    };
    debug_assert!(index_shift < u64::BITS);
    // SAFETY: a shift other than `GENERAL_REDUCTION` is
    // `probe::elastic_index_shift` of the capacity, below the word width.
    unsafe { core::hint::assert_unchecked(index_shift < u64::BITS) };
    let (mut word, word_step) = sequence.run_words(run);
    let mut countdown = settled;
    loop {
        let slot = probe::shifted_elastic_index(word, index_shift);
        // SAFETY: the level's shift maps the index into its capacity.
        let byte = unsafe { signed_control(control, slot) };
        if byte >= 0 {
            return Some(SettledSlot {
                level,
                control_bytes: control,
                data,
                summary_bit: settled_summary_bit(countdown),
                slot,
                control: byte,
            });
        }
        word = word.wrapping_add(word_step);
        let spent;
        (countdown, spent) = countdown.overflowing_sub(SETTLED_PROBE);
        if spent {
            return None;
        }
    }
}

/// One of the paper's insertion cases, resolved against a table's levels.
struct PlacementCase<'a, K, V> {
    /// The level to search first.
    level: usize,
    region: &'a Level<SlotEntry<K, V>>,
    /// Probes of `level` to search.
    budget: u64,
    /// The level to search when the budget finds no slot.
    fallback: Option<usize>,
    /// `level` has no free slot by its counts, so no search of it finds one.
    full: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BatchTarget {
    Bootstrap,
    LevelPair(usize),
}

impl BatchScheduler {
    pub(crate) fn new(batch_plan: &[usize], settled_limit: usize, delete_budget: usize) -> Self {
        let mut total = 0_usize;
        let batch_ends = batch_plan
            .iter()
            .map(|&quota| {
                total = total.saturating_add(quota);
                total
            })
            .collect::<Box<[usize]>>();
        let mut scheduler = Self {
            batch_ends,
            current_batch_index: 0,
            batch_start: 0,
            batch_end: usize::MAX,
            settled_limit,
            deletes_left: Self::countdown_start(delete_budget),
            settled_end: 0,
        };
        scheduler.reset();
        scheduler
    }

    /// The cached batch is current for the live entries of a table at
    /// `placed`, and their count is below the settled limit. One compare,
    /// which [`Self::note_removal`] keeps sound for a live count that falls
    /// back under the cached batch.
    #[inline]
    fn settles(&self, placed: usize) -> bool {
        placed < self.settled_end
    }

    /// Records a removal: counts it and closes the settled gate, whatever
    /// the live count, with no test of where the count fell.
    #[inline]
    fn note_removal(&mut self) {
        self.deletes_left = self.deletes_left.wrapping_sub(1);
        self.settled_end = 0;
    }

    /// Closes the settled gate for a change of the placed count that is not
    /// a counted removal.
    #[inline]
    fn close(&mut self) {
        self.settled_end = 0;
    }

    /// Starts the removal countdown over from `budget`. The removals a
    /// placed count holds change with it, so the gate closes.
    #[inline]
    fn rearm(&mut self, budget: usize) {
        self.deletes_left = Self::countdown_start(budget);
        self.close();
    }

    /// Removals reached the budget the countdown started from.
    #[inline]
    fn maintenance_is_due(&self) -> bool {
        self.deletes_left.cast_signed() < 0
    }

    /// One more removal makes [`Self::maintenance_is_due`].
    #[inline]
    fn next_removal_is_due(&self) -> bool {
        self.deletes_left.wrapping_sub(1).cast_signed() < 0
    }

    /// Removals counted since the countdown started from `budget`.
    #[inline]
    fn removed(&self, budget: usize) -> usize {
        Self::countdown_start(budget).wrapping_sub(self.deletes_left)
    }

    /// Where a countdown of `budget` removals starts: one under the budget,
    /// so the last of them leaves it negative. A table with no budget holds
    /// no key to remove.
    #[inline]
    fn countdown_start(budget: usize) -> usize {
        budget.wrapping_sub(1)
    }

    /// Reopens a closed gate while the cached batch still covers the live
    /// entries of a table at `placed`, `removed` of which have left, and
    /// reports whether that table settles.
    #[cfg(test)]
    fn reopen(&mut self, placed: usize, removed: usize) -> bool {
        if let Some(end) = self.reopened_end(placed, removed) {
            self.settled_end = end;
        }
        self.settles(placed)
    }

    /// The highest bound the gate may reopen to: `None` while the cached
    /// batch does not cover the live entries.
    #[inline]
    fn reopened_end(&self, placed: usize, removed: usize) -> Option<usize> {
        self.covers(placed - removed)
            .then(|| self.batch_end.min(self.settled_limit) + removed)
    }

    /// Counts an insert into one of `level`'s tombstones. In a level past
    /// its cleanup threshold it also leaves no live count covered or
    /// settled, so the next insert re-syncs off the settled path.
    #[cold]
    #[inline(never)]
    fn reuse_tombstone<T>(&mut self, level: &mut Level<T>) {
        // The threshold is at least half the level, a cheaper test.
        if level.tombstones() > level.capacity / 2 && level.needs_cleanup() {
            self.batch_end = 0;
            self.settled_end = 0;
        }
        level.counters_mut().tombstones -= 1;
    }

    /// [`Self::reopen`] on a copy: whether an insert into that table
    /// settles.
    #[cfg(test)]
    fn would_settle(&self, placed: usize, removed: usize) -> bool {
        self.clone().reopen(placed, removed)
    }

    /// [`Self::target`] on a copy, for assertions through a shared borrow.
    #[cfg(test)]
    fn target_at(&self, len: usize) -> BatchTarget {
        self.clone().target(len)
    }

    /// Distinguish bootstrap placement from the level pair for later batches,
    /// for a table holding `len` live entries. Re-syncs the cached batch when
    /// `len` has left its window; the common case is two compares.
    #[inline]
    fn target(&mut self, len: usize) -> BatchTarget {
        if !self.covers(len) {
            self.sync(len);
        }
        self.cached_target()
    }

    /// The cached batch is the one a table holding `len` live entries is in.
    #[inline]
    fn covers(&self, len: usize) -> bool {
        len < self.batch_end && len >= self.batch_start
    }

    /// The target of the cached batch, which may trail `len` until the next
    /// [`Self::target`] re-syncs it.
    #[inline]
    fn cached_target(&self) -> BatchTarget {
        if self.current_batch_index == 0 {
            BatchTarget::Bootstrap
        } else {
            BatchTarget::LevelPair(self.current_batch_index - 1)
        }
    }

    /// Move the cached window to the batch covering `len`. Zero-quota batches
    /// are never selected because their window is empty. Beyond the last end,
    /// the last batch stays active.
    #[cold]
    #[inline(never)]
    fn sync(&mut self, len: usize) {
        let ends = &self.batch_ends;
        if ends.is_empty() {
            return;
        }
        let index = ends.partition_point(|&end| end <= len).min(ends.len() - 1);
        self.current_batch_index = index;
        self.batch_start = if index == 0 { 0 } else { ends[index - 1] };
        self.batch_end = ends[index];
        self.settled_end = 0;
    }

    /// Reset batch progress after resize or clear.
    #[inline]
    pub(crate) fn reset(&mut self) {
        self.sync(0);
    }
}

/// Most levels, and most batch quotas, any Elastic geometry can have: a table
/// holds at most `MAX_ELASTIC_SLOTS = 2^32` slots and the paper uses
/// `ceil(log2(n))` levels with one quota each.
const MAX_LEVELS: usize = u32::BITS as usize;

/// A geometry's level lengths or batch quotas, held on the stack so building
/// or resizing a table allocates only what the table keeps.
#[derive(Clone, Copy)]
struct PlanBuffer {
    items: [usize; MAX_LEVELS],
    len: usize,
}

impl PlanBuffer {
    const EMPTY: Self = Self {
        items: [0; MAX_LEVELS],
        len: 0,
    };

    fn from_iter(items: impl ExactSizeIterator<Item = usize>) -> Self {
        let mut buffer = Self::EMPTY;
        assert!(
            items.len() <= MAX_LEVELS,
            "Elastic plan exceeds {MAX_LEVELS} levels"
        );
        for item in items {
            buffer.items[buffer.len] = item;
            buffer.len += 1;
        }
        buffer
    }
}

impl core::ops::Deref for PlanBuffer {
    type Target = [usize];

    fn deref(&self) -> &[usize] {
        &self.items[..self.len]
    }
}

/// Capacity shape and batch schedule for one elastic table allocation.
struct ElasticGeometry {
    total_slots: usize,
    max_insertions: usize,
    level_capacities: PlanBuffer,
    batch_plan: PlanBuffer,
}

impl ElasticGeometry {
    fn for_insert_budget(
        requested_insertions: usize,
        reserve_fraction: ReserveFraction,
    ) -> Option<Self> {
        let total_slots = if requested_insertions == 0 {
            0
        } else {
            capacity::capacity_for(INITIAL_CAPACITY, requested_insertions, reserve_fraction)?
        };
        Self::for_slots(total_slots, reserve_fraction)
    }

    /// `None` when `total_slots` exceeds `MAX_ELASTIC_SLOTS`.
    fn for_slots(total_slots: usize, reserve_fraction: ReserveFraction) -> Option<Self> {
        if !u64::try_from(total_slots).is_ok_and(|slots| slots <= MAX_ELASTIC_SLOTS) {
            return None;
        }
        if total_slots == 0 {
            return Some(Self {
                total_slots: 0,
                max_insertions: 0,
                level_capacities: PlanBuffer::EMPTY,
                batch_plan: PlanBuffer::EMPTY,
            });
        }

        // Public construction rounds positive maps up to INITIAL_CAPACITY, so
        // one slot is only an internal bootstrap shape outside the paper's
        // n >= 2 domain.
        if total_slots == 1 {
            let single = PlanBuffer::from_iter(core::iter::once(1));
            return Some(Self {
                total_slots: 1,
                max_insertions: 1,
                level_capacities: single,
                batch_plan: single,
            });
        }

        let config = PaperConfig::new(total_slots, reserve_fraction.exponent())
            .expect("validated Elastic library geometry");
        let plan = config.elastic_plan();
        Some(Self {
            total_slots,
            max_insertions: config.max_insertions(),
            level_capacities: PlanBuffer::from_iter(plan.level_lengths()),
            batch_plan: PlanBuffer::from_iter(plan.batch_quotas()),
        })
    }
}

/// Stamps level descriptors with arena-relative `(ctrl_ptr, data_ptr)`.
/// Split out so the alloc-then-deallocate-on-error wrapper stays shallow.
fn build_elastic_levels<K, V>(
    arena_base: *mut u8,
    data_base_off: usize,
    level_capacities: &[usize],
    reserve_fraction: ReserveFraction,
) -> Result<LevelSlice<K, V>, TryReserveError> {
    let mut cursor = arena::LayoutCursor::<SlotEntry<K, V>>::new(arena_base, data_base_off)?;
    let mut levels: Vec<Level<SlotEntry<K, V>>> = Vec::new();
    levels
        .try_reserve_exact(level_capacities.len())
        .map_err(|_| TryReserveError::AllocError)?;
    let all_shift = level_capacities
        .iter()
        .all(|&cap| probe::elastic_index_shift(cap).is_some());
    for (level, &cap) in level_capacities.iter().enumerate() {
        let cap_u32 = u32::try_from(cap).map_err(|_| TryReserveError::CapacityOverflow)?;
        let index_shift = match probe::elastic_index_shift(cap) {
            Some(shift) if all_shift => shift,
            _ => GENERAL_REDUCTION,
        };
        cursor.reserve_ctrl_header::<LevelCounters>()?;
        // SAFETY: the arena was allocated for the layout these caps sum to,
        // with room for every level's counters.
        let (ctrl_ptr, data_ptr) = unsafe { cursor.reserve(cap_u32)? };
        levels.push(Level::new_at(
            level,
            cap_u32,
            reserve_fraction,
            index_shift,
            ctrl_ptr,
            data_ptr,
        ));
    }
    Ok(levels.into_boxed_slice().into())
}

fn total_ctrl(level_capacities: &[usize]) -> Option<usize> {
    level_capacities
        .iter()
        .try_fold(0_usize, |total, &capacity| total.checked_add(capacity))
}

#[allow(clippy::cast_ptr_alignment)]
fn try_alloc_elastic_arena<K, V, A: Allocator + Clone>(
    level_capacities: &[usize],
    reserve_fraction: ReserveFraction,
    alloc: &A,
) -> Result<ElasticArenaBuild<K, V>, TryReserveError> {
    let total_ctrl = total_ctrl(level_capacities).ok_or(TryReserveError::CapacityOverflow)?;
    let arena_layout = elastic_arena_layout::<K, V>(total_ctrl, level_capacities.len())?;
    // Zeroed counters read as an empty level.
    let arena = Arena::try_allocate_with_ctrl_zeroed(
        arena_layout.layout,
        total_ctrl + counter_bytes(level_capacities.len()),
        alloc,
    )?;
    let membership = arena_layout.membership;
    // The arena zeroes control bytes only; an empty filter must read as
    // "nothing recorded".
    // SAFETY: `membership` was laid out by `elastic_arena_layout` for this arena.
    unsafe { reset_metadata(membership, arena.as_ptr()) };

    // `Arena` has no `Drop`: deallocate explicitly if level construction fails.
    match build_elastic_levels::<K, V>(
        arena.as_ptr(),
        arena_layout.data_base_off,
        level_capacities,
        reserve_fraction,
    ) {
        Ok(levels) => Ok((arena, levels, membership)),
        Err(e) => {
            arena.deallocate(alloc);
            Err(e)
        }
    }
}

/// The word a table without a metadata tail reads: it records no key, so
/// the filter rejects every lookup without testing for the missing tail.
static NO_METADATA: TailWord = TailWord {
    level_bins: [NO_LEVELS_OCCUPIED; SUMMARY_BINS],
    membership: 0,
};

/// [`NO_METADATA`] as the two machine words it occupies: the equal
/// level bins, then the membership lane.
const NO_METADATA_WORDS: [u64; 2] = {
    assert!(
        size_of::<TailWord>() == size_of::<[u64; 2]>()
            && mem::offset_of!(TailWord, membership) == size_of::<u64>()
    );
    let bin = NO_LEVELS_OCCUPIED as u64;
    [bin * 0x0101_0101_0101_0101, 0]
};

/// Writes [`NO_METADATA`] over every word of `membership`'s tail, as plain
/// machine words so the fill is a wide store loop.
///
/// # Safety
///
/// `membership` was laid out for the arena at `base`.
unsafe fn reset_metadata(membership: MembershipRegion, base: *mut u8) {
    if membership.words != 0 {
        // SAFETY: the caller's arena holds the region's words.
        let words = unsafe { membership.ptr::<TailWord>(base) };
        // SAFETY: as above, nothing else borrows the words, and a metadata
        // word is two machine words, by the assertion beside the pattern.
        // The tail may be uninitialized, which `MaybeUninit` allows.
        let tail = unsafe {
            core::slice::from_raw_parts_mut(words.cast::<MaybeUninit<[u64; 2]>>(), membership.words)
        };
        // Rebuilt from its elements: the fill then stores a value it holds
        // in registers, which is what makes the loop a wide one.
        tail.fill(MaybeUninit::new([
            NO_METADATA_WORDS[0],
            NO_METADATA_WORDS[1],
        ]));
    }
}

/// Writes a word every key passes and no level is closed in over every word
/// of `membership`'s tail: the filter then sends each lookup to its walk.
///
/// # Safety
///
/// `membership` was laid out for the arena at `base`, and its words are
/// initialized.
unsafe fn saturate_metadata(membership: MembershipRegion, base: *mut u8) {
    if membership.words != 0 {
        // SAFETY: the caller's arena holds the region's words.
        let words = unsafe { membership.ptr::<TailWord>(base) };
        // SAFETY: as above, the words are initialized, and nothing else
        // borrows them.
        let tail = unsafe { core::slice::from_raw_parts_mut(words, membership.words) };
        tail.fill(TailWord {
            level_bins: [0; SUMMARY_BINS],
            membership: u64::MAX,
        });
    }
}

/// Saturates the table's filter when dropped. A filter refresh holds one
/// while it re-records the live keys and forgets it at the end, so a key
/// whose hasher unwinds leaves a filter that still passes every live key.
struct SaturateOnUnwind<'a, K, V, S, A: Allocator + Clone>(&'a mut ElasticTable<K, V, S, A>);

impl<K, V, S, A: Allocator + Clone> Drop for SaturateOnUnwind<'_, K, V, S, A> {
    fn drop(&mut self) {
        // SAFETY: `membership` was laid out together with `arena`, and the
        // refresh cleared its words before it made this guard.
        unsafe { saturate_metadata(self.0.membership, self.0.arena.as_ptr()) };
    }
}

/// First metadata word of `membership`'s tail inside `arena`, or
/// [`NO_METADATA`] when it has none. Only a tail with words is written to.
fn metadata_words(arena: &Arena, membership: MembershipRegion) -> *mut TailWord {
    if membership.words == 0 {
        return (&raw const NO_METADATA).cast_mut();
    }
    // SAFETY: `membership` was laid out together with `arena`.
    unsafe { membership.ptr::<TailWord>(arena.as_ptr()) }
}

fn alloc_elastic_arena<K, V, A: Allocator + Clone>(
    level_capacities: &[usize],
    reserve_fraction: ReserveFraction,
    alloc: &A,
) -> ElasticArenaBuild<K, V> {
    try_alloc_elastic_arena(level_capacities, reserve_fraction, alloc)
        .unwrap_or_else(|_| handle_elastic_alloc_error::<K, V>(level_capacities))
}

/// Reports the failed allocation for `level_capacities`, or a placeholder
/// layout when the geometry itself does not fit.
#[cold]
fn handle_elastic_alloc_error<K, V>(level_capacities: &[usize]) -> ! {
    let layout = total_ctrl(level_capacities)
        .and_then(|total_ctrl| {
            elastic_arena_layout::<K, V>(total_ctrl, level_capacities.len())
                .ok()
                .map(|layout| layout.layout)
        })
        .unwrap_or_else(Layout::new::<u8>);
    allocator_api2::alloc::handle_alloc_error(layout)
}

/// Drops every level's live values, backing [`arena::ArenaDropGuard`]'s
/// panic-safe rollback in `resize`/`clone`.
impl<K, V> arena::RegionSet for LevelSlice<K, V> {
    fn drop_all_values(&mut self) {
        arena::drop_values(self);
    }
}

impl<K, V, S, A> ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Allocates an empty table for `geometry`. Every constructor ends here.
    fn try_from_geometry(
        geometry: &ElasticGeometry,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let schedule_room = ProbeScheduleRoom::try_for_levels(geometry.level_capacities.len())?;
        let (arena, levels, membership) =
            try_alloc_elastic_arena(&geometry.level_capacities, reserve_fraction, &alloc)?;

        let settled_limit = settled_limit(
            &levels,
            geometry.batch_plan.len,
            membership,
            geometry.max_insertions,
        );
        let probe_schedule = schedule_room.schedule(&levels);
        Ok(Self {
            levels,
            placed: 0,
            total_slots: geometry.total_slots,
            max_insertions: geometry.max_insertions,
            reserve_fraction,
            scheduler: BatchScheduler::new(
                &geometry.batch_plan,
                settled_limit,
                membership::refresh_deletes(geometry.max_insertions),
            ),
            hash_builder,
            alloc,
            metadata_scale: MetadataPlace::scale(membership.words),
            metadata_words: metadata_words(&arena, membership),
            arena,
            epoch: EpochState::initial(),
            probe_high_water: empty_high_water(settled_limit),
            scheduled_levels: 0,
            uncounted: Uncounted::default(),
            probe_schedule,
            settled_level: ptr::null_mut(),
            settled_fallback: ptr::null_mut(),
            fold_multiplier: probe::ELASTIC_FOLD_MULTIPLIER,
            membership,
        })
    }

    /// Full constructor using an exact dyadic reserve.
    #[must_use]
    pub fn with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        let geometry = ElasticGeometry::for_insert_budget(capacity, reserve_fraction)
            .expect("capacity overflow");
        Self::try_from_geometry(&geometry, reserve_fraction, hash_builder, alloc)
            .unwrap_or_else(|_| handle_elastic_alloc_error::<K, V>(&geometry.level_capacities))
    }

    /// Fallible full constructor using an exact dyadic reserve.
    fn try_with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        let geometry = ElasticGeometry::for_insert_budget(capacity, reserve_fraction)
            .ok_or(TryBuildError::Reserve(TryReserveError::CapacityOverflow))?;
        Self::try_from_geometry(&geometry, reserve_fraction, hash_builder, alloc)
            .map_err(Into::into)
    }

    #[inline]
    fn membership_ptr(&self) -> *mut TailWord {
        self.metadata_words
    }

    /// Tests the membership scalar of the key's metadata word:
    /// `maybe_present == false` proves the key was never recorded. The
    /// word's summary bins narrow the candidate levels.
    #[inline]
    fn route_filter(&self, prepared: PreparedElasticRoute) -> ElasticRouteFilter<'_> {
        // A zero scale reduces every signature to place zero, whose word is
        // then `NO_METADATA`: no bit is set there, so the filter rejects
        // the key.
        let place = MetadataPlace::new(prepared.signature(), self.metadata_scale);
        let bits = place.bits();
        // SAFETY: the place's word is below the word count, and the cached
        // region covers exactly that many initialized, properly aligned
        // `TailWord`s; with no words it is zero and `metadata_words`
        // addresses the one word of `NO_METADATA`.
        let word = unsafe { &*self.membership_ptr().add(place.word()) };
        let lane = word.membership;
        ElasticRouteFilter {
            maybe_present: lane & bits == bits,
            read: LaneRead { place, lane, bits },
            word,
        }
    }

    #[inline]
    fn record_membership(&mut self, route: PreparedElasticRoute, summary_bit: SummaryBin) {
        let read = self.route_filter(route).recording();
        // SAFETY: the filter read `read` just now.
        unsafe { self.record_membership_over(summary_bit, read) };
    }

    /// Records a key in `summary_bit`'s level over `read`.
    ///
    /// # Safety
    ///
    /// `read` is the key's, as [`Self::route_filter`] reads it now.
    #[inline]
    unsafe fn record_membership_over(&mut self, summary_bit: SummaryBin, read: LaneRead) {
        let LaneRead { place, lane, bits } = read;
        if self.metadata_scale != 0 {
            // SAFETY: the caller's place is the one the filter reduces for
            // this tail, so its word indexes an initialized word of it,
            // which a scale that is not zero says the table has; `&mut
            // self` makes the borrow exclusive.
            let metadata = unsafe { &mut *self.membership_ptr().add(place.word()) };
            metadata.membership = lane | bits;
            metadata.level_bins[place.summary_bin()] &= !summary_bit;
        }
    }

    /// Clears a removed key's membership bit where no other live key can
    /// hold it, so the key's next lookup or insert ends at the filter.
    ///
    /// # Safety
    ///
    /// `read` is the key's, as [`Self::route_filter`] read it with the key
    /// present, and the table's metadata is as it was then.
    #[inline]
    unsafe fn forget_membership(&mut self, read: LaneRead) {
        let LaneRead { place, lane, bits } = read;
        debug_assert_eq!(lane & bits, bits, "the filter did not pass the key");
        // The key's bit where the lane holds no pair for it, else nothing.
        // The lane holds the bit, so flipping it clears it.
        let unshared = bits & !paired_bits(lane);
        // SAFETY: the filter passed the key, so its word holds a bit: it is
        // a word of this table's tail, not the empty tail's shared one, and
        // `&mut self` makes the write exclusive.
        unsafe { (*self.membership_ptr().add(place.word())).membership = lane ^ unshared };
    }

    fn clear_membership(&mut self) {
        // SAFETY: `self.membership` was laid out together with `self.arena`.
        unsafe {
            reset_metadata(self.membership, self.arena.as_ptr());
        }
        self.rearm_deletes();
    }

    /// Starts the delete countdown over at the same live count. The placed
    /// count moves with it, so the settled gate closes.
    fn rearm_deletes(&mut self) {
        self.count_settled();
        self.placed = self.live();
        self.uncounted = Uncounted::none_at(self.placed);
        self.scheduler
            .rearm(membership::refresh_deletes(self.max_insertions));
    }

    /// Live entries.
    #[inline]
    fn live(&self) -> usize {
        self.placed - self.stale_membership()
    }

    /// Live entries of `level`, one of this table's.
    #[inline]
    fn live_in(&self, level: &Level<SlotEntry<K, V>>) -> u32 {
        let settled = ptr::eq(level, self.settled_level);
        let live = self
            .uncounted
            .live(self.placed, level.counters().len, settled);
        debug_assert!(live <= level.capacity, "a live count fell below zero");
        live
    }

    /// Moves the settled inserts into `settled_level`'s stored live count,
    /// ahead of a change to the placed count or to the settled level that
    /// is not a settled insert.
    fn count_settled(&mut self) {
        if self.uncounted.pending(self.placed) != 0 {
            // SAFETY: an insert goes uncounted only into the settled level
            // of an open gate, which `reopen_settled` set to one of the
            // levels. A generation swap moves the uncounted inserts with
            // their levels and leaves the pointer on them.
            let counters = unsafe { (*self.settled_level).counters_mut() };
            self.uncounted.count_into(self.placed, &mut counters.len);
        }
    }

    fn copy_membership_from(&mut self, source: &Self) {
        // SAFETY: each region was laid out for its own table's arena, so the two
        // never overlap; clones share geometry, so word counts match.
        unsafe {
            self.membership.copy_from::<TailWord>(
                self.arena.as_ptr(),
                source.membership,
                source.arena.as_ptr(),
            );
        };
    }

    fn clear(&mut self) {
        self.count_settled();
        for level in &mut self.levels {
            level.drain_reset(|entry| {
                self.placed -= 1;
                self.uncounted.uncover_one();
                // Before the drop: one that panics leaves the table live
                // with this count.
                self.scheduler.close();
                drop(entry);
            });
        }
        debug_assert_eq!(self.live(), 0);
        self.reset_after_clear();
    }

    /// Resets placement, lookup, and filter state once every level is empty.
    fn reset_after_clear(&mut self) {
        self.scheduler.reset();
        self.probe_high_water = empty_high_water(self.scheduler.settled_limit);
        self.scheduled_levels = 0;
        for level in &mut self.levels {
            level.scheduled_probes = 0;
        }
        self.probe_schedule.clear();
        self.clear_membership();
        self.epoch.start(EpochTransition::Clear);
    }

    /// Post-lookup insert for a key known to be absent. Returns the chosen
    /// slot so the caller can borrow into it without re-probing.
    #[inline]
    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> (usize, usize) {
        let prepared = PreparedElasticRoute::new(key_hash);
        let key_fingerprint = control::control_fingerprint_low(key_hash);
        self.insert_absent(key, value, prepared, key_fingerprint)
    }

    /// [`Self::insert_for_vacant_entry`] of a prepared key: a settled
    /// insert, reopening the gate for it where it may open, or else the
    /// general one.
    fn insert_absent(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
    ) -> (usize, usize) {
        if self.scheduler.settles(self.placed) || self.reopen_settled() {
            // SAFETY: the gate is open.
            let found = unsafe {
                self.settled_level_slot(prepared.probe)
                    .or_else(|| self.settled_fallback_slot(prepared.probe))
            };
            if let Some(found) = found {
                // SAFETY: the settled search returns one of this table's levels.
                let level = unsafe { found.level.offset_from_unsigned(self.levels.as_ptr()) };
                let slot = found.slot;
                let read = self.route_filter(prepared).recording();
                // SAFETY: the settled search returns a free slot of that
                // level with the level's words.
                unsafe {
                    self.write_new_entry_at::<false>(key, value, key_fingerprint, found, read);
                }
                return (level, slot);
            }
        }
        self.insert_for_vacant_entry_prepared(key, value, prepared, key_fingerprint)
    }

    /// [`Self::settled_level_slot`] with the level by index, for a table
    /// whose gate is closed too: the slot a settled insert would write once
    /// the gate reopened.
    #[cfg(test)]
    fn settled_slot(&self, probe: PreparedElasticProbe) -> Option<(usize, usize, u8)> {
        let plan = self.settled_plan()?;
        let searches = [
            Some((plan.level, plan.budget)),
            plan.fallback.map(|budget| (plan.level + 1, budget)),
        ];
        searches.into_iter().flatten().find_map(|(index, budget)| {
            let level = &self.levels[index];
            // SAFETY: a plan's levels are those of a table that settles,
            // whose levels reduce by shift.
            let found = unsafe {
                first_settled_vacancy(
                    probe.sequence(self.fold_multiplier),
                    ptr::from_ref(level).cast_mut(),
                    settled_word(level.summary_bit(), budget),
                )
            }?;
            Some((index, found.slot, found.control.to_le_bytes()[0]))
        })
    }

    /// The plan the settled gate opens on, when the cached batch covers the
    /// live count, that count is below the settled limit, and the paper's
    /// insertion case for the batch has a scheduled probe to search in a
    /// level with a free slot.
    ///
    /// The case and its budget follow the fill of the batch's levels, which
    /// a settled insert raises in one of the plan's levels. The plan ends
    /// where that fill changes either: where the level a budgeted case
    /// searches comes down to half its reserve or to a free fraction with
    /// another budget, where the level it falls back to comes down to a
    /// quarter free, or where the level another case searches is full.
    /// Counting every insert against both levels ends it no later.
    fn settled_plan(&self) -> Option<SettledPlan> {
        let end = self
            .scheduler
            .reopened_end(self.placed, self.stale_membership())?;
        let target = self.scheduler.cached_target();
        let (case, budget, fallback) = self.settled_case(target)?;
        let region = case.region;
        let free = region.capacity - self.live_in(region);
        let holds_for = match target {
            // The level a case searches without a bound stays the case's
            // while the other level of its pair keeps its fill.
            BatchTarget::LevelPair(current) if case.level == current => {
                // Not low, so above half the reserve.
                let until_low = free - region.half_reserve;
                if case.fallback.is_none() {
                    until_low
                } else {
                    until_low.min(probe::elastic_level_budget_run(
                        free,
                        region.capacity,
                        self.reserve_fraction.exponent(),
                    ))
                }
            }
            // Until the level is full.
            _ => free,
        };
        let holds_for = if fallback.is_some() {
            let next = &self.levels[case.level + 1];
            // Not a quarter free or less, the case's test of this level.
            holds_for.min(next.capacity - self.live_in(next) - next.capacity / 4)
        } else {
            holds_for
        };
        let end = end.min(self.placed.saturating_add(holds_for as usize));
        (self.placed < end).then_some(SettledPlan {
            level: case.level,
            budget,
            fallback,
            end,
        })
    }

    /// The paper's insertion case for `target` with the budget a settled
    /// search gives it, the case's own within the level's scheduled probes,
    /// and [`SettledPlan::fallback`]: `None` for a table whose levels do
    /// not reduce by shift, and where no probe is left to search.
    #[inline]
    fn settled_case(
        &self,
        target: BatchTarget,
    ) -> Option<(PlacementCase<'_, K, V>, u16, Option<u16>)> {
        let case = self.placement_case(target, |_, budget| budget.unwrap_or(u64::MAX))?;
        if case.region.index_shift() == GENERAL_REDUCTION {
            return None;
        }
        let budget = case.region.scheduled_probes;
        let budget = u16::try_from(case.budget).map_or(budget, |own| own.min(budget));
        if budget == 0 {
            return None;
        }
        let fallback = case.fallback.and_then(|next| {
            // What the general search gives the case's level.
            let own = case.budget.min(*LEVEL_PROBE_LIMIT.get(case.level)?);
            let scheduled = self.levels.get(next)?.scheduled_probes;
            (u64::from(budget) == own && scheduled != 0).then_some(scheduled)
        });
        Some((case, budget, fallback))
    }

    /// What an open gate holds of a plan with these searches: each level
    /// and its [`settled_word`], the fallback's null and zero without one.
    fn plan_words(
        &self,
        level: usize,
        budget: u16,
        fallback: Option<u16>,
    ) -> [(*const Level<SlotEntry<K, V>>, u32); 2] {
        let words = |index: usize, budget| {
            let level = &self.levels[index];
            (
                ptr::from_ref(level),
                settled_word(level.summary_bit(), budget),
            )
        };
        [
            words(level, budget),
            fallback.map_or((ptr::null(), 0), |budget| words(level + 1, budget)),
        ]
    }

    /// [`Self::plan_words`] of the plan the gate last opened on.
    ///
    /// # Safety
    ///
    /// The gate opened since the levels were last replaced.
    unsafe fn open_words(&self) -> [(*const Level<SlotEntry<K, V>>, u32); 2] {
        let (level, fallback) = (self.settled_level, self.settled_fallback);
        // SAFETY: the caller's contract: the gate's levels are levels.
        unsafe {
            [
                (level.cast_const(), (*level).search.settled),
                if fallback.is_null() {
                    (ptr::null(), 0)
                } else {
                    (fallback.cast_const(), (*fallback).search.settled)
                },
            ]
        }
    }

    /// Reopens the gate a general insert closed, which stood open to `end`
    /// before it: on the plan it stood open on while the insertion case
    /// still names that plan's levels and budgets, and on a fresh plan
    /// otherwise.
    ///
    /// The insert raised the placed count and one level's fill by one, which
    /// the plan's bound counts against each of its levels.
    fn keep_settled(&mut self, end: usize) {
        let removed = self.stale_membership();
        if self.placed < end && self.scheduler.covers(self.placed - removed) {
            let kept = self
                .settled_case(self.scheduler.cached_target())
                .is_some_and(|(case, budget, fallback)| {
                    // SAFETY: the gate stood open before the insert, which
                    // took `place_new_entry` and so kept the levels.
                    self.plan_words(case.level, budget, fallback) == unsafe { self.open_words() }
                });
            if kept {
                self.scheduler.settled_end = end;
                return;
            }
        }
        self.reopen_settled();
    }

    /// Opens the settled gate on [`Self::settled_plan`], and reports whether
    /// there is one.
    #[cold]
    #[inline(never)]
    fn reopen_settled(&mut self) -> bool {
        let Some(plan) = self.settled_plan() else {
            return false;
        };
        self.count_settled();
        // Both levels by address before either write, so the writes reload
        // nothing of the table.
        let level = self.levels.level_ptr(plan.level);
        let fallback = match plan.fallback {
            Some(_) => self.levels.level_ptr(plan.level + 1),
            None => ptr::null_mut(),
        };
        // SAFETY: `level_ptr` checked each index, so the pointers are to
        // levels, which `&mut self` borrows alone.
        unsafe {
            (*level).search.settled = settled_word((*level).summary_bit(), plan.budget);
            if let Some(budget) = plan.fallback {
                (*fallback).search.settled = settled_word((*fallback).summary_bit(), budget);
            }
        }
        self.settled_level = level;
        self.settled_fallback = fallback;
        debug_assert_eq!(
            // SAFETY: the gate's levels were set just above.
            unsafe { self.open_words() },
            self.plan_words(plan.level, plan.budget, plan.fallback),
        );
        self.scheduler.settled_end = plan.end;
        true
    }

    /// The level and free slot [`Self::choose_slot_for_new_key`] gives a
    /// new key, with the level's words a write needs, when the plan the
    /// settled gate opened on finds a free slot among its probes. `None`
    /// leaves the insert to [`Self::insert_for_vacant_entry_prepared`].
    ///
    /// # Safety
    ///
    /// The settled gate is open: [`BatchScheduler::settles`] holds.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    unsafe fn settled_level_slot(&self, probe: PreparedElasticProbe) -> Option<SettledSlot<K, V>> {
        debug_assert!(self.scheduler.settles(self.placed));
        debug_assert_eq!(
            self.settled_plan()
                .map(|plan| self.plan_words(plan.level, plan.budget, plan.fallback)),
            // SAFETY: the gate is open.
            Some(unsafe { self.open_words() }),
            "the open gate's plan is the table's"
        );
        debug_assert!(self.metadata_scale != 0);
        // SAFETY: the scheduler settles only below the limit it was built
        // with, which `settled_limit` derives from the levels and the
        // filter built beside it: zero without a filter word, and a tail
        // with a word has a nonzero scale. A clone takes
        // the scheduler and builds a filter of the same capacity, and a
        // rebuild swaps both together.
        unsafe { core::hint::assert_unchecked(self.metadata_scale != 0) };
        let sequence = probe.sequence(self.fold_multiplier);
        let level = self.settled_level;
        // SAFETY: the gate is open, so `settled_level` and a
        // `settled_fallback` that is not null are the levels of the plan it
        // opened on, with that plan's countdowns: every path that replaces
        // the levels, changes a level's fill other than by a settled
        // insert, or changes a level's scheduled probes closes the gate. A
        // plan's levels reduce by shift.
        unsafe { first_settled_vacancy(sequence, level, (*level).search.settled) }
    }

    /// The first free slot `probe` reaches in the settled plan's fallback
    /// level, for a key [`Self::settled_level_slot`] found no slot for;
    /// `None` without such a level too.
    ///
    /// # Safety
    ///
    /// As for [`Self::settled_level_slot`].
    unsafe fn settled_fallback_slot(
        &self,
        probe: PreparedElasticProbe,
    ) -> Option<SettledSlot<K, V>> {
        let fallback = self.settled_fallback;
        if fallback.is_null() {
            return None;
        }
        let sequence = probe.sequence(self.fold_multiplier);
        // SAFETY: as in `settled_level_slot`.
        unsafe { first_settled_vacancy(sequence, fallback, (*fallback).search.settled) }
    }

    fn insert_for_vacant_entry_prepared(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
    ) -> (usize, usize) {
        if self.live() >= self.max_insertions {
            let new_cap = if self.total_slots == 0 {
                INITIAL_CAPACITY
            } else {
                self.total_slots.saturating_mul(2)
            };
            self.resize_with_transition(new_cap, EpochTransition::Growth);
        }

        if !self.scheduler.covers(self.live()) {
            self.enter_batch();
        }
        let target = self.scheduler.cached_target();
        // The write closes the gate; the next insert finds it open again
        // where it may be.
        if let Some(placement) = self.choose_slot_for_insert(prepared.probe, target) {
            let open_to = self.scheduler.settled_end;
            let location = self.place_new_entry(key, value, prepared, key_fingerprint, placement);
            self.keep_settled(open_to);
            location
        } else {
            let location =
                self.place_after_target_failure(key, value, prepared, key_fingerprint, target);
            self.reopen_settled();
            location
        }
    }

    /// [`map::TableBackend::insert`] off its common path: a key the walk
    /// left unresolved, or an absent key without a settled slot. It tells
    /// the two apart itself, so its callers pass the same arguments and
    /// share one call.
    #[inline(never)]
    fn insert_slow(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
    ) -> Option<V> {
        let filter = self.route_filter(prepared);
        if filter.maybe_present && self.walk_ends_unresolved() {
            let level_mask = filter.expanded_level_mask();
            let found = self.find_by_general_schedule(
                &key,
                prepared,
                level_mask,
                key_fingerprint,
                |level, slot, _| (level, slot),
            );
            if let Some(location) = found {
                return Some(map::TableBackend::replace_value(self, location, value));
            }
        }
        self.insert_absent(key, value, prepared, key_fingerprint);
        None
    }

    /// [`map::TableBackend::insert`] of an absent key the open gate's
    /// [`Self::settled_level_slot`] found no slot for: into the plan's
    /// fallback level, or else the general insert.
    ///
    /// # Safety
    ///
    /// As for [`Self::settled_level_slot`].
    #[inline(never)]
    unsafe fn insert_unsettled(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
    ) {
        // SAFETY: the caller's contract.
        if let Some(found) = unsafe { self.settled_fallback_slot(prepared.probe) } {
            let read = self.route_filter(prepared).recording();
            // SAFETY: the settled search returns one of this table's levels
            // with its words, and a free slot of it with its control byte.
            unsafe { self.write_new_entry_at::<false>(key, value, key_fingerprint, found, read) };
            return;
        }
        self.insert_for_vacant_entry_prepared(key, value, prepared, key_fingerprint);
    }

    /// [`Self::place_unique`] of a key the cached batch's target has no
    /// slot for. Kept out of line, and deriving the key's route again, so
    /// the rebuild's loop holds a single target attempt and nothing for
    /// this one.
    #[cold]
    #[inline(never)]
    fn place_unique_off_target(&mut self, entry: SlotEntry<K, V>, key_hash: u64) -> bool {
        let prepared = PreparedElasticRoute::new(key_hash);
        let key_fingerprint = control::control_fingerprint_low(key_hash);
        let target = self.scheduler.cached_target();
        if let Some(placement) = self.choose_slot_on_other_targets(prepared.probe, target) {
            self.place_new_entry(entry.key, entry.value, prepared, key_fingerprint, placement);
            false
        } else {
            self.place_exceptional_entry(entry.key, entry.value, prepared, key_fingerprint);
            true
        }
    }

    /// Places a key whose active batch target has no slot: another target,
    /// then [`Self::place_after_recovery`]. Kept out of line
    /// so the common path inlines as a single target attempt.
    #[cold]
    #[inline(never)]
    fn place_after_target_failure(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
        target: BatchTarget,
    ) -> (usize, usize) {
        if let Some(placement) = self.choose_slot_on_other_targets(prepared.probe, target) {
            return self.place_new_entry(key, value, prepared, key_fingerprint, placement);
        }
        // An epoch that already placed outside its probe routes failed its
        // own rebuild; another would cost O(n) per insert without helping.
        if self.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG != 0 {
            self.epoch.note_placement_recovery();
            return self.place_exceptional_entry(key, value, prepared, key_fingerprint);
        }
        self.place_after_recovery(key, value, prepared, key_fingerprint)
    }

    /// Places a key no target has a slot for: a same-size rebuild, which
    /// moves the entries, then every target again, then exceptional
    /// placement. Out of line, so the failure that another target absorbs
    /// carries none of it.
    #[cold]
    #[inline(never)]
    fn place_after_recovery(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
    ) -> (usize, usize) {
        self.resize_with_transition(self.total_slots, EpochTransition::PlacementRecovery);
        let target = self.scheduler.target(self.live());
        let placement = self
            .choose_slot_for_new_key(prepared.probe, target)
            .or_else(|| self.choose_slot_on_other_targets(prepared.probe, target));
        if let Some(placement) = placement {
            self.place_new_entry(key, value, prepared, key_fingerprint, placement)
        } else {
            self.place_exceptional_entry(key, value, prepared, key_fingerprint)
        }
    }

    /// Write a new entry and update placement and batch metadata.
    #[inline]
    fn place_new_entry(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
        placement: ExactPlacement,
    ) -> (usize, usize) {
        if placement.paper_probe > u64::from(self.levels[placement.level].scheduled_probes) {
            self.schedule_placement(placement);
        }
        // SAFETY: a placement names a slot of its level.
        let prev_ctrl = unsafe { self.levels[placement.level].control_at(placement.slot) };
        self.write_new_entry(
            key,
            value,
            prepared,
            key_fingerprint,
            placement.level,
            placement.slot,
            prev_ctrl,
        )
    }

    #[cold]
    fn place_exceptional_entry(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
    ) -> (usize, usize) {
        let (level, slot) = self
            .first_free_slot()
            .expect("Elastic insertion limit must leave a free slot");
        self.probe_high_water |= EXCEPTIONAL_PLACEMENT_FLAG | WALK_UNRESOLVED_FLAG;
        // SAFETY: the scan found `slot` within `level`.
        let prev_ctrl = unsafe { self.levels[level].control_at(slot) };
        self.write_new_entry(
            key,
            value,
            prepared,
            key_fingerprint,
            level,
            slot,
            prev_ctrl,
        )
    }

    fn first_free_slot(&self) -> Option<(usize, usize)> {
        self.levels
            .iter()
            .enumerate()
            .find_map(|(level_index, level)| {
                (0..level.capacity())
                    // SAFETY: `slot` ranges over the level's capacity.
                    .find(|&slot| control::is_free(unsafe { level.control_at(slot) }))
                    .map(|slot| (level_index, slot))
            })
    }

    /// Writes a new entry into the free slot `slot_idx` of `level_idx`.
    /// `prev_ctrl` is the control byte the caller found the slot free by.
    #[allow(clippy::too_many_arguments)]
    #[inline]
    fn write_new_entry(
        &mut self,
        key: K,
        value: V,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
        level_idx: usize,
        slot_idx: usize,
        prev_ctrl: u8,
    ) -> (usize, usize) {
        debug_assert!(level_idx < self.levels.len());
        let level = self.levels.level_ptr(level_idx);
        let read = self.route_filter(prepared).recording();
        // SAFETY: `level_ptr` checked the index, so the pointer is to a level.
        let found = unsafe {
            SettledSlot {
                level,
                control_bytes: (*level).ctrl_ptr,
                data: (*level).data_ptr,
                summary_bit: (*level).summary_bit(),
                slot: slot_idx,
                control: i32::from(prev_ctrl.cast_signed()),
            }
        };
        // SAFETY: callers pass a free slot of the level they found it in.
        unsafe { self.write_new_entry_at::<false>(key, value, key_fingerprint, found, read) };
        // Not a settled insert: it may change the fill or the scheduled
        // probes the settled plan was made for.
        self.scheduler.close();
        (level_idx, slot_idx)
    }

    /// [`Self::write_new_entry`] for a level by address, which leaves the
    /// settled gate as it is.
    ///
    /// # Safety
    ///
    /// `found` names one of this table's levels, derived from their
    /// pointer, with that level's pointers and summary bit, a free slot of
    /// it and the slot's control byte. `read` is the key's, as
    /// [`Self::route_filter`] reads it now.
    ///
    /// `SETTLED` leaves the insert out of the level's stored live count,
    /// for a slot of `settled_level` alone.
    #[allow(clippy::needless_pass_by_value)]
    #[inline]
    unsafe fn write_new_entry_at<const SETTLED: bool>(
        &mut self,
        key: K,
        value: V,
        key_fingerprint: u8,
        found: SettledSlot<K, V>,
        read: LaneRead,
    ) {
        let SettledSlot {
            level,
            control_bytes,
            data,
            summary_bit,
            slot,
            control,
        } = found;
        // SAFETY: the caller's contract.
        unsafe { self.record_membership_over(summary_bit, read) };
        debug_assert!(control >= 0);
        // SAFETY: the caller's contract: the slot is a free one of the
        // level these pointers are of, whose counters sit ahead of its
        // control bytes, and `&mut self` borrows the arena alone.
        // `key_fingerprint` is an occupied control byte.
        unsafe {
            debug_assert_eq!(control, signed_control(control_bytes, slot));
            data.add(slot)
                .write(MaybeUninit::new(SlotEntry { value, key }));
            control_bytes.add(slot).write(key_fingerprint);
            if !SETTLED {
                self.uncounted
                    .count_one(&mut (*level_counters(control_bytes)).len);
            }
        }
        self.placed += 1;
        // A free slot that is not empty is a tombstone, which differs from
        // an empty one in this bit. Last, so the call sits after every
        // store of the common path.
        const { assert!(CTRL_EMPTY & CTRL_TOMBSTONE == 0) };
        if control & i32::from(CTRL_TOMBSTONE) != 0 {
            // SAFETY: the caller's contract.
            self.scheduler.reuse_tombstone(unsafe { &mut *level });
        }
    }

    /// Extends the schedule to cover a placement outside the scheduled levels
    /// or past the probes its own level already holds.
    #[cold]
    #[inline(never)]
    fn schedule_placement(&mut self, placement: ExactPlacement) {
        if placement.level >= self.scheduled_levels as usize {
            self.schedule_levels_through(placement.level);
        }
        self.extend_probe_schedule(placement.phi());
    }

    /// Rebuilds the schedule to hold the routes of every level up to `level`,
    /// the first placement of this epoch past the levels scheduled so far.
    fn schedule_levels_through(&mut self, level: usize) {
        let high_water = self.probe_high_water & !HIGH_WATER_FLAGS;
        self.probe_high_water &= HIGH_WATER_FLAGS;
        // The levels scheduled before and after are scheduled again, to the
        // same position.
        self.probe_schedule.rewind(level + 1);
        self.scheduled_levels = u32::try_from(level + 1).expect("Elastic level count fits u32");
        for level in &mut self.levels {
            level.scheduled_probes = 0;
        }
        self.extend_probe_schedule(u128::from(high_water));
    }

    fn extend_probe_schedule(&mut self, high_water: u128) {
        assert!(
            high_water <= QUERY_POSITION_CAP,
            "Elastic query-position convention exhausted"
        );
        let prior_high_water = self.probe_high_water & !HIGH_WATER_FLAGS;
        if high_water <= u128::from(prior_high_water) {
            return;
        }
        // A level's positions grow with its probe, so each level offers its
        // next unscheduled probe and the lowest position among them is the
        // next route in position order.
        let position = |level: usize, paper_probe: u64| {
            if paper_probe > UNIFORM_SEARCH_CAP {
                return None;
            }
            let phi = probe::elastic_phi(level as u128 + 1, u128::from(paper_probe))
                .expect("bounded Elastic query coordinate");
            (phi <= high_water).then_some(phi)
        };
        let levels = &mut self.levels[..self.scheduled_levels as usize];
        let mut next = [None; MAX_LEVELS];
        for (level, region) in levels.iter().enumerate() {
            next[level] = position(level, u64::from(region.scheduled_probes) + 1);
        }
        while let Some((level, _)) = next[..levels.len()]
            .iter()
            .enumerate()
            .filter_map(|(level, phi)| phi.map(|phi| (level, phi)))
            .min_by_key(|&(_, phi)| phi)
        {
            let logical_probe_index = u64::from(levels[level].scheduled_probes);
            // Level zero's first probe is the direct slot, which every
            // lookup reads before it walks the schedule.
            if level != 0 || logical_probe_index != 0 {
                assert!(
                    usize::try_from(logical_probe_index)
                        .is_ok_and(|index| index < QUERY_PROBE_LIMIT),
                    "Elastic query-probe convention exhausted"
                );
                self.probe_schedule.push(levels, level, logical_probe_index);
            }
            let region = &mut levels[level];
            region.scheduled_probes += 1;
            next[level] = position(level, u64::from(region.scheduled_probes) + 1);
        }
        self.probe_high_water = (self.probe_high_water & HIGH_WATER_FLAGS)
            | u32::try_from(high_water).expect("Elastic query cap fits u32");
    }
}

#[allow(private_interfaces)]
impl<K, V, S, A> map::TableBackend<K, V> for ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Location = (usize, usize);
    type Vacant = u64;
    type Hasher = S;
    type Alloc = A;

    #[inline]
    fn hasher(&self) -> &S {
        &self.hash_builder
    }

    #[inline]
    fn allocator(&self) -> &A {
        &self.alloc
    }

    #[inline]
    fn len(&self) -> usize {
        self.live()
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.max_insertions
    }

    #[inline]
    fn total_slots(&self) -> usize {
        self.total_slots
    }

    #[inline]
    fn reserve_config(&self) -> ReserveFraction {
        self.reserve_fraction
    }

    fn epoch_snapshot(&self) -> EpochSnapshot {
        let mut epoch = self.epoch;
        epoch.note_deletes(self.stale_membership());
        epoch.snapshot(self.live())
    }

    #[inline]
    unsafe fn slot_ref(&self, (level_idx, slot_idx): (usize, usize)) -> &SlotEntry<K, V> {
        // SAFETY: caller passes a live location: occupied and in bounds.
        unsafe { self.levels[level_idx].get_ref(slot_idx) }
    }

    /// Projects through raw pointers from `&self.levels`, forming no
    /// intermediate `&mut Level`, so distinct locations yield non-aliasing
    /// `*mut`.
    #[inline]
    unsafe fn slot_ptr(&self, (level_idx, slot_idx): (usize, usize)) -> *mut SlotEntry<K, V> {
        let levels_ptr: *const Level<SlotEntry<K, V>> = self.levels.as_ptr();
        // SAFETY: shared `&Level` only — never `&mut` — so no aliasing tag.
        let level = unsafe { &*levels_ptr.add(level_idx) };
        // SAFETY: caller passes a live location, so `slot_idx` is in bounds.
        unsafe { level.slot_ptr(slot_idx) }
    }

    #[inline]
    fn replace_value(&mut self, (level_idx, slot_idx): (usize, usize), value: V) -> V {
        // SAFETY: `Location` contract: a valid location is occupied and in bounds.
        let slot = unsafe { self.levels[level_idx].get_mut(slot_idx) };
        mem::replace(&mut slot.value, value)
    }

    #[inline]
    fn find<Q>(&self, key: &Q, hash: u64) -> Option<(usize, usize)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_by_exact_schedule(
            key,
            PreparedElasticRoute::new(hash),
            |route| control::control_fingerprint_low(route.key_hash()),
            |level, slot, _entry| (level, slot),
        )
    }

    #[inline]
    fn find_entry<'a, Q>(&'a self, key: &Q, hash: u64) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_by_exact_schedule(
            key,
            PreparedElasticRoute::new(hash),
            |route| control::control_fingerprint_low(route.key_hash()),
            |_level, _slot, entry| entry,
        )
    }

    /// [`Self::find_by_exact_schedule`] with the walk and the lookup off
    /// the schedule each handing on the value, where
    /// [`Self::find_after_filter`] hands both an entry.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn find_value<'a, Q>(&'a self, key: &Q, hash: u64) -> Option<&'a V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
        K: 'a,
    {
        let prepared = PreparedElasticRoute::new(hash);
        let filter = self.route_filter(prepared);
        if !filter.maybe_present {
            return None;
        }
        let key_fingerprint = control::control_fingerprint_low(hash);
        // Every way to an answer ends on the value itself, so the lookup
        // off the schedule returns in this one's place.
        let walked =
            self.walk_schedule(key, prepared, key_fingerprint, filter, |_, _, entry, _| {
                // SAFETY: the walk hands on an occupied slot of this table,
                // which `&'a self` keeps from changing.
                unsafe { &(*entry).value }
            });
        match walked {
            ScheduleSearch::Hit(value) => Some(value),
            ScheduleSearch::Absent => None,
            ScheduleSearch::Unresolved => {
                self.find_unresolved(key, prepared, key_fingerprint, filter, |_, _, entry| {
                    &entry.value
                })
            }
        }
    }

    #[inline]
    fn find_for_entry<Q>(&self, key: &Q, hash: u64) -> Result<Self::Location, u64>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find(key, hash).ok_or(hash)
    }

    #[inline]
    fn insert_for_vacant(&mut self, key: K, value: V, hash: u64) -> (usize, usize) {
        self.insert_for_vacant_entry(key, value, hash)
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn insert(&mut self, key: K, value: V, hash: u64) -> Option<V>
    where
        K: Hash + Eq,
    {
        let prepared = PreparedElasticRoute::new(hash);
        let key_fingerprint = control::control_fingerprint_low(hash);
        // Every way off the common path meets in one call, which tells them
        // apart itself.
        'common: {
            let filter = self.route_filter(prepared);
            let mut read = filter.read;
            if filter.maybe_present {
                let walked = self.walk_schedule(
                    &key,
                    prepared,
                    key_fingerprint,
                    filter,
                    |_, _, entry, _| entry,
                );
                match walked {
                    ScheduleSearch::Hit(entry) => {
                        // SAFETY: the walk hands on an occupied slot of this
                        // table, which `&mut self` borrows alone.
                        let slot: &mut SlotEntry<K, V> = unsafe { &mut *entry };
                        return Some(mem::replace(&mut slot.value, value));
                    }
                    // The lane holds the key's bit, so the insert marks
                    // its pair.
                    ScheduleSearch::Absent => read.bits = read.place.bits_with_pair(),
                    ScheduleSearch::Unresolved => break 'common,
                }
            }
            // A closed gate leaves the insert to the call below, which
            // reopens it where it may open.
            if self.scheduler.settles(self.placed) {
                // SAFETY: the gate is open.
                let Some(found) = (unsafe { self.settled_level_slot(prepared.probe) }) else {
                    // SAFETY: the gate is open.
                    unsafe { self.insert_unsettled(key, value, prepared, key_fingerprint) };
                    return None;
                };
                // SAFETY: the settled search returns one of this table's
                // levels with its words, and a free slot of it with its
                // control byte.
                unsafe {
                    self.write_new_entry_at::<true>(key, value, key_fingerprint, found, read);
                }
                return None;
            }
        }
        self.insert_slow(key, value, prepared, key_fingerprint)
    }

    fn remove(&mut self, (level_idx, slot_idx): (usize, usize)) -> (K, V) {
        // SAFETY: `TableBackend::Location` contract: a live location from
        // this table names an occupied in-bounds slot of one of its levels.
        let removed = unsafe { self.levels.get_unchecked_mut(level_idx).take(slot_idx) };
        self.extract_finish((level_idx, slot_idx));
        if self.maintenance_is_due() {
            self.maintain_after_deletes();
        }
        (removed.key, removed.value)
    }

    #[inline]
    fn take<Q>(&mut self, key: &Q, hash: u64) -> Option<(K, V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.take_as(key, hash, |key, value| (key, value))
    }

    // Forced inline, as `take_as` is: the shell's removal is the one
    // function boundary a removal has.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn take_value<Q>(&mut self, key: &Q, hash: u64) -> Option<V>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.take_as(key, hash, |_, value| value)
    }

    #[inline]
    fn tombstone_slot(&mut self, (level_idx, slot_idx): (usize, usize)) {
        // SAFETY: a live location names an in-bounds slot.
        unsafe { self.levels[level_idx].mark_tombstone(slot_idx) };
    }

    #[inline]
    fn extract_finish(&mut self, (level_idx, slot_idx): (usize, usize)) {
        {
            // SAFETY: a live location names one of this table's levels.
            let level = unsafe { self.levels.get_unchecked_mut(level_idx) };
            // SAFETY: and an in-bounds slot of it.
            unsafe { level.mark_tombstone(slot_idx) };
            level.counters_mut().remove_one();
            debug_assert!(
                level.tombstones() <= level.capacity,
                "a level counts more tombstones than it has slots"
            );
        }
        self.scheduler.note_removal();
    }

    fn finish_deferred_removals(&mut self) {
        if self.maintenance_is_due() || self.levels.iter().any(Level::needs_cleanup) {
            self.maintain_after_deletes();
        }
    }

    type Scan = ElasticScan;

    #[inline]
    fn scan(&self) -> ElasticScan {
        ElasticScan {
            level_idx: 0,
            slots: OccupiedIndices::new(),
        }
    }

    #[inline]
    fn scan_next(&self, scan: &mut ElasticScan) -> Option<ElasticScanItem<K, V>> {
        while let Some(level) = self.levels.get(scan.level_idx) {
            if let Some(slot_idx) = scan.slots.step(level) {
                // SAFETY: `step` yields in-bounds slots.
                let slot = unsafe { level.slot_ptr(slot_idx) };
                return Some((slot, (scan.level_idx, slot_idx)));
            }
            scan.level_idx += 1;
            scan.slots = OccupiedIndices::new();
        }
        None
    }

    #[inline]
    fn with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        Self::with_capacity_and_reserve_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            alloc,
        )
    }

    #[inline]
    fn try_with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        Self::try_with_capacity_and_reserve_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            alloc,
        )
    }

    #[inline]
    fn resize(&mut self, new_capacity: usize) {
        self.resize(new_capacity);
    }

    #[inline]
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError> {
        self.try_resize(new_capacity)
    }

    #[inline]
    fn clear(&mut self) {
        self.clear();
    }

    fn wipe_all(&mut self) {
        for level in &mut self.levels {
            level.clear_all_controls();
            *level.counters_mut() = LevelCounters::default();
        }
        self.placed = self.stale_membership();
        self.uncounted = Uncounted::none_at(self.placed);
        self.reset_after_clear();
    }

    fn clone_table(&self) -> Self
    where
        K: Clone,
        V: Clone,
        S: Clone,
    {
        let scheduler = self.scheduler.clone();
        let hash_builder = self.hash_builder.clone();
        let alloc = self.alloc.clone();
        let level_capacities = PlanBuffer::from_iter(self.levels.iter().map(ArenaSlots::capacity));
        let (arena, levels, membership) =
            alloc_elastic_arena(&level_capacities, self.reserve_fraction, &self.alloc);

        // If a user `K::clone` / `V::clone` panics, the guard drops the
        // already-cloned values and frees the arena; see `ArenaDropGuard`.
        let mut guard = arena::ArenaDropGuard::new(arena, levels, self.alloc.clone());

        for (dst, src_lvl) in guard.regions_mut().iter_mut().zip(self.levels.iter()) {
            dst.clone_region_from(src_lvl);
            *dst.counters_mut() = *src_lvl.counters();
            dst.scheduled_probes = src_lvl.scheduled_probes;
        }

        let regions = guard.regions_mut();
        let probe_schedule = self.probe_schedule.clone_onto(regions);

        // Success: reclaim arena + levels so the guard's Drop no-ops.
        let (arena, levels) = guard.disarm();

        let mut cloned = Self {
            levels,
            placed: self.placed,
            total_slots: self.total_slots,
            max_insertions: self.max_insertions,
            reserve_fraction: self.reserve_fraction,
            scheduler,
            hash_builder,
            alloc,
            metadata_scale: MetadataPlace::scale(membership.words),
            metadata_words: metadata_words(&arena, membership),
            arena,
            epoch: self.epoch,
            probe_high_water: self.probe_high_water,
            scheduled_levels: self.scheduled_levels,
            uncounted: self.uncounted,
            probe_schedule,
            settled_level: ptr::null_mut(),
            settled_fallback: ptr::null_mut(),
            fold_multiplier: probe::ELASTIC_FOLD_MULTIPLIER,
            membership,
        };
        // The copied gate is open on the source's settled level, whose
        // uncounted inserts the copy counts.
        cloned.scheduler.close();
        if self.uncounted.pending(self.placed) != 0 {
            // SAFETY: an uncounted insert went into the settled level, one
            // of the levels, and the copy has the same levels.
            let settled = unsafe {
                self.settled_level
                    .offset_from_unsigned(self.levels.as_ptr())
            };
            cloned.uncounted.count_into(
                cloned.placed,
                &mut cloned.levels[settled].counters_mut().len,
            );
        }
        cloned.copy_membership_from(self);
        cloned
    }
}

/// Track a pointerless scan across elastic levels.
#[derive(Clone, Debug)]
pub struct ElasticScan {
    level_idx: usize,
    slots: OccupiedIndices,
}

impl<K, V, S, A> ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Departed keys reached [`membership::refresh_deletes`], so the deletes
    /// since the last maintenance pay for a pass over the live entries.
    #[inline]
    fn maintenance_is_due(&self) -> bool {
        self.scheduler.maintenance_is_due()
    }

    /// Deletes since the filter last matched the live set. They are also the
    /// deletes the epoch has not counted yet.
    fn stale_membership(&self) -> usize {
        self.scheduler
            .removed(membership::refresh_deletes(self.max_insertions))
    }

    /// [`map::TableBackend::take`] with the removed pair handed through
    /// `project`. Both ways off the common path leave before anything is
    /// written and end in one call that returns the answer itself, so the
    /// removal keeps nothing across it.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn take_as<Q, R>(&mut self, key: &Q, hash: u64, project: impl Fn(K, V) -> R) -> Option<R>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let prepared = PreparedElasticRoute::new(hash);
        let filter = self.route_filter(prepared);
        if !filter.maybe_present {
            // A removal mostly names a key the table holds.
            unlikely_path();
            return None;
        }
        let read = filter.read;
        let key_fingerprint = control::control_fingerprint_low(hash);
        let walked = self.walk_schedule(
            key,
            prepared,
            key_fingerprint,
            filter,
            |_, slot, entry, control| (slot, entry, control),
        );
        let (slot, entry, control) = match walked {
            ScheduleSearch::Hit(hit) if !self.scheduler.next_removal_is_due() => hit,
            ScheduleSearch::Absent => return None,
            ScheduleSearch::Hit(_) | ScheduleSearch::Unresolved => {
                return self.take_off_schedule(key, hash, key_fingerprint, project);
            }
        };
        self.scheduler.note_removal();
        // SAFETY: the walk hands on an occupied slot of one of this table's
        // levels, which `&mut self` borrows alone. The tombstone below keeps
        // the entry from being read again.
        let removed = unsafe { entry.read() };
        // SAFETY: `control` is that level's control bytes, which the table
        // owns and may write, and `slot` indexes them. The sentinel's are
        // never handed on: they match no fingerprint.
        unsafe { control.cast_mut().add(slot).write(control::CTRL_TOMBSTONE) };
        // SAFETY: `control` is the control bytes of one of this table's
        // levels, which its counters precede, and `&mut self` borrows them
        // alone.
        unsafe { (*level_counters(control.cast_mut())).remove_one() };
        debug_assert!(
            self.levels
                .iter()
                .all(|level| level.tombstones() <= level.capacity),
            "a level counts more tombstones than it has slots"
        );
        // SAFETY: the filter read the key's lane with the key present, and
        // nothing has recorded a key since.
        unsafe { self.forget_membership(read) };
        Some(project(removed.key, removed.value))
    }

    /// [`Self::take_as`] by location: for a key the walk left unresolved,
    /// and for the removal that makes delete maintenance due, which walks
    /// to its key again.
    #[cold]
    #[inline(never)]
    fn take_off_schedule<Q, R>(
        &mut self,
        key: &Q,
        hash: u64,
        key_fingerprint: u8,
        project: impl Fn(K, V) -> R,
    ) -> Option<R>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let prepared = PreparedElasticRoute::new(hash);
        let location = if self.walk_ends_unresolved() {
            let filter = self.route_filter(prepared);
            self.find_unresolved(key, prepared, key_fingerprint, filter, |level, slot, _| {
                (level, slot)
            })?
        } else {
            self.find_by_exact_schedule(
                key,
                prepared,
                |_| key_fingerprint,
                |level, slot, _| (level, slot),
            )?
        };
        let (key, value) = map::TableBackend::remove(self, location);
        Some(project(key, value))
    }

    /// Same-size cleanup when a level passed its tombstone threshold;
    /// otherwise a filter refresh. The cleanup rebuilds the filter too, so
    /// the two never stack.
    ///
    /// A single removal runs this only once [`Self::maintenance_is_due`], so
    /// removals alone rebuild at most once per capacity's worth of deletes.
    /// Tombstones cost a removal nothing and a present key's lookup nothing;
    /// the insert that reuses one in a level past its threshold asks for the
    /// cleanup through [`BatchScheduler::reuse_tombstone`].
    #[cold]
    #[inline(never)]
    fn maintain_after_deletes(&mut self) {
        if self.levels.iter().any(Level::needs_cleanup) {
            self.resize_with_transition(self.total_slots, EpochTransition::TombstoneCleanup);
        } else {
            self.refresh_membership();
        }
    }

    /// Moves the scheduler to the batch of the live count, first cleaning up
    /// a level past its tombstone threshold. Runs when the cached batch no
    /// longer covers the live count, which an insert that reused a tombstone
    /// in such a level forces.
    #[cold]
    #[inline(never)]
    fn enter_batch(&mut self) {
        if self.levels.iter().any(Level::needs_cleanup) {
            self.resize_with_transition(self.total_slots, EpochTransition::TombstoneCleanup);
        }
        self.scheduler.sync(self.live());
    }

    /// Re-record the filter from the live entries, dropping the bits departed
    /// keys left behind. Entries stay put; only the metadata tail is rewritten.
    /// A key's hasher that unwinds leaves the filter saturated, so every live
    /// key still passes it.
    #[cold]
    #[inline(never)]
    fn refresh_membership(&mut self) {
        self.epoch.note_deletes(self.stale_membership());
        self.clear_membership();
        let guard = SaturateOnUnwind(self);
        let table = &mut *guard.0;
        for level_idx in 0..table.levels.len() {
            let mut scan = OccupiedIndices::new();
            while let Some(slot_idx) = scan.step(&table.levels[level_idx]) {
                let hash = {
                    // SAFETY: `step` yields occupied in-bounds slots.
                    let entry = unsafe { table.levels[level_idx].get_ref(slot_idx) };
                    table.hash_builder.hash_one(&entry.key)
                };
                let prepared = PreparedElasticRoute::new(hash);
                let summary_bit = table.levels[level_idx].summary_bit();
                table.record_membership(prepared, summary_bit);
            }
        }
        mem::forget(guard);
    }

    /// Rebuilds levels at `new_capacity` and moves every live entry across.
    /// Passing the current capacity flushes tombstones without growing.
    fn resize(&mut self, new_capacity: usize) {
        self.resize_with_transition(new_capacity, EpochTransition::ExplicitResize);
    }

    fn resize_with_transition(&mut self, new_capacity: usize, transition: EpochTransition) {
        let geometry = ElasticGeometry::for_slots(new_capacity, self.reserve_fraction)
            .expect("capacity overflow");
        if self.try_resize_to(&geometry, transition).is_err() {
            handle_elastic_alloc_error::<K, V>(&geometry.level_capacities);
        }
    }

    /// Moves every entry into fresh levels for `geometry`. Each key is hashed
    /// in place before its entry is copied, and the old levels are freed only
    /// after the last copy, so `Err` or a panicking hasher leaves the table
    /// intact.
    fn try_resize_to(
        &mut self,
        geometry: &ElasticGeometry,
        transition: EpochTransition,
    ) -> Result<(), TryReserveError> {
        let schedule_room = ProbeScheduleRoom::try_for_levels(geometry.level_capacities.len())?;
        let (arena, levels, membership) = try_alloc_elastic_arena(
            &geometry.level_capacities,
            self.reserve_fraction,
            &self.alloc,
        )?;
        let settled_limit = settled_limit(
            &levels,
            geometry.batch_plan.len,
            membership,
            geometry.max_insertions,
        );
        let probe_schedule = schedule_room.schedule(&levels);
        let used_exceptional_placement = rebuild::rebuild(
            self,
            ElasticGeneration {
                levels,
                placed: 0,
                uncounted: Uncounted::default(),
                total_slots: geometry.total_slots,
                max_insertions: geometry.max_insertions,
                scheduler: BatchScheduler::new(
                    &geometry.batch_plan,
                    settled_limit,
                    membership::refresh_deletes(geometry.max_insertions),
                ),
                metadata_scale: MetadataPlace::scale(membership.words),
                metadata_words: metadata_words(&arena, membership),
                arena,
                probe_high_water: empty_high_water(settled_limit),
                scheduled_levels: 0,
                probe_schedule,
                membership,
            },
        );
        self.epoch.start_epoch(
            transition,
            transition == EpochTransition::PlacementRecovery || used_exceptional_placement,
        );
        Ok(())
    }

    /// Fallible counterpart to [`Self::resize`]; `Err` leaves the map intact.
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError> {
        let geometry = ElasticGeometry::for_slots(new_capacity, self.reserve_fraction)
            .ok_or(TryReserveError::CapacityOverflow)?;
        self.try_resize_to(&geometry, EpochTransition::ExplicitResize)
    }

    /// Test constructor taking a raw slot count; public constructors take an
    /// insertion budget and inflate it via `capacity_for`.
    #[cfg(test)]
    fn try_with_slots_and_reserve_fraction_and_hasher_in(
        slots: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let geometry = ElasticGeometry::for_slots(slots, reserve_fraction)
            .ok_or(TryReserveError::CapacityOverflow)?;
        Self::try_from_geometry(&geometry, reserve_fraction, hash_builder, alloc)
    }

    /// Retries placement on every other batch target, shallowest first.
    /// Batches follow the live count, so after deletes the active pair can be
    /// one that earlier batches filled while other levels have room again.
    /// A trace without deletes gets here only when a key's probes in its
    /// active pair all land on occupied slots.
    fn choose_slot_on_other_targets(
        &self,
        probe: PreparedElasticProbe,
        target: BatchTarget,
    ) -> Option<ExactPlacement> {
        let has_room = |level: usize| {
            self.levels
                .get(level)
                .is_some_and(|l| l.free_slots(self.live_in(l)) > 0)
        };
        let pairs = self.levels.len().saturating_sub(1);
        core::iter::once(BatchTarget::Bootstrap)
            .chain((0..pairs).map(BatchTarget::LevelPair))
            .filter(|&candidate| candidate != target)
            .filter(|&candidate| match candidate {
                BatchTarget::Bootstrap => has_room(0),
                BatchTarget::LevelPair(current) => has_room(current) || has_room(current + 1),
            })
            .find_map(|candidate| self.choose_slot_for_new_key(probe, candidate))
    }

    fn choose_slot_for_new_key(
        &self,
        probe: PreparedElasticProbe,
        target: BatchTarget,
    ) -> Option<ExactPlacement> {
        self.choose_slot_with::<false>(target, |level, budget| {
            self.first_vacancy(probe, level, budget)
        })
    }

    /// [`Self::choose_slot_for_new_key`] without the search of a level the
    /// case already counts as full, which finds nothing.
    fn choose_slot_for_insert(
        &self,
        probe: PreparedElasticProbe,
        target: BatchTarget,
    ) -> Option<ExactPlacement> {
        self.choose_slot_with::<true>(target, |level, budget| {
            self.first_vacancy(probe, level, budget)
        })
    }

    /// The paper's insertion case for `target`. `budget_of` turns the
    /// case's probe bound for its level, `None` when the case sets none,
    /// into the budget the caller searches with; resolving it per case
    /// lets an unbounded case skip the comparison against a bound.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn placement_case(
        &self,
        target: BatchTarget,
        budget_of: impl Fn(&Level<SlotEntry<K, V>>, Option<u64>) -> u64,
    ) -> Option<PlacementCase<'_, K, V>> {
        // The paper's insertion cases, in order: Batch 0 fills level 0; then,
        // for the active pair, Case 2 (current nearly full) places in `next`,
        // Case 3 (next nearly full) in `current`, and Case 1 gives `current`
        // a bounded probe budget before falling back to `next`.
        Some(match target {
            BatchTarget::Bootstrap => PlacementCase {
                level: 0,
                region: self.levels.first()?,
                budget: budget_of(self.levels.first()?, None),
                fallback: None,
                full: false,
            },
            BatchTarget::LevelPair(current) => {
                let next = current.checked_add(1)?;
                let [current_level, next_level] = self.levels.get(current..=next)? else {
                    return None;
                };
                let free_next = next_level.free_slots(self.live_in(next_level));
                let current_low = current_level.low(self.live_in(current_level));
                let next_low = free_next.saturating_mul(4) <= next_level.capacity();

                if current_low {
                    PlacementCase {
                        level: next,
                        region: next_level,
                        budget: budget_of(next_level, None),
                        fallback: None,
                        full: free_next == 0,
                    }
                } else if next_low {
                    PlacementCase {
                        level: current,
                        region: current_level,
                        budget: budget_of(current_level, None),
                        fallback: None,
                        full: false,
                    }
                } else {
                    // Not low, so the level has a free slot.
                    let budget = probe::elastic_level_probe_budget(
                        current_level.capacity - self.live_in(current_level),
                        current_level.capacity,
                        self.reserve_fraction.exponent(),
                        ELASTIC_PROBE_BUDGET_C,
                    );
                    PlacementCase {
                        level: current,
                        region: current_level,
                        budget: budget_of(current_level, Some(budget)),
                        fallback: Some(next),
                        full: false,
                    }
                }
            }
        })
    }

    /// Chooses `target`'s slot for a new key. `first_vacancy(level, budget)`
    /// yields the first free slot among `level`'s first `budget` probes and
    /// the one-based probe that reached it. `SKIP_FULL` answers for a level
    /// the case counts as full without searching it.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn choose_slot_with<const SKIP_FULL: bool>(
        &self,
        target: BatchTarget,
        first_vacancy: impl Fn(usize, u64) -> Option<(usize, u64)>,
    ) -> Option<ExactPlacement> {
        let PlacementCase {
            mut level,
            mut budget,
            mut fallback,
            full,
            ..
        } = self.placement_case(target, |_, budget| budget.unwrap_or(u64::MAX))?;
        if SKIP_FULL && full {
            return None;
        }
        // One search site serves every case, so the search inlines once.
        let (slot, paper_probe) = loop {
            let limit = *LEVEL_PROBE_LIMIT.get(level)?;
            if let Some(found) = first_vacancy(level, budget.min(limit)) {
                break found;
            }
            level = fallback.take()?;
            budget = u64::MAX;
        };
        // Every vacancy search stops within `LEVEL_PROBE_LIMIT`, whose probes
        // all sit at positions up to `QUERY_POSITION_CAP`.
        Some(ExactPlacement {
            level,
            slot,
            paper_probe,
        })
    }

    /// The first free slot among `level`'s first `budget` probes, in probe
    /// order, with the one-based probe that reached it.
    fn first_vacancy(
        &self,
        probe: PreparedElasticProbe,
        level: usize,
        budget: u64,
    ) -> Option<(usize, u64)> {
        let region = self.levels.get(level)?;
        if region.index_shift() == GENERAL_REDUCTION {
            return self.first_vacancy_general(probe, level, budget);
        }
        // SAFETY: the level reduces by shift.
        unsafe { self.first_shifted_vacancy(probe, level, region, budget) }
    }

    /// [`Self::first_vacancy`] for a level that reduces by shift.
    ///
    /// # Safety
    ///
    /// `region` must be this table's `level`, and must not be marked
    /// [`GENERAL_REDUCTION`].
    #[allow(clippy::inline_always)]
    #[inline(always)]
    unsafe fn first_shifted_vacancy(
        &self,
        probe: PreparedElasticProbe,
        level: usize,
        region: &Level<SlotEntry<K, V>>,
        budget: u64,
    ) -> Option<(usize, u64)> {
        debug_assert!(core::ptr::eq(region, &raw const self.levels[level]));
        let index_shift = region.index_shift();
        debug_assert!(index_shift < u64::BITS);
        // SAFETY: a shift other than `GENERAL_REDUCTION` is
        // `probe::elastic_index_shift` of the capacity, below the word width.
        unsafe { core::hint::assert_unchecked(index_shift < u64::BITS) };
        let sequence = probe.sequence(self.fold_multiplier);
        let (mut word, word_step) = sequence.run_words(region.sequence_run);
        let mut remaining = budget;
        while remaining != 0 {
            let slot = probe::shifted_elastic_index(word, index_shift);
            // SAFETY: the caller's shift maps the index into the level's
            // capacity.
            let control = unsafe { region.control_at(slot) };
            if control::is_free(control) {
                return Some((slot, budget - remaining + 1));
            }
            word = word.wrapping_add(word_step);
            remaining -= 1;
        }
        None
    }

    /// [`Self::first_vacancy`] for a table whose levels need the general
    /// range reduction.
    #[inline(never)]
    fn first_vacancy_general(
        &self,
        probe: PreparedElasticProbe,
        level: usize,
        budget: u64,
    ) -> Option<(usize, u64)> {
        (0..budget).find_map(|logical_index| {
            self.vacancy(level, probe, logical_index)
                .map(|slot| (slot, logical_index + 1))
        })
    }

    fn vacancy(
        &self,
        level: usize,
        probe: PreparedElasticProbe,
        logical_index: u64,
    ) -> Option<usize> {
        let slot = self.route_prepared(level, probe, logical_index)?;
        // SAFETY: `route_prepared` maps into the level's capacity.
        control::is_free(unsafe { self.levels[level].control_at(slot) }).then_some(slot)
    }

    fn route_prepared(
        &self,
        level: usize,
        probe: PreparedElasticProbe,
        logical_index: u64,
    ) -> Option<usize> {
        let level = u32::try_from(level).ok()?;
        let counter_base = probe::elastic_counter_base(level, logical_index);
        self.route_prepared_counter(level as usize, probe, counter_base)
    }

    #[inline]
    fn route_prepared_counter(
        &self,
        level: usize,
        probe: PreparedElasticProbe,
        counter_base: u32,
    ) -> Option<usize> {
        let upper = self.levels.get(level)?.capacity();
        Self::route_prepared_counter_for_upper(probe, counter_base, upper)
    }

    #[inline]
    fn route_prepared_counter_for_upper(
        prepared: PreparedElasticProbe,
        counter_base: u32,
        upper: usize,
    ) -> Option<usize> {
        probe::unbiased_prepared_elastic_probe_index(
            prepared,
            counter_base,
            upper,
            probe::RANGE_WORD_CAP,
        )
        .ok()
        .map(|probe| probe.index)
    }

    #[cfg(test)]
    fn find_slot_indices_prepared<Q>(
        &self,
        key: &Q,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
    ) -> Option<(usize, usize)>
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.find_by_exact_schedule(
            key,
            prepared,
            |_| key_fingerprint,
            |level, slot, _entry| (level, slot),
        )
    }

    #[cfg(test)]
    fn find_entry_prepared<'a, Q>(
        &'a self,
        key: &Q,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
    ) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.find_by_exact_schedule(
            key,
            prepared,
            |_| key_fingerprint,
            |_level, _slot, entry| entry,
        )
    }

    /// Looks the key up along its schedule. The filter is tested where the
    /// caller is, so a key it rejects costs no call and derives no
    /// fingerprint.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn find_by_exact_schedule<'a, Q, R>(
        &'a self,
        key: &Q,
        prepared: PreparedElasticRoute,
        key_fingerprint: impl FnOnce(PreparedElasticRoute) -> u8,
        on_hit: impl FnMut(usize, usize, &'a SlotEntry<K, V>) -> R,
    ) -> Option<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // A key the filter never recorded was never inserted, so neither the
        // candidates nor the exceptional full scan can hold it.
        let filter = self.route_filter(prepared);
        if !filter.maybe_present {
            return None;
        }
        self.find_after_filter(key, prepared, key_fingerprint, filter, on_hit)
    }

    /// The lookup of a key that passed `filter`: the schedule walk, then the
    /// general schedule for a walk that ends unresolved.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn find_after_filter<'a, Q, R>(
        &'a self,
        key: &Q,
        route: PreparedElasticRoute,
        key_fingerprint: impl FnOnce(PreparedElasticRoute) -> u8,
        filter: ElasticRouteFilter<'_>,
        mut on_hit: impl FnMut(usize, usize, &'a SlotEntry<K, V>) -> R,
    ) -> Option<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let key_fingerprint = key_fingerprint(route);
        let walked = self.walk_schedule(
            key,
            route,
            key_fingerprint,
            filter,
            |level, slot, entry, _| (level, slot, entry),
        );
        match walked {
            ScheduleSearch::Hit((level, slot, entry)) => {
                // SAFETY: the walk hands on an occupied slot of this table,
                // which `&'a self` keeps from changing.
                Some(on_hit(level, slot, unsafe { &*entry }))
            }
            ScheduleSearch::Absent => None,
            ScheduleSearch::Unresolved => {
                self.find_unresolved(key, route, key_fingerprint, filter, on_hit)
            }
        }
    }

    /// [`Self::find_by_general_schedule`] for a table whose walk can end
    /// unresolved ([`Self::walk_ends_unresolved`]). Out of line with the
    /// filter, so the summary is read here and the walk keeps no copy of it
    /// for this path.
    #[inline(never)]
    fn find_unresolved<'a, Q, R>(
        &'a self,
        key: &Q,
        route: PreparedElasticRoute,
        key_fingerprint: u8,
        filter: ElasticRouteFilter<'_>,
        on_hit: impl FnMut(usize, usize, &'a SlotEntry<K, V>) -> R,
    ) -> Option<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.find_by_general_schedule(
            key,
            route,
            filter.expanded_level_mask(),
            key_fingerprint,
            on_hit,
        )
    }

    /// Whether a walk that finds no key leaves it unresolved: a table that
    /// needs the general reduction has routes that probe nothing, and one
    /// that placed a key exceptionally holds it off the schedule.
    #[inline]
    fn walk_ends_unresolved(&self) -> bool {
        self.probe_high_water & WALK_UNRESOLVED_FLAG != 0
    }

    /// Walks the candidates of a key that passed `filter` in schedule order
    /// and hands `on_hit` the level and slot that hold the key, the entry,
    /// and the level's control bytes. A table that needs the general
    /// reduction has routes that probe nothing, so its walk ends unresolved.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn walk_schedule<Q, R>(
        &self,
        key: &Q,
        prepared: PreparedElasticRoute,
        key_fingerprint: u8,
        filter: ElasticRouteFilter<'_>,
        mut on_hit: impl FnMut(usize, usize, *mut SlotEntry<K, V>, *const u8) -> R,
    ) -> ScheduleSearch<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let sequence = prepared.probe.sequence(self.fold_multiplier);
        let (index_shift, direct_control, direct_entries) = self.probe_schedule.direct_reach();
        let h11_slot = probe::masked_shift_elastic_index(sequence.word(0), index_shift);
        // SAFETY: the direct route's shifted index maps into the control
        // bytes it holds.
        if unsafe { *direct_control.add(h11_slot) } == key_fingerprint {
            let entry: *mut SlotEntry<K, V> = ProbeSchedule::direct_entry(direct_entries, h11_slot);
            // SAFETY: only a level's own control bytes hold a fingerprint,
            // and one marks an occupied slot, so the slot holds an entry,
            // level zero's at the slot's index.
            if key.equivalent(unsafe { found_key(entry) }) {
                return ScheduleSearch::Hit(on_hit(0, h11_slot, entry, direct_control));
            }
        }

        let summary = filter.summary();
        let (entry_origin, start) = self.probe_schedule.walk_reach(summary);
        match start.run() {
            Ok(mut run) => loop {
                // SAFETY: a sentinel closes the run, and the walk cannot
                // pass it: its probe reads `EMPTY` and ends the walk below.
                // So the walk is ahead of that sentinel here.
                let sequence_index = unsafe { run.step() };
                let route = run.route();
                // SAFETY: the walk has stepped, so `route` is a route of the
                // schedule, at most the sentinel.
                let (index_shift, level_control) = unsafe { PhiRoute::reach(route) };
                let slot = probe::masked_shift_elastic_index(
                    sequence.word_at(sequence_index),
                    index_shift,
                );
                // SAFETY: the route's shifted index maps into the control
                // bytes it holds.
                let control = unsafe { *level_control.add(slot) };
                if control == key_fingerprint {
                    let entry: *mut SlotEntry<K, V> =
                        ProbeSchedule::entry_at(entry_origin, level_control, slot);
                    // SAFETY: the sentinel's control bytes match no
                    // fingerprint, so the route names a real level, and a
                    // fingerprint match means the slot is occupied and
                    // holds an entry.
                    if key.equivalent(unsafe { found_key(entry) }) {
                        // SAFETY: as above.
                        let level = unsafe { (*route).level() };
                        return ScheduleSearch::Hit(on_hit(
                            level as usize,
                            slot,
                            entry,
                            level_control,
                        ));
                    }
                    unlikely_path();
                } else if control == CTRL_EMPTY {
                    // The run's level has no later probe to hold the key,
                    // as below, and the walk has no other level to visit.
                    break;
                }
            },
            Err(direct) => {
                let mut closed_levels = schedule::closed_levels(summary);
                let mut route = direct;
                loop {
                    // SAFETY: a sentinel closes the routes after the direct
                    // route, and the walk cannot pass it: the sentinel's
                    // level stays open until its own probe, which reads
                    // `EMPTY` and ends the walk below. So `route` is ahead
                    // of that sentinel here.
                    let step = unsafe { PhiRoute::step(&mut route) };
                    if step.is_closed(closed_levels) {
                        continue;
                    }
                    // SAFETY: as above, `route` is at most the sentinel.
                    let (index_shift, level_control) = unsafe { PhiRoute::reach(route) };
                    // The route holds a shift whichever reduction its level
                    // needs.
                    let slot = probe::masked_shift_elastic_index(
                        sequence.word_at(step.sequence_index()),
                        index_shift,
                    );
                    // SAFETY: the route's shifted index maps into the
                    // control bytes it holds.
                    let control = unsafe { *level_control.add(slot) };
                    if control == key_fingerprint {
                        let entry: *mut SlotEntry<K, V> =
                            ProbeSchedule::entry_at(entry_origin, level_control, slot);
                        // SAFETY: the sentinel's control bytes match no
                        // fingerprint, so the route names a real level, and
                        // a fingerprint match means the slot is occupied and
                        // holds an entry.
                        if key.equivalent(unsafe { found_key(entry) }) {
                            // SAFETY: as above.
                            let level = unsafe { (*route).level() };
                            return ScheduleSearch::Hit(on_hit(
                                level as usize,
                                slot,
                                entry,
                                level_control,
                            ));
                        }
                        unlikely_path();
                    } else if control == CTRL_EMPTY {
                        // A key takes its level's first free probe, and a
                        // slot returns to `EMPTY` only when its whole level
                        // is reset: a removal leaves a tombstone, and so
                        // does a `clear` until its last entry is out, even
                        // one a panicking drop interrupts. So the key cannot
                        // sit at a later probe of this level.
                        closed_levels = step.close(closed_levels);
                        // Either this was the sentinel, or no real level is
                        // left open.
                        if closed_levels & SENTINEL_BIT != 0 || closed_levels == !SENTINEL_BIT {
                            break;
                        }
                    }
                }
            }
        }
        if self.walk_ends_unresolved() {
            ScheduleSearch::Unresolved
        } else {
            ScheduleSearch::Absent
        }
    }

    /// The schedule walk from the first candidate, for a key that passed the
    /// filter and that [`Self::walk_schedule`] left unresolved: the table
    /// needs the general range reduction or placed an entry outside its
    /// probe routes.
    #[inline(never)]
    fn find_by_general_schedule<'a, Q, R>(
        &'a self,
        key: &Q,
        prepared: PreparedElasticRoute,
        level_mask: u64,
        key_fingerprint: u8,
        mut on_hit: impl FnMut(usize, usize, &'a SlotEntry<K, V>) -> R,
    ) -> Option<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let Some(h11_slot) = Self::route_prepared_counter_for_upper(
            prepared.probe,
            H11_COUNTER_BASE,
            self.levels[0].capacity(),
        ) else {
            return self.find_by_full_scan(key, key_fingerprint, on_hit);
        };
        // SAFETY: the counter route maps into level zero's capacity.
        if let Some(entry) = unsafe { self.entry_if_match(0, h11_slot, key_fingerprint, key) } {
            return Some(on_hit(0, h11_slot, entry));
        }

        for route in self.probe_schedule.routes() {
            let level = route.level() as usize;
            if level_mask & (1_u64 << level) == 0 {
                continue;
            }
            let Some(slot) =
                self.route_prepared_counter(level, prepared.probe, route.counter_base())
            else {
                return self.find_by_full_scan(key, key_fingerprint, on_hit);
            };
            // SAFETY: schedule routes name real levels and the counter route
            // maps into that level's capacity.
            if let Some(entry) = unsafe { self.entry_if_match(level, slot, key_fingerprint, key) } {
                return Some(on_hit(level, slot, entry));
            }
        }
        if self.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG != 0 {
            self.find_by_full_scan(key, key_fingerprint, on_hit)
        } else {
            None
        }
    }

    fn find_by_full_scan<'a, Q, R>(
        &'a self,
        key: &Q,
        key_fingerprint: u8,
        mut on_hit: impl FnMut(usize, usize, &'a SlotEntry<K, V>) -> R,
    ) -> Option<R>
    where
        Q: Equivalent<K> + ?Sized,
    {
        for (level_index, level) in self.levels.iter().enumerate() {
            for slot in 0..level.capacity() {
                if let Some(entry) =
                    // SAFETY: both indices come from iterating the levels.
                    unsafe { self.entry_if_match(level_index, slot, key_fingerprint, key) }
                {
                    return Some(on_hit(level_index, slot, entry));
                }
            }
        }
        None
    }

    /// # Safety
    ///
    /// `level < self.levels.len()` and `slot` is within that level's capacity.
    #[inline]
    unsafe fn entry_if_match<'a, Q>(
        &'a self,
        level: usize,
        slot: usize,
        key_fingerprint: u8,
        key: &Q,
    ) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        debug_assert!(level < self.levels.len());
        // SAFETY: caller keeps `level` and `slot` in bounds; a fingerprint
        // match means the slot is occupied.
        unsafe {
            let level = self.levels.get_unchecked(level);
            if level.control_at(slot) != key_fingerprint {
                return None;
            }
            let entry = level.get_ref(slot);
            key.equivalent(&entry.key).then_some(entry)
        }
    }
}

#[cfg(test)]
impl<K, V, S, A> ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn route_exact(&self, level: usize, key_hash: u64, logical_index: u64) -> Option<usize> {
        let probe = CounterPrf::new(ELASTIC_PROBE_SEED).prepare_elastic(key_hash);
        self.levels.get(level)?;
        self.route_prepared(level, probe, logical_index)
    }
}

/// The fields a resize replaces as a unit.
pub(crate) struct ElasticGeneration<K, V> {
    levels: LevelSlice<K, V>,
    placed: usize,
    uncounted: Uncounted,
    total_slots: usize,
    max_insertions: usize,
    scheduler: BatchScheduler,
    arena: Arena,
    probe_high_water: u32,
    scheduled_levels: u32,
    probe_schedule: ProbeSchedule,
    membership: MembershipRegion,
    metadata_scale: u64,
    metadata_words: *mut TailWord,
}

impl<K, V, S, A> Rebuildable for ElasticTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Key = K;
    type Value = V;
    type Region = Level<SlotEntry<K, V>>;
    type Generation = ElasticGeneration<K, V>;

    fn swap_generation(&mut self, other: &mut ElasticGeneration<K, V>) {
        mem::swap(&mut self.levels, &mut other.levels);
        mem::swap(&mut self.placed, &mut other.placed);
        // The uncounted inserts go with the levels they went into, and
        // `settled_level` stays on those: a rebuild places by the general
        // insert, which sets no settled level, so levels put back find it
        // where they left it.
        mem::swap(&mut self.uncounted, &mut other.uncounted);
        debug_assert!(
            self.uncounted.pending(self.placed) == 0
                || self
                    .levels
                    .as_ptr_range()
                    .contains(&self.settled_level.cast_const())
        );
        mem::swap(&mut self.total_slots, &mut other.total_slots);
        mem::swap(&mut self.max_insertions, &mut other.max_insertions);
        mem::swap(&mut self.scheduler, &mut other.scheduler);
        // An open gate goes with the settled level of the levels it left.
        self.scheduler.close();
        other.scheduler.close();
        mem::swap(&mut self.arena, &mut other.arena);
        mem::swap(&mut self.probe_high_water, &mut other.probe_high_water);
        mem::swap(&mut self.scheduled_levels, &mut other.scheduled_levels);
        mem::swap(&mut self.probe_schedule, &mut other.probe_schedule);
        mem::swap(&mut self.membership, &mut other.membership);
        mem::swap(&mut self.metadata_scale, &mut other.metadata_scale);
        mem::swap(&mut self.metadata_words, &mut other.metadata_words);
    }

    fn regions(generation: &ElasticGeneration<K, V>) -> &[Level<SlotEntry<K, V>>] {
        &generation.levels
    }

    fn release(&self, generation: ElasticGeneration<K, V>) {
        generation.arena.deallocate(&self.alloc);
    }

    fn hash_key(&self, key: &K) -> u64 {
        self.hash_builder.hash_one(key)
    }

    #[inline]
    fn prefetch_placement(&self, key_hash: u64) {
        let prepared = PreparedElasticRoute::new(key_hash);
        if self.metadata_scale != 0 {
            let place = MetadataPlace::new(prepared.signature(), self.metadata_scale);
            prefetch::prefetch_write(self.membership_ptr().wrapping_add(place.word()));
        }
        // The level whose first probe `choose_slot_for_new_key` reads, judged
        // from the cached batch; a stale batch only misdirects the hint.
        let level = match self.scheduler.cached_target() {
            BatchTarget::Bootstrap => 0,
            BatchTarget::LevelPair(current) => {
                let Some(current_level) = self.levels.get(current) else {
                    return;
                };
                if current_level.low(self.live_in(current_level)) {
                    current + 1
                } else {
                    current
                }
            }
        };
        if let (Some(region), Some(slot)) = (
            self.levels.get(level),
            self.route_prepared(level, prepared.probe, 0),
        ) {
            region.prefetch_slot(slot);
        }
    }

    /// Skips the existence and capacity checks in `insert`: the new
    /// generation starts all-EMPTY, so neither can succeed. Never sets
    /// `settled_level` ([`Self::reopen_settled`]), which
    /// [`Self::swap_generation`] leaves on the levels a rollback puts back.
    ///
    /// A key its batch's target has no slot for goes to another target, as
    /// an insert's does, and off its probes only when none has one: a key
    /// placed there leaves every walk of the epoch unresolved.
    #[inline]
    fn place_unique(&mut self, entry: SlotEntry<K, V>, key_hash: u64) -> bool {
        let prepared = PreparedElasticRoute::new(key_hash);
        let key_fingerprint = control::control_fingerprint_low(key_hash);
        let target = self.scheduler.target(self.live());
        if let Some(placement) = self.choose_slot_for_new_key(prepared.probe, target) {
            self.place_new_entry(entry.key, entry.value, prepared, key_fingerprint, placement);
            false
        } else {
            self.place_unique_off_target(entry, key_hash)
        }
    }
}

#[cfg(test)]
mod tests;
