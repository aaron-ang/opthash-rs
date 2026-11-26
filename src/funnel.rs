//! Paper-exact Funnel placement with explicit dynamic-map epoch extensions.
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::ptr::{self, NonNull};

use alloc::boxed::Box;
use alloc::vec::Vec;
use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::ReserveFraction;
use crate::capacity;
use crate::epoch::{EpochSnapshot, EpochState, EpochTransition};
use crate::error::{TryBuildError, TryReserveError};
use crate::exact::geometry::{self, PaperConfig};
use crate::exact::probe::{
    self, FUNNEL_SPECIAL_FALLBACK_A_BASE, FUNNEL_SPECIAL_FALLBACK_B_BASE,
    FUNNEL_SPECIAL_PRIMARY_BASE, FunnelPrf, PreparedFastFunnelDomainProbe, PreparedFastFunnelProbe,
    PreparedProbeRange,
};
use crate::hasher::DefaultHashBuilder;
use crate::membership::{self, MembershipRegion};
use crate::raw::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::raw::bitmask::{BITMASK_SLOT_BIT, BITMASK_STRIDE, BitMask, LEAD_ORIGIN};
use crate::raw::config::GROUP_SIZE;
use crate::raw::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE};
use crate::raw::iter::OccupiedIndices;
use crate::raw::prefetch;
use crate::raw::rebuild::{self, Rebuildable};
use crate::raw::simd;
use crate::{macros, map};

/// Initial probe seed; each placement-recovery rebuild advances it by
/// [`FUNNEL_RESEED_STEP`].
const FUNNEL_PROBE_SEED: u64 = probe::WYHASH_DEFAULT_SECRET[3];
/// Added to the probe seed by each placement-recovery rebuild. The seed is
/// added to the key hash ahead of the fold, so a reseed translates every hash
/// by this step.
const FUNNEL_RESEED_STEP: u64 = probe::WYHASH_DEFAULT_SECRET[0];

/// Pointerless scan progress through Funnel's flat storage.
#[derive(Clone, Debug)]
pub struct FunnelScan {
    mode: FunnelScanMode,
}

/// A slot-by-slot scan over the lanes that can hold entries. Below
/// `padded_end` a bucket's group holds its `lanes` lanes and then padding,
/// so the scan runs to `lane_end`, the end of the current bucket's lanes, and
/// then steps to the next group; from `padded_end` on it runs to the end of
/// the slots.
#[derive(Clone, Debug)]
struct DenseScan {
    next: usize,
    lane_end: usize,
    lanes: usize,
    padded_end: usize,
}

#[derive(Clone, Debug)]
enum FunnelScanMode {
    Dense(DenseScan),
    Sparse(OccupiedIndices),
}

/// Entries of [`FunnelTable::head`]: one for each count of leading zeros a
/// [`WideLevelBin`] can have, which is never zero. A level-bin bit's count is
/// its level's index.
const HEAD_ENTRIES: usize = u32::BITS as usize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LevelShape {
    /// See [`FunnelPrf::ordinary_multiplier`].
    multiplier: u64,
    buckets: usize,
    offset: usize,
}

#[derive(Clone, Debug)]
struct FunnelShape {
    max_insertions: usize,
    beta: usize,
    n: usize,
    levels: Box<[LevelShape]>,
    loglog_ceiling: usize,
    primary_offset: usize,
    primary_range: PreparedProbeRange,
    fallback_offset: usize,
    fallback_bucket_width: usize,
    fallback_bucket_range: PreparedProbeRange,
    /// Slots of the storage, padding lanes included; `n` counts the rest.
    slots: usize,
}

// An ordinary level stores the head group of each bucket, one after another,
// then the tail of each. A bucket's head group is a whole group holding its
// first lanes, so the group of bucket `b` is group `b` of its level; a
// bucket no wider than a group pads its head group with lanes that hold
// `CTRL_PADDING` and no entry, and has no tail. The tail holds the lanes
// past the first group's worth, packed, so a level has no padding past its
// head groups.
impl FunnelShape {
    /// The lanes of an ordinary bucket that its head group holds.
    #[inline]
    fn head_width(&self) -> usize {
        self.beta.min(GROUP_SIZE)
    }

    /// The lanes of an ordinary bucket past its head group.
    #[inline]
    fn tail_width(&self) -> usize {
        self.beta - self.head_width()
    }

    /// The first slot of bucket `bucket`'s head group in `level`.
    #[inline]
    fn head_start(level: &LevelShape, bucket: usize) -> usize {
        level.offset + bucket * GROUP_SIZE
    }

    /// The first slot of bucket `bucket`'s tail in `level`.
    #[inline]
    fn tail_start(&self, level: &LevelShape, bucket: usize) -> usize {
        level.offset + level.buckets * GROUP_SIZE + bucket * self.tail_width()
    }
}

/// One level as the first-match lookup and the head placement read it: its
/// draw, and where its buckets start in the control and entry arrays, so
/// neither walk adds the level's offset to a base.
// Declaration order is layout order: a draw reads the multiplier with the
// bucket count, and a scan the two addresses together. The size is a power
// of two on 64-bit targets, so a walk steps between entries by a shift.
#[repr(C)]
struct HeadLevel<T> {
    /// See [`FunnelPrf::ordinary_multiplier`]; zero for an entry that stands
    /// for a level the head does not hold.
    multiplier: u64,
    buckets: usize,
    ctrl: *mut u8,
    /// The entry of lane [`LEAD_ORIGIN`] of the level's first bucket. The
    /// lookup counts a match from a group's lane [`LEAD_ORIGIN`], and from
    /// here that count alone is the entry's offset.
    lead_origin: *mut MaybeUninit<T>,
}

impl<T> Clone for HeadLevel<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for HeadLevel<T> {}

impl<T> HeadLevel<T> {
    /// Whether this entry stands for a level the head does not hold: every
    /// level of a shape without slots, and the overflow levels.
    #[inline]
    fn is_absent(&self) -> bool {
        self.multiplier == 0
    }

    /// Bucket `bucket`'s control group. Addressed in groups so the bucket
    /// index scales in the load that reads it.
    ///
    /// # Safety
    ///
    /// `bucket` is below the level's bucket count, or zero for an entry
    /// that is no level.
    #[inline]
    unsafe fn group(&self, bucket: usize) -> *mut [u8; GROUP_SIZE] {
        // SAFETY: the caller keeps the bucket inside the level.
        unsafe { self.ctrl.cast::<[u8; GROUP_SIZE]>().add(bucket) }
    }

    /// The entry of bucket `bucket`'s lane [`LEAD_ORIGIN`].
    ///
    /// # Safety
    ///
    /// `bucket` is below the level's bucket count, or zero for an entry
    /// that is no level.
    #[inline]
    unsafe fn lead_origin_entry(&self, bucket: usize) -> *mut MaybeUninit<T> {
        // SAFETY: the caller keeps the bucket inside the level.
        unsafe {
            self.lead_origin
                .cast::<[MaybeUninit<T>; GROUP_SIZE]>()
                .add(bucket)
                .cast()
        }
    }

    /// The entry of slot `slot` of the level.
    ///
    /// # Safety
    ///
    /// `slot` is below the level's slot count.
    #[inline]
    unsafe fn entry(&self, slot: usize) -> *mut MaybeUninit<T> {
        // SAFETY: the first bucket's lane `LEAD_ORIGIN` is that many slots
        // into the level, so stepping back that far reaches the level's
        // first slot, and the caller keeps `slot` inside the level.
        unsafe { self.lead_origin.sub(LEAD_ORIGIN).add(slot) }
    }
}

/// The head of a table with `shape` over `storage`: an entry for each level
/// that owns a level-bin bit, addressing the head groups of its buckets,
/// then one for the overflow bit, and absent ones for the counts no bin
/// leads with. A shape without slots has no level, so all its level entries
/// are absent. Every entry that is no level draws bucket zero at the group
/// of [`CTRL_PADDING`] that ends the control array: a scan of it finds no
/// entry and no EMPTY lane, so its data address is never read through.
fn head_levels<T>(shape: &FunnelShape, storage: &FlatStorage<T>) -> [HeadLevel<T>; HEAD_ENTRIES] {
    // In bounds for a shape with slots: the control array holds a group
    // past them. A shape without slots is never scanned.
    let absent = HeadLevel {
        multiplier: 0,
        buckets: 0,
        ctrl: storage.ctrl_ptr().wrapping_add(shape.slots),
        lead_origin: storage.data_ptr().wrapping_add(shape.slots),
    };
    let mut head = [absent; HEAD_ENTRIES];
    if shape.n != 0 {
        for (entry, level) in head
            .iter_mut()
            .zip(shape.levels.iter().take(OVERFLOW_LEVEL))
        {
            *entry = HeadLevel {
                multiplier: level.multiplier,
                buckets: level.buckets,
                // In bounds: the storage holds `shape.slots` slots, and a
                // level starts below that count.
                ctrl: storage.ctrl_ptr().wrapping_add(level.offset),
                // In bounds as well: a level starts with a whole group for
                // each of its buckets.
                lead_origin: storage.data_ptr().wrapping_add(level.offset + LEAD_ORIGIN),
            };
        }
    }
    head
}

impl FunnelShape {
    fn empty() -> Self {
        Self {
            n: 0,
            max_insertions: 0,
            levels: Box::new([]),
            beta: 0,
            loglog_ceiling: 0,
            primary_offset: 0,
            primary_range: PreparedProbeRange::empty(),
            fallback_offset: 0,
            fallback_bucket_width: 0,
            fallback_bucket_range: PreparedProbeRange::empty(),
            slots: 0,
        }
    }

    /// Whether the head placement places in this shape: one with slots
    /// whose buckets have no tail, so a bucket's head group is all of it.
    #[inline]
    fn places_through_head(&self) -> bool {
        self.n != 0 && self.tail_width() == 0
    }

    /// The slot bits of a group mask that are lanes of a bucket the head
    /// placement places in, the rest being its padding. None in a shape it
    /// does not place in.
    fn head_lanes(&self) -> u64 {
        if !self.places_through_head() {
            return 0;
        }
        low_lanes(self.beta)
    }

    /// Entries a table may place through its head.
    fn head_insertions(&self) -> usize {
        if self.places_through_head() {
            self.max_insertions
        } else {
            0
        }
    }

    #[inline]
    fn encode_logical_probe(&self, logical_probe: usize) -> u8 {
        debug_assert!(logical_probe < self.loglog_ceiling);
        #[allow(
            clippy::cast_possible_truncation,
            reason = "shape construction validates the counter lane"
        )]
        {
            logical_probe as u8
        }
    }

    fn from_slots(n: usize, reserve: ReserveFraction) -> Result<Self, TryReserveError> {
        Self::try_from_slots(n, reserve).map_err(TryReserveError::from)
    }

    /// Writes [`CTRL_PADDING`] to the padding lanes of every ordinary bucket
    /// and EMPTY to its other lanes.
    ///
    /// # Safety
    ///
    /// `ctrl_ptr` must be writable for `self.slots` bytes, none of them the
    /// control of an initialized entry.
    unsafe fn reset_ordinary_controls(&self, ctrl_ptr: *mut u8) {
        if self.beta >= GROUP_SIZE {
            return;
        }
        let mut bucket = [CTRL_EMPTY; GROUP_SIZE];
        bucket[self.beta..].fill(CTRL_PADDING);
        for start in (0..self.primary_offset).step_by(GROUP_SIZE) {
            // SAFETY: a bucket narrower than a group is its head group, so
            // the ordinary levels are whole groups below `primary_offset`,
            // itself at most `slots`.
            unsafe { ctrl_ptr.add(start).cast::<[u8; GROUP_SIZE]>().write(bucket) };
        }
    }

    fn try_from_slots(n: usize, reserve: ReserveFraction) -> Result<Self, ShapeError> {
        if n == 0 {
            return Ok(Self::empty());
        }
        let config = PaperConfig::new(n, reserve.exponent()).map_err(|_| ShapeError::Infeasible)?;
        let plan = config.funnel_plan().map_err(|_| ShapeError::Infeasible)?;
        // A bucket's lanes, or its head group if that holds more.
        let bucket_slots = plan.beta().max(GROUP_SIZE);
        let mut offset = 0_usize;
        let mut unpadded = 0_usize;
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(plan.alpha())
            .map_err(|_| ShapeError::Alloc)?;
        for (level_index, bucket_count) in plan.ordinary_bucket_counts().enumerate() {
            // A draw from no buckets would still name bucket zero.
            if bucket_count == 0 {
                return Err(ShapeError::Infeasible);
            }
            levels.push(LevelShape {
                multiplier: FunnelPrf::ordinary_multiplier(level_index as u64)
                    .ok_or(ShapeError::Infeasible)?,
                buckets: bucket_count,
                offset,
            });
            offset = offset
                .checked_add(
                    bucket_count
                        .checked_mul(bucket_slots)
                        .ok_or(ShapeError::Oversize)?,
                )
                .ok_or(ShapeError::Oversize)?;
            // No overflow: at most the padded count above.
            unpadded += bucket_count * plan.beta();
        }
        // The head placement walks its levels unchecked.
        if levels.len() <= OVERFLOW_LEVEL {
            return Err(ShapeError::Infeasible);
        }
        let primary_offset = offset;
        let primary_len = plan.special_primary_len();
        let primary_range =
            PreparedProbeRange::new(primary_len).map_err(|_| ShapeError::Infeasible)?;
        let fallback_offset = primary_offset
            .checked_add(primary_len)
            .ok_or(ShapeError::Oversize)?;
        let fallback_len = plan.special_fallback_len();
        let slots = fallback_offset
            .checked_add(fallback_len)
            .ok_or(ShapeError::Oversize)?;
        if slots - (offset - unpadded) != n {
            return Err(ShapeError::Infeasible);
        }
        let loglog_ceiling =
            u8::try_from(plan.loglog_ceiling()).map_err(|_| ShapeError::Infeasible)?;
        Ok(Self {
            n,
            max_insertions: config.max_insertions(),
            levels: levels.into_boxed_slice(),
            beta: plan.beta(),
            loglog_ceiling: usize::from(loglog_ceiling),
            primary_offset,
            primary_range,
            fallback_offset,
            fallback_bucket_width: plan.fallback_bucket_width(),
            fallback_bucket_range: PreparedProbeRange::new(plan.fallback_bucket_count())
                .map_err(|_| ShapeError::Infeasible)?,
            slots,
        })
    }

    fn for_insert_budget(
        requested: usize,
        reserve: ReserveFraction,
    ) -> Result<Self, TryReserveError> {
        if requested == 0 {
            return Ok(Self::empty());
        }
        let d = reserve.exponent();
        if !(geometry::MIN_FUNNEL_RESERVE_EXPONENT..usize::BITS).contains(&d) {
            return Err(TryReserveError::CapacityOverflow);
        }
        let mut n = capacity::exact_capacity_for(requested, reserve)
            .ok_or(TryReserveError::CapacityOverflow)?
            .max(2);

        let alpha = usize::try_from(u128::from(d) * 4 + 10)
            .map_err(|_| TryReserveError::CapacityOverflow)?;
        let beta =
            usize::try_from(u128::from(d) * 2).map_err(|_| TryReserveError::CapacityOverflow)?;
        n = n.max(
            alpha
                .checked_mul(beta)
                .and_then(|value| value.checked_add(2))
                .ok_or(TryReserveError::CapacityOverflow)?,
        );

        n = geometry::funnel_minimum_slots(d, n).ok_or(TryReserveError::CapacityOverflow)?;
        loop {
            match Self::try_from_slots(n, reserve) {
                Ok(shape) if shape.max_insertions >= requested => return Ok(shape),
                Ok(_) | Err(ShapeError::Infeasible) => {}
                // More slots only pad to more, and no table that large can
                // be allocated, so a larger `n` is not worth trying.
                Err(error) => return Err(error.into()),
            }
            n = n.checked_add(1).ok_or(TryReserveError::CapacityOverflow)?;
        }
    }
}

/// Why a slot count has no [`FunnelShape`].
enum ShapeError {
    /// The paper's geometry does not come out at exactly this many slots;
    /// another count may.
    Infeasible,
    /// The padded buckets need more slots than can be counted.
    Oversize,
    Alloc,
}

impl From<ShapeError> for TryReserveError {
    fn from(error: ShapeError) -> Self {
        match error {
            ShapeError::Infeasible | ShapeError::Oversize => Self::CapacityOverflow,
            ShapeError::Alloc => Self::AllocError,
        }
    }
}

/// Control byte of a bucket's padding lanes. It is free, so no scan takes it
/// for an entry, and it is not EMPTY, so the EMPTY controls of a bucket's
/// group are lanes of the bucket.
const CTRL_PADDING: u8 = 0x02;
const _: () = assert!(CTRL_PADDING != CTRL_EMPTY && CTRL_PADDING != CTRL_TOMBSTONE);

/// Marks the path that calls it as rarely taken, so the paths around it are
/// laid out to fall through.
#[cold]
#[inline]
const fn rarely_taken() {}

pub(crate) struct FlatStorage<T> {
    ctrl_ptr: *mut u8,
    data_ptr: *mut MaybeUninit<T>,
    capacity: usize,
}

// SAFETY: the raw pointers address slots owned solely by this descriptor's
// table, so sending or sharing it is sending or sharing the `T` values.
unsafe impl<T: Send> Send for FlatStorage<T> {}
// SAFETY: as for `Send`; `&FlatStorage` only exposes `&T` through the slots.
unsafe impl<T: Sync> Sync for FlatStorage<T> {}

// SAFETY: storage is only stamped at offsets carved from an arena laid out by
// `funnel_layout` with at least `capacity` ctrl bytes (plus group padding) and
// `capacity` slots, whose ctrl bytes `try_allocate_with_ctrl_zeroed` starts
// EMPTY, and is re-stamped before that arena is freed. The group of padding
// bytes past the slots holds `CTRL_PADDING` and is never stamped, and a
// bucket's padding lanes hold the same byte, which is not occupied.
unsafe impl<T> ArenaSlots<T> for FlatStorage<T> {
    const PADDED_TAIL: bool = true;

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
        self.capacity
    }
}

impl<T> arena::RegionSet for FlatStorage<T> {
    fn drop_all_values(&mut self) {
        arena::drop_values(core::slice::from_mut(self));
    }
}

/// Level-bin bit shared by every ordinary level from this index on and by both
/// special arrays: the lowest bit. Shallower levels each own a bit above it,
/// level zero the highest, so the leading zeros of a bin count up to its
/// shallowest recorded level.
const OVERFLOW_LEVEL: usize = u16::BITS as usize - 1;
// Every plan has a level for each bit above the shared one, so a walk over
// those levels meets no absent head entry; `FunnelShape::try_from_slots`
// holds each shape to it.
const _: () = assert!(geometry::MIN_FUNNEL_LEVELS > OVERFLOW_LEVEL);
const OVERFLOW_LEVEL_BIT: u16 = 1;

/// Level-bin bit of ordinary level `level`.
#[inline]
fn level_bit_of(level: usize) -> u16 {
    if level < OVERFLOW_LEVEL {
        (1 << OVERFLOW_LEVEL) >> level
    } else {
        OVERFLOW_LEVEL_BIT
    }
}

/// Bit of level zero in [`recorded_head_levels`].
const SHALLOWEST_LEVEL: u32 = 1 << (u32::BITS - 1);

/// The levels below `OVERFLOW_LEVEL` that a level bin records, level zero in
/// the top bit, so the leading zeros of a non-empty set are the index of its
/// shallowest level.
#[inline]
fn recorded_head_levels(levels: u16) -> u32 {
    u32::from(levels & !OVERFLOW_LEVEL_BIT) << (u32::BITS - u16::BITS)
}

/// A filter unit: membership bits in its low half, the key's level bin in
/// its high half.
type FilterUnit = u32;

/// Membership bits of a filter unit, its low half.
const MEMBERSHIP_BITS: u32 = FilterUnit::BITS - u16::BITS;

/// The key's bit of a filter unit's membership half, from the low bits of
/// the hash; the unit index draws on the high half.
#[inline]
const fn membership_bit(key_hash: u64) -> u32 {
    #[allow(clippy::cast_possible_truncation)]
    {
        1 << (key_hash as u32 & (MEMBERSHIP_BITS - 1))
    }
}

/// One key's filter location: which unit, and which membership bit of it.
/// Computed once per operation and carried to the record step, so placement
/// never re-derives it.
#[derive(Clone, Copy)]
struct MembershipSlot {
    index: usize,
    bits: u32,
}

use level_bin::WideLevelBin;

mod level_bin {
    use core::num::NonZeroU32;

    use super::{FilterUnit, unit_records};

    /// A filter unit that records a key, as loaded: its level bin in the top
    /// half, where the leading zeros of the unit are the index of the bin's
    /// shallowest level, and its membership bits below. The first-match walk
    /// steps the head by those counts; the head has an entry for every count
    /// a unit that is not zero can have.
    #[derive(Clone, Copy)]
    pub(super) struct WideLevelBin(NonZeroU32);

    impl WideLevelBin {
        /// `unit` if it holds a membership bit of `bits`. Such a unit is not
        /// zero, and every insert that sets a membership bit records a level
        /// with it, so its bin is not empty either.
        #[inline]
        pub(super) const fn of_recording_unit(unit: FilterUnit, bits: u32) -> Option<Self> {
            if unit_records(unit, bits) {
                // SAFETY: a unit with a set bit is not zero.
                Some(Self(unsafe { NonZeroU32::new_unchecked(unit) }))
            } else {
                None
            }
        }

        #[inline]
        pub(super) fn get(self) -> u32 {
            self.0.get()
        }
    }
}

/// A loaded filter unit paired with the key's bit, split from the test so the
/// load can be issued before the work that hides its latency. An absent tail
/// yields a gate that never passes, matching an empty table. It omits the
/// unit index: a lookup never records, and carrying it costs the miss path on
/// every call.
#[derive(Clone, Copy)]
struct MembershipGate {
    unit: FilterUnit,
    bits: u32,
}

impl MembershipGate {
    /// `false` proves no insert ever recorded this key.
    #[cfg(test)]
    #[inline]
    const fn passes(self) -> bool {
        unit_records(self.unit, self.bits)
    }

    /// The unit as the first-match walk reads it, if it passes.
    #[inline]
    const fn recorded(self) -> Option<WideLevelBin> {
        WideLevelBin::of_recording_unit(self.unit, self.bits)
    }

    /// The unit's level bin: a set bit marks a level some key sharing the
    /// unit was recorded at.
    #[inline]
    const fn levels(self) -> u16 {
        unit_levels(self.unit)
    }
}

/// Whether a filter unit's membership half holds the bit `bits`.
#[inline]
const fn unit_records(unit: FilterUnit, bits: u32) -> bool {
    unit & bits != 0
}

/// The level bin of a filter unit.
#[inline]
#[allow(clippy::cast_possible_truncation)]
const fn unit_levels(unit: FilterUnit) -> u16 {
    (unit >> MEMBERSHIP_BITS) as u16
}

/// The bits of a filter unit that hold its level bin, in their place.
const UNIT_BIN_BITS: FilterUnit = !((1 << MEMBERSHIP_BITS) - 1);

/// A membership bit and a level bin, each in its half of a filter unit.
#[inline]
const fn unit_of(bits: u32, levels: u16) -> FilterUnit {
    bits | (levels as FilterUnit) << MEMBERSHIP_BITS
}

/// Where each region of one Funnel epoch's arena lives.
struct FunnelLayout {
    layout: Layout,
    data_offset: usize,
    control_bytes: usize,
    membership: MembershipRegion,
}

/// A table's filter tail: where it sits in the arena, and its base address.
#[derive(Clone, Copy)]
struct FilterTail {
    region: MembershipRegion,
    /// The gate is a lookup's first dependent load, so its base is cached
    /// rather than rebuilt from the arena base and region offset. An empty
    /// region points at [`NO_FILTER_UNIT`], which rejects every key, so the
    /// gate needs no emptiness test; nothing writes through that pointer.
    ///
    /// A unit holds a membership half and one level bin, so one load at a
    /// scaled index off the base reads both.
    base: *mut FilterUnit,
}

/// The filter unit an empty table's gate reads: nothing recorded.
static NO_FILTER_UNIT: FilterUnit = 0;

impl FilterTail {
    /// # Safety
    ///
    /// `region` must have been laid out for the arena at `arena_base`.
    unsafe fn new(region: MembershipRegion, arena_base: *mut u8) -> Self {
        let base = if region.words == 0 {
            (&raw const NO_FILTER_UNIT).cast_mut()
        } else {
            // SAFETY: the caller's contract is `ptr`'s.
            unsafe { region.ptr::<FilterUnit>(arena_base) }
        };
        Self { region, base }
    }
}

/// An arena with the storage laid out in it, the head levels addressed into
/// that storage, and the filter tail. Built together, so no storage exists
/// without the head that points into it.
type FunnelStorageBuild<K, V> = (
    Arena,
    FlatStorage<SlotEntry<K, V>>,
    [HeadLevel<SlotEntry<K, V>>; HEAD_ENTRIES],
    FilterTail,
);

fn try_allocate_storage<K, V, A: Allocator>(
    geometry: &FunnelShape,
    alloc: &A,
) -> Result<FunnelStorageBuild<K, V>, TryReserveError> {
    let n = geometry.slots;
    let shape = funnel_layout::<K, V>(geometry.slots, geometry.n)?;
    let arena = Arena::try_allocate_with_ctrl_zeroed(shape.layout, shape.control_bytes, alloc)?;
    // The arena zeroes control bytes only; an empty filter must read as
    // "nothing recorded".
    // SAFETY: `shape.membership` was laid out for this arena by `funnel_layout`.
    unsafe { shape.membership.clear::<FilterUnit>(arena.as_ptr()) };
    // SAFETY: the arena holds `geometry.slots` control bytes and no entry.
    unsafe { geometry.reset_ordinary_controls(arena.as_ptr()) };
    if n != 0 {
        // SAFETY: an arena with slots holds one group of control bytes past
        // them, which no slot owns.
        unsafe {
            arena
                .as_ptr()
                .add(n)
                .cast::<[u8; GROUP_SIZE]>()
                .write([CTRL_PADDING; GROUP_SIZE]);
        }
    }
    let storage = FlatStorage {
        ctrl_ptr: arena.as_ptr(),
        // SAFETY: `data_offset` is the data section's offset within this
        // arena's layout, and is zero for the dangling empty arena.
        data_ptr: unsafe {
            arena
                .as_ptr()
                .add(shape.data_offset)
                .cast::<MaybeUninit<SlotEntry<K, V>>>()
        },
        capacity: n,
    };
    // SAFETY: as above.
    let membership = unsafe { FilterTail::new(shape.membership, arena.as_ptr()) };
    let head = head_levels(geometry, &storage);
    Ok((arena, storage, head, membership))
}

/// Layout of an arena with `slots` slots, `n` of which hold entries.
fn funnel_layout<K, V>(slots: usize, n: usize) -> Result<FunnelLayout, TryReserveError> {
    let control_bytes = if slots == 0 {
        0
    } else {
        slots
            .checked_add(GROUP_SIZE)
            .ok_or(TryReserveError::CapacityOverflow)?
    };
    let (base_layout, data_offset) = arena::layout_for_extents::<K, V>(control_bytes, slots)?;
    // One filter unit an entry.
    let (layout, membership) = MembershipRegion::extend_words::<FilterUnit>(base_layout, n)?;
    Ok(FunnelLayout {
        layout,
        data_offset,
        control_bytes,
        membership,
    })
}

/// A free slot and the level-bin bit an entry placed there records. The
/// placement walk knows the level it stopped at; carrying the bit spares the
/// insert a slot-to-level search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Vacancy {
    slot: usize,
    level_bit: u16,
}

/// A free slot of the head walk, and the level-bin bit an entry placed
/// there records.
struct HeadVacancy<T> {
    /// The free slot's control byte and entry.
    lane: *mut u8,
    entry: *mut MaybeUninit<T>,
    level_bit: u16,
}

/// A live entry and its control byte. Lookups return both, so no caller
/// re-derives one address from the other.
struct Found<'a, K, V> {
    lane: NonNull<u8>,
    entry: NonNull<SlotEntry<K, V>>,
    /// The table borrow the entry lives under.
    table: PhantomData<&'a SlotEntry<K, V>>,
}

impl<K, V> Clone for Found<'_, K, V> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<K, V> Copy for Found<'_, K, V> {}

/// The part of a [`Found`] a lookup's caller wants. A lookup is instantiated
/// per projection, so each builds that part alone, and the walk past the
/// head it hands off to returns one word.
trait FoundPart<'a, K, V> {
    type Part;

    fn of(found: Found<'a, K, V>) -> Self::Part;
}

/// The entry's control byte, which names its slot.
struct FoundLane;

impl<'a, K, V> FoundPart<'a, K, V> for FoundLane {
    type Part = NonNull<u8>;

    #[inline]
    fn of(found: Found<'a, K, V>) -> NonNull<u8> {
        found.lane
    }
}

struct FoundEntry;

impl<'a, K: 'a, V: 'a> FoundPart<'a, K, V> for FoundEntry {
    type Part = &'a SlotEntry<K, V>;

    #[inline]
    fn of(found: Found<'a, K, V>) -> &'a SlotEntry<K, V> {
        // SAFETY: a `Found` names an initialized entry of the table it
        // borrows for `'a`.
        unsafe { found.entry.as_ref() }
    }
}

/// A known-absent search, retained only while the entry borrows its map.
#[derive(Debug)]
pub struct FunnelVacant {
    hash: u64,
}

/// What [`FunnelTable::find_recorded_for_entry`] returns in place of a slot
/// for a key it settles as absent. Allocated slot indices are below
/// `isize::MAX`, so the two largest `usize` values name no slot.
const ENTRY_ABSENT: usize = usize::MAX;
/// What [`FunnelTable::find_recorded_for_entry`] returns in place of a slot
/// for a key it leaves to the walk past the head.
const ENTRY_UNSETTLED: usize = usize::MAX - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BucketScanResult<T> {
    Hit(T),
    Empty(usize),
    Full,
}

/// Tombstone-blind scan of one masked SIMD group containing `logical_lanes`
/// controls: stops at the first EMPTY lane and never inspects tombstones. A
/// lookup needs nothing more.
///
/// # Safety
///
/// `ctrl_ptr.add(start)` must be readable for `GROUP_SIZE` bytes,
/// `logical_lanes <= GROUP_SIZE`, and every slot passed to `inspect_match`
/// must be valid for the corresponding data arena.
#[inline]
unsafe fn scan_clean_funnel_group<T>(
    ctrl_ptr: *const u8,
    start: usize,
    logical_lanes: usize,
    fingerprint: u8,
    inspect_match: &mut impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    // SAFETY: caller guarantees `GROUP_SIZE` readable bytes at `start`.
    let group = unsafe { ctrl_ptr.add(start) };
    // SAFETY: as above, `group` is readable for one full group.
    let matches = unsafe { simd::eq_mask_group(group, fingerprint) };
    // Iterator search on purpose: a test of the lowest lane against the
    // bound is the same test, but here LLVM lowers it to a select chain
    // instead of one test-and-branch.
    // SAFETY: as above.
    let first_empty = unsafe { simd::eq_mask_group(group, CTRL_EMPTY) }
        .into_iter()
        .find(|&lane| lane < logical_lanes);
    let semantic_lanes = first_empty.unwrap_or(logical_lanes);

    for lane in matches {
        if lane >= semantic_lanes {
            break;
        }
        let slot = start + lane;
        if let Some(hit) = inspect_match(slot) {
            return BucketScanResult::Hit(hit);
        }
    }
    if let Some(empty_lane) = first_empty {
        return BucketScanResult::Empty(start + empty_lane);
    }
    BucketScanResult::Full
}

/// Tombstone-blind scan over `length` logical controls; see
/// [`scan_clean_funnel_group`].
///
/// # Safety
///
/// `ctrl_ptr.add(start)` must be readable through `length + GROUP_SIZE - 1`
/// bytes, and every slot passed to `inspect_match` must be a valid logical
/// slot for the corresponding data arena.
unsafe fn scan_clean_funnel_bucket<T>(
    ctrl_ptr: *const u8,
    start: usize,
    length: usize,
    fingerprint: u8,
    mut inspect_match: impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
        // SAFETY: `position < start + length`, so a full group from `position`
        // stays within the caller's readable span.
        match unsafe {
            scan_clean_funnel_group(
                ctrl_ptr,
                position,
                logical_lanes,
                fingerprint,
                &mut inspect_match,
            )
        } {
            BucketScanResult::Full => {}
            result => return result,
        }
        position += logical_lanes;
    }
    BucketScanResult::Full
}

/// The first slot among `length` controls from `start` whose control is
/// `fingerprint` and which `holds_key` accepts. Reads no other control, so
/// it neither stops at an EMPTY lane nor looks past a tombstone.
///
/// # Safety
///
/// `ctrl_ptr.add(start)` must be readable through `length + GROUP_SIZE - 1`
/// bytes, and every slot passed to `holds_key` must be a valid logical slot
/// for the corresponding data arena.
#[inline]
unsafe fn first_match_in_lanes(
    ctrl_ptr: *const u8,
    start: usize,
    length: usize,
    fingerprint: u8,
    mut holds_key: impl FnMut(usize) -> bool,
) -> Option<usize> {
    let end = start + length;
    let mut position = start;
    while position < end {
        let lanes = GROUP_SIZE.min(end - position);
        // SAFETY: `position < start + length`, so a full group from
        // `position` stays within the caller's readable span.
        let matches = unsafe { simd::eq_mask_group(ctrl_ptr.add(position), fingerprint) };
        for lane in matches {
            if lane >= lanes {
                break;
            }
            if holds_key(position + lane) {
                return Some(position + lane);
            }
        }
        position += lanes;
    }
    None
}

/// The slot bits of a group mask that are its lanes.
const ALL_LANES: u64 = {
    let mut lanes = 0;
    let mut lane = 0;
    while lane < GROUP_SIZE {
        lanes |= 1 << (lane * BITMASK_STRIDE as usize + BITMASK_SLOT_BIT as usize);
        lane += 1;
    }
    lanes
};

/// The slot bits of a group mask that are its first `lanes` lanes, at most
/// [`GROUP_SIZE`].
#[allow(clippy::cast_possible_truncation)]
const fn low_lanes(lanes: usize) -> u64 {
    ALL_LANES & u64::MAX.unbounded_shr(u64::BITS - lanes as u32 * BITMASK_STRIDE)
}

/// The lanes of an ordinary bucket as [`first_free_in_bucket`] reads them:
/// those of its head group, and the offset of its tail's last group from
/// the tail's first with that last group's lanes, none without a tail.
#[derive(Clone, Copy)]
struct BucketLanes {
    head: u64,
    last_group: usize,
    last: u64,
}

impl BucketLanes {
    /// The lanes of a bucket `beta` lanes wide.
    fn of(beta: usize) -> Self {
        let head = beta.min(GROUP_SIZE);
        let tail = beta - head;
        let last_group = tail.saturating_sub(1) / GROUP_SIZE * GROUP_SIZE;
        Self {
            head: low_lanes(head),
            last_group,
            last: low_lanes(tail - last_group),
        }
    }
}

/// First free (EMPTY or TOMBSTONE) lane of an ordinary bucket: its head
/// group's lanes from `head`, then its tail's from `tail`, whole groups and
/// then the last.
///
/// # Safety
///
/// `ctrl_ptr` must be readable for a group from `head` and from each group
/// of the tail.
#[inline]
unsafe fn first_free_in_bucket(
    ctrl_ptr: *const u8,
    head: usize,
    tail: usize,
    lanes: BucketLanes,
) -> Option<usize> {
    // SAFETY: the caller keeps every group this reads readable.
    let free_in =
        |group: usize, mask: u64| unsafe { simd::free_lanes_group(ctrl_ptr.add(group), mask).0 };
    let at = |group: usize, free: u64| group + (free.trailing_zeros() / BITMASK_STRIDE) as usize;
    let free = free_in(head, lanes.head);
    if free != 0 {
        return Some(at(head, free));
    }
    if lanes.last == 0 {
        return None;
    }
    let last = tail + lanes.last_group;
    let mut group = tail;
    while group != last {
        let free = free_in(group, ALL_LANES);
        if free != 0 {
            return Some(at(group, free));
        }
        group += GROUP_SIZE;
    }
    let free = free_in(last, lanes.last);
    (free != 0).then(|| at(last, free))
}

/// Paper-exact Funnel hashing within each table epoch. Deletion, growth, and
/// exceptional collision recovery are built-in dynamic-map behavior beyond
/// the paper's fixed-size insertion model.
// Declaration order is layout order: the words the lookup and the common
// insert read, then the head array, then the rest. The allocator comes
// last, so its size moves no other field.
#[repr(C)]
pub struct FunnelTable<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    storage: FlatStorage<SlotEntry<K, V>>,
    /// Seeds every probe sequence. Starts at [`FUNNEL_PROBE_SEED`]; a
    /// placement-recovery rebuild advances it, because survivors of slot-order
    /// deletes are skewed toward the buckets the old seed left full.
    prf: FunnelPrf,
    /// Cached location of the membership filter tail. Lookups load one word
    /// from it before probing; see [`crate::membership`].
    membership: FilterTail,
    exceptional_placement: bool,
    /// Whether a key [`Self::first_match`] finds in none of its recorded
    /// levels may still be present: the buckets have tails, which that scan
    /// does not read, or the epoch placed a key outside its funnel. Set with
    /// [`Self::exceptional_placement`], and read alone, by
    /// [`Self::unmatched_is_absent`].
    walk_unmatched: bool,
    /// The lanes of a group that are slots of a head bucket; see
    /// [`FunnelShape::head_lanes`]. Next to [`Self::head_left`], which the
    /// head placement reads with it.
    head_lanes: u64,
    /// Inserts the head placement may still make: no more than the
    /// insertion limit less the entry count. Deletes leave it as it is, and
    /// [`Self::reopen_head`] adds the room they made once it runs out, so
    /// that placement tests and counts with one word.
    head_left: usize,
    /// The levels the first-match lookup and the head placement walk, with
    /// their addresses in [`Self::storage`]; see [`head_levels`]. Replaced
    /// with the storage it points into.
    head: [HeadLevel<SlotEntry<K, V>>; HEAD_ENTRIES],
    /// The entry count plus [`Self::head_left`]; see [`Self::entries`].
    entries_base: usize,
    shape: FunnelShape,
    hash_builder: S,
    reserve_fraction: ReserveFraction,
    arena: Arena,
    epoch: EpochState,
    /// Deletes since the filter last matched the live set, less
    /// [`Self::uncounted_deletes`]; see [`membership::refresh_deletes`].
    stale_membership: usize,
    /// What [`Self::stale_membership`] and [`Self::uncounted_deletes`] lack
    /// of a bound on the tombstones, modulo the word: the sum of the three
    /// is the bound. A filter refresh moves its deletes here, a count of the
    /// tombstones sets the sum to the count, and a placement that takes a
    /// tombstone's lane leaves it as it is.
    refreshed_deletes: usize,
    /// Deletes left before one has to look at the counters: a delete only
    /// counts this word down, and the first to exhaust it settles the rest.
    settle_left: usize,
    /// [`Self::settle_left`] as the counts were last settled with it.
    settle_armed: usize,
    alloc: A,
}

// SAFETY: the table uniquely owns its arena and every `K`/`V` in it; no
// shared or thread-local state escapes through the raw pointers.
unsafe impl<K: Send, V: Send, S: Send, A: Allocator + Clone + Send> Send
    for FunnelTable<K, V, S, A>
{
}
// SAFETY: `&FunnelTable` only hands out shared references to its contents
// and has no interior mutability.
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for FunnelTable<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for FunnelTable<K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunnelTable").finish_non_exhaustive()
    }
}

impl<K, V, S, A: Allocator + Clone> Drop for FunnelTable<K, V, S, A> {
    fn drop(&mut self) {
        let storage = &mut self.storage;
        self.arena.drop_table(&self.alloc, || {
            arena::drop_values(core::slice::from_mut(storage));
        });
    }
}

macros::declare_backend_aliases! {
    table = FunnelTable,
    map_no_lifetime {
        /// Open-addressed hash map using funnel hashing.
        ///
        /// # Examples
        ///
        /// ```
        /// use opthash::FunnelHashMap;
        ///
        /// let mut lengths: FunnelHashMap<&str, usize> = ["alpha", "beta", "gamma"]
        ///     .into_iter()
        ///     .map(|word| (word, word.len()))
        ///     .collect();
        /// lengths.retain(|_, len| *len > 4);
        ///
        /// assert_eq!(lengths.len(), 2);
        /// assert!(!lengths.contains_key("beta"));
        /// ```
        FunnelHashMap => HashMap,
        /// Consuming iterator over owned `(K, V)`.
        FunnelIntoIter => IntoIter,
        /// Owned `K` iterator.
        FunnelIntoKeys => IntoKeys,
        /// Owned `V` iterator.
        FunnelIntoValues => IntoValues,
    },
    map_ref {
        /// A view into a single entry, occupied or vacant.
        FunnelEntry => Entry,
        /// View of an occupied entry.
        FunnelOccupiedEntry => OccupiedEntry,
        /// View of a vacant entry.
        FunnelVacantEntry => VacantEntry,
        /// Error returned by `try_insert` on key collision.
        FunnelOccupiedError => OccupiedError,
        /// Borrowing iterator over `(&K, &V)`.
        FunnelIter => Iter,
        /// Borrowing iterator over `(&K, &mut V)`.
        FunnelIterMut => IterMut,
        /// `&K` iterator.
        FunnelKeys => Keys,
        /// `&V` iterator.
        FunnelValues => Values,
        /// `&mut V` iterator.
        FunnelValuesMut => ValuesMut,
        /// Draining iterator that empties the map.
        FunnelDrain => Drain,
    },
    map_extract_if {
        /// Iterator yielding entries removed by `extract_if`.
        FunnelExtractIf
    },
    set_no_lifetime {
        /// Hash set using funnel hashing.
        ///
        /// # Examples
        ///
        /// ```
        /// use opthash::FunnelHashSet;
        ///
        /// let mut seen = FunnelHashSet::new();
        /// assert!(seen.insert("Paris"));
        /// assert!(!seen.insert("Paris"));
        /// assert!(seen.remove("Paris"));
        /// assert!(seen.is_empty());
        /// ```
        FunnelHashSet => HashSet,
        /// Consuming iterator over set values.
        FunnelSetIntoIter => IntoIter,
    },
    set_ref {
        /// Borrowing iterator over set values.
        FunnelSetIter => Iter,
        /// Draining iterator that empties the set.
        FunnelSetDrain => Drain,
        /// Iterator over values present only in the first set.
        FunnelDifference => Difference,
        /// Iterator over values present in both sets.
        FunnelIntersection => Intersection,
        /// Iterator over values present in exactly one set.
        FunnelSymmetricDifference => SymmetricDifference,
        /// Iterator over values present in either set.
        FunnelUnion => Union,
        /// A view into a single set entry.
        FunnelSetEntry => Entry,
        /// View of an occupied set entry.
        FunnelSetOccupiedEntry => OccupiedEntry,
        /// View of a vacant set entry.
        FunnelSetVacantEntry => VacantEntry,
    },
    set_extract_if {
        /// Iterator yielding values removed by set `extract_if`.
        FunnelSetExtractIf
    },
}

impl<K, V, S, A> FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn try_from_shape(
        shape: FunnelShape,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let (arena, storage, head, membership) = try_allocate_storage(&shape, &alloc)?;
        let mut table = Self {
            head,
            entries_base: 0,
            head_left: 0,
            head_lanes: shape.head_lanes(),
            shape,
            storage,
            reserve_fraction,
            hash_builder,
            alloc,
            arena,
            epoch: EpochState::initial(),
            exceptional_placement: false,
            walk_unmatched: false,
            prf: FunnelPrf::new(FUNNEL_PROBE_SEED),
            membership,
            stale_membership: 0,
            refreshed_deletes: 0,
            settle_left: 1,
            settle_armed: 1,
        };
        table.set_entries(0);
        table.set_exceptional_placement(false);
        Ok(table)
    }

    fn try_with_insert_budget(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        if reserve_fraction.exponent() < 3 {
            return Err(TryBuildError::FunnelExponentBelowMinimum {
                reserve_exponent: reserve_fraction.exponent(),
                minimum: 3,
            });
        }
        let shape = FunnelShape::for_insert_budget(capacity, reserve_fraction)?;
        Self::try_from_shape(shape, reserve_fraction, hash_builder, alloc).map_err(Into::into)
    }

    /// Bucket of the key in the ordinary level of shape `level`.
    #[inline]
    fn sample_ordinary(probe: PreparedFastFunnelProbe, level: &LevelShape) -> usize {
        probe::ordinary_funnel_bucket(probe, level.multiplier, level.buckets)
    }

    #[inline]
    fn sample(
        prepared: &PreparedFastFunnelDomainProbe,
        logical_probe: u8,
        range: PreparedProbeRange,
    ) -> Option<usize> {
        probe::unbiased_prepared_funnel_probe_index_in_range(
            prepared,
            logical_probe,
            range,
            probe::RANGE_WORD_CAP,
        )
        .ok()
        .map(|probe| probe.index)
    }

    /// # Safety
    ///
    /// `slot < self.shape.slots`.
    #[inline]
    unsafe fn inspect_slot<Q>(&self, slot: usize, key_fingerprint: u8, key: &Q) -> Option<bool>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // SAFETY: caller keeps `slot` in bounds.
        let ctrl = unsafe { self.storage.control_at(slot) };
        if ctrl == CTRL_EMPTY {
            return Some(false);
        }
        if ctrl == key_fingerprint {
            // SAFETY: a fingerprint control is occupied, so the slot is initialized.
            let entry = unsafe { self.storage.get_ref(slot) };
            if key.equivalent(&entry.key) {
                return Some(true);
            }
        }
        None
    }

    /// The ordered walk, read-only: the buckets of [`Self::search_vacancy`]
    /// in the same order, restricted to the levels set in the key's bin
    /// `levels`, shallowest first. It stops only at a real EMPTY and skips
    /// tombstones. The reference [`Self::lookup_past_head`] answers as,
    /// given the first-match scan.
    #[cfg(test)]
    fn lookup_recorded_levels<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        key_fingerprint: u8,
        levels: u16,
    ) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let mut ordinary = recorded_head_levels(levels);
        while ordinary != 0 {
            let index = ordinary.leading_zeros();
            ordinary ^= SHALLOWEST_LEVEL >> index;
            let index = index as usize;
            match self.lookup_level(key, probe, index, key_fingerprint) {
                BucketScanResult::Hit(slot) => return Some(slot),
                BucketScanResult::Empty(_) => return None,
                BucketScanResult::Full => {}
            }
        }
        if levels & OVERFLOW_LEVEL_BIT == 0 {
            return None;
        }
        self.lookup_overflow_levels(key, probe, key_fingerprint)
    }

    /// Lookup over the ordinary levels the key's bin recorded, comparing the
    /// key against the fingerprint matches of each bucket's head group.
    /// `Err` is not yet an answer: it carries the head entry scanned last,
    /// from which [`Self::unmatched_is_absent`] settles it or hands the
    /// lookup to [`Self::lookup_past_head`].
    ///
    /// A head group without the fingerprint cannot hold the key, so the walk
    /// moves on without the ordered walk's `EMPTY` test, which only shortens
    /// misses the filter let through. A bucket's tail is not read here: a
    /// shape with tails hands every miss on.
    ///
    /// Calls nothing but the key comparison, so the lookup that finds its key
    /// runs wherever this is inlined without a call.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn first_match<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        levels: WideLevelBin,
    ) -> Result<Found<'_, K, V>, &HeadLevel<SlotEntry<K, V>>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let fingerprint_word = probe.fingerprint_word();
        // Fingerprint matches of the head group of the key's bucket in one
        // level, with the bucket's index in the level. The head group is a
        // whole group, so the bucket index scales in the load.
        let scan = |level: &HeadLevel<SlotEntry<K, V>>| -> (usize, u64) {
            let bucket = probe::ordinary_funnel_bucket(probe, level.multiplier, level.buckets);
            // SAFETY: a draw is below the level's bucket count, an ordinary
            // bucket ends at or before `slots`, and the control array pads
            // one group past them, which is the bucket an entry that is no
            // level draws; every shape that recorded a key has slots. Every
            // lane of the group is a lane of the bucket but its padding,
            // which no fingerprint matches.
            let matches =
                unsafe { simd::eq_fingerprint_group(level.group(bucket).cast(), fingerprint_word) };
            (bucket, matches.0)
        };
        // The entry at the lead match of bucket `bucket` of `level`, if it
        // holds the key. A bucket holds a key once, so the order the matches
        // are compared in changes no answer, and the walk takes them in the
        // order the group backend locates cheapest.
        let holding_key = |level: &HeadLevel<SlotEntry<K, V>>,
                           bucket: usize,
                           matches: u64|
         -> Option<Found<'_, K, V>> {
            let matches = BitMask(matches);
            // SAFETY: every caller passes a non-empty set: the group mask
            // `scan` returned, or what is left of it once lead lanes are
            // cleared. A matched lane lies inside its bucket and carries the
            // fingerprint, so the slot is in bounds and occupied.
            let (lane, entry) = unsafe {
                (
                    NonNull::new_unchecked(
                        level
                            .group(bucket)
                            .cast::<u8>()
                            .add(LEAD_ORIGIN)
                            .offset(matches.lead_offset(1)),
                    ),
                    NonNull::new_unchecked(
                        level
                            .lead_origin_entry(bucket)
                            .byte_offset(matches.lead_offset(mem::size_of::<SlotEntry<K, V>>()))
                            .cast::<SlotEntry<K, V>>(),
                    ),
                )
            };
            // SAFETY: as above, the entry is initialized.
            let stored = unsafe { &entry.as_ref().key };
            key.equivalent(stored).then_some(Found {
                lane,
                entry,
                table: PhantomData,
            })
        };
        // A passed gate means a recorded key, so the table has slots.
        debug_assert_ne!(self.shape.n, 0);
        // The leading zeros of the unit are the index of its bin's
        // shallowest level. The overflow bit reaches an absent entry: it
        // stands where the level past the last recorded one would. A unit
        // whose bin is empty leads with a membership bit, which reaches an
        // absent entry too.
        // None of these is a level, and each scans the group past the slots,
        // which matches nothing.
        let unit = levels.get();
        // The walk steps a pointer to the table itself and reads the head
        // at its offset from there, so the head's address is never formed.
        // The first step is taken from the table and the rest from the
        // step before, so the first costs no copy of the table's address.
        let table = ptr::from_ref(self).cast::<HeadLevel<SlotEntry<K, V>>>();
        let mut distance = unit.leading_zeros();
        let mut stepped = table.wrapping_add(distance as usize);
        // The head entry the walk stands on.
        macro_rules! take_level {
            () => {{
                // SAFETY: the distances stepped so far add up to the index
                // of a set bit of the unit, which is one of the head's
                // `HEAD_ENTRIES` entries, and they outlive the borrow of
                // `self`.
                unsafe { &*stepped.wrapping_byte_add(mem::offset_of!(Self, head)) }
            }};
        }
        // The key in a head level, if the level holds it. A macro and not a
        // closure, so that each scan is laid out where it is used: the
        // first level then runs in line from the gate, and only a deeper
        // level takes the loop's jump back.
        macro_rules! key_in {
            ($level:expr) => {{
                let level = $level;
                let (bucket, mut matches) = scan(level);
                loop {
                    if matches == 0 {
                        break None;
                    }
                    if let Some(found) = holding_key(level, bucket, matches) {
                        break Some(found);
                    }
                    // Another key shares the fingerprint.
                    rarely_taken();
                    // SAFETY: the test above: the set is not empty, and it
                    // is the scan's mask less whole lanes.
                    matches = unsafe { BitMask(matches).without_lead() }.0;
                }
            }};
        }
        let mut level = take_level!();
        if let Some(found) = key_in!(level) {
            return Ok(found);
        }
        // The bin's bits after the first, which the walk visits next: moved
        // up by the distance stepped so far, so each keeps its distance from
        // the entry the walk stands on, and with the first cleared at the
        // top. The membership half is dropped first, so only levels follow;
        // the first step read through it, as a recorded unit's leading
        // zeros are its bin's. A unit is not zero, so the distance is below
        // its width.
        let mut pending = ((unit & UNIT_BIN_BITS) << distance) & !SHALLOWEST_LEVEL;
        while pending != 0 {
            distance = pending.leading_zeros();
            stepped = stepped.wrapping_add(distance as usize);
            pending = (pending << distance) & !SHALLOWEST_LEVEL;
            level = take_level!();
            if let Some(found) = key_in!(level) {
                return Ok(found);
            }
        }
        Err(level)
    }

    /// Whether a lookup [`Self::first_match`] found nothing for is absent,
    /// given the head entry it scanned last. Otherwise the walk past the
    /// head decides: the key may sit outside its funnel, in a bucket's tail,
    /// or in a level the head does not hold. The scan ends at an absent entry
    /// exactly when the bin records such a level, or records none: the
    /// overflow bit is the last it reaches, and the entry an empty bin's
    /// membership bit leads to is absent.
    #[inline]
    fn unmatched_is_absent(&self, last: &HeadLevel<SlotEntry<K, V>>) -> bool {
        !last.is_absent() && !self.walk_unmatched
    }

    /// Sets [`Self::exceptional_placement`], and with it
    /// [`Self::walk_unmatched`] for the current shape.
    #[inline]
    fn set_exceptional_placement(&mut self, exceptional: bool) {
        self.exceptional_placement = exceptional;
        self.walk_unmatched = exceptional || self.shape.tail_width() != 0;
    }

    /// Tombstone-blind scan of the key's bucket in ordinary level `index`:
    /// its head group, then its tail.
    ///
    /// Forced inline: the call per visited level would cost more than the
    /// scan.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn lookup_level<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        index: usize,
        key_fingerprint: u8,
    ) -> BucketScanResult<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let shape = &self.shape;
        let level = &shape.levels[index];
        let bucket = Self::sample_ordinary(probe, level);
        let ctrl_ptr = self.storage.ctrl_ptr();
        let mut inspect = |slot: usize| {
            // SAFETY: a matched lane lies inside the bucket and carries the
            // fingerprint, so it is an occupied slot.
            let entry = unsafe { self.storage.get_ref(slot) };
            key.equivalent(&entry.key).then_some(slot)
        };
        // SAFETY: a head group ends at or before `slots`, and the control
        // array pads a group past them.
        let head = unsafe {
            scan_clean_funnel_group(
                ctrl_ptr,
                FunnelShape::head_start(level, bucket),
                shape.head_width(),
                key_fingerprint,
                &mut inspect,
            )
        };
        match head {
            // SAFETY: a tail ends at or before `slots`, as above; an empty
            // one reads no control.
            BucketScanResult::Full => unsafe {
                scan_clean_funnel_bucket(
                    ctrl_ptr,
                    shape.tail_start(level, bucket),
                    shape.tail_width(),
                    key_fingerprint,
                    inspect,
                )
            },
            result => result,
        }
    }

    /// Read-only walk for a key [`Self::first_match`] found in none of the
    /// head groups it scanned, its bin `levels`: the tails of the key's
    /// buckets in the levels below the overflow bit that the bin records,
    /// shallowest first, then the overflow leg. No head group needs a second
    /// look, and a tail without the fingerprint cannot hold the key, so the
    /// tails are read for fingerprint matches alone, as the head groups were.
    ///
    /// The answer is the ordered walk's, which also stops at an `EMPTY` lane
    /// of a visited bucket: a slot returns to `EMPTY` only when the epoch is
    /// rebuilt, so that lane was free when the key was placed, and placement
    /// takes the first free slot of the walk, so the key is not deeper. The
    /// level holding a live key always has its bit set, as bits only
    /// accumulate and a refresh re-records every live entry. Entries placed
    /// outside their funnel are the caller's full scan's concern.
    ///
    /// The first-match lookup hands every key it cannot settle to this
    /// walk, which therefore decides them all.
    fn lookup_past_head<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        key_fingerprint: u8,
        levels: u16,
    ) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let shape = &self.shape;
        if shape.tail_width() != 0 {
            let mut ordinary = recorded_head_levels(levels);
            while ordinary != 0 {
                let index = ordinary.leading_zeros();
                ordinary ^= SHALLOWEST_LEVEL >> index;
                let level = &shape.levels[index as usize];
                let bucket = Self::sample_ordinary(probe, level);
                // SAFETY: a tail ends at or before `slots`, and the control
                // array pads a group past them; a matched lane lies inside
                // the tail and carries the fingerprint, so it is occupied.
                let found = unsafe {
                    first_match_in_lanes(
                        self.storage.ctrl_ptr(),
                        shape.tail_start(level, bucket),
                        shape.tail_width(),
                        key_fingerprint,
                        |slot| key.equivalent(&self.storage.get_ref(slot).key),
                    )
                };
                if found.is_some() {
                    return found;
                }
            }
        }
        if levels & OVERFLOW_LEVEL_BIT == 0 {
            return None;
        }
        self.lookup_overflow_levels(key, probe, key_fingerprint)
    }

    /// Overflow leg of [`Self::lookup_past_head`]: every ordinary level
    /// from `OVERFLOW_LEVEL` on, then the special arrays, as the placement
    /// walk visits them.
    ///
    /// Out of line: most keys never record the overflow bit, and inlining
    /// this leg would give the hot walk a second copy of the level scan.
    #[inline(never)]
    fn lookup_overflow_levels<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        key_fingerprint: u8,
    ) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        if self.shape.n == 0 {
            return None;
        }
        for index in OVERFLOW_LEVEL..self.shape.levels.len() {
            match self.lookup_level(key, probe, index, key_fingerprint) {
                BucketScanResult::Hit(slot) => return Some(slot),
                BucketScanResult::Empty(_) => return None,
                BucketScanResult::Full => {}
            }
        }

        let primary_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_PRIMARY_BASE);
        for logical_probe in 0..self.shape.loglog_ceiling {
            let local = Self::sample(
                &primary_probe,
                self.shape.encode_logical_probe(logical_probe),
                self.shape.primary_range,
            )?;
            let slot = self.shape.primary_offset + local;
            // SAFETY: a primary probe stays inside the primary range.
            match unsafe { self.inspect_slot(slot, key_fingerprint, key) } {
                Some(true) => return Some(slot),
                Some(false) => return None,
                None => {}
            }
        }

        let first_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_A_BASE);
        let first_bucket = Self::sample(&first_probe, 0, self.shape.fallback_bucket_range)?;
        let second_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_B_BASE);
        let second_bucket = Self::sample(&second_probe, 0, self.shape.fallback_bucket_range)?;
        for slot_in_bucket in 0..self.shape.fallback_bucket_width {
            for bucket in [first_bucket, second_bucket] {
                let slot = self.shape.fallback_offset
                    + bucket * self.shape.fallback_bucket_width
                    + slot_in_bucket;
                // SAFETY: both buckets lie inside the fallback range.
                match unsafe { self.inspect_slot(slot, key_fingerprint, key) } {
                    Some(true) => return Some(slot),
                    Some(false) => return None,
                    None => {}
                }
            }
        }
        None
    }

    /// A vacancy at `slot`, found by a walk that did not track its level.
    #[inline]
    fn vacancy_at(&self, slot: usize) -> Vacancy {
        Vacancy {
            slot,
            level_bit: self.level_bit(slot),
        }
    }

    /// Placement walk for a key already known to be absent: the key's bucket
    /// in each ordinary level, shallowest first, then the special arrays,
    /// returning the first free slot. No fingerprint mask, no key compares.
    /// `None` is an exhausted walk.
    ///
    /// Forced inline: the loop keeps many registers live, so a call costs more
    /// in prologue and epilogue than the walk. The special-array tail stays out
    /// of line because almost every insert finds its slot in the funnel.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn search_vacancy(&self, probe: PreparedFastFunnelProbe) -> Option<Vacancy> {
        #[cfg(test)]
        tests::VACANCY_WALKS.with(|walks| walks.set(walks.get() + 1));
        if self.shape.n == 0 {
            return None;
        }
        let shape = &self.shape;
        let ctrl_ptr = self.storage.ctrl_ptr();
        let lanes = BucketLanes::of(shape.beta);
        // Each level's word is the level before's times the step, which
        // is what its multiplier makes of the key's folded word.
        let level_step = self.prf.level_step();
        let mut word = probe.ordinary_first_word(level_step);
        for (index, level) in shape.levels.iter().enumerate() {
            let bucket = probe::ordinary_bucket_of_word(word, level.buckets);
            word = word.wrapping_mul(level_step);
            // SAFETY: a head group and every group of a tail start before
            // `slots`, and the control array pads a group past `slots`.
            let free = unsafe {
                first_free_in_bucket(
                    ctrl_ptr,
                    FunnelShape::head_start(level, bucket),
                    shape.tail_start(level, bucket),
                    lanes,
                )
            };
            if let Some(slot) = free {
                return Some(Vacancy {
                    slot,
                    level_bit: level_bit_of(index),
                });
            }
        }
        self.search_vacancy_special(probe).map(|slot| Vacancy {
            slot,
            level_bit: OVERFLOW_LEVEL_BIT,
        })
    }

    /// [`Self::search_vacancy`] over the levels that own a level-bin bit: the
    /// first free lane of the walk, EMPTY or a tombstone. `None` hands the
    /// insert to the general walk: no vacancy in those levels. The walk of
    /// [`Self::place_through_head`], which tests hold that placement to.
    #[cfg(test)]
    fn first_free_in_head(
        &self,
        probe: PreparedFastFunnelProbe,
    ) -> Option<HeadVacancy<SlotEntry<K, V>>> {
        let mut word = probe.ordinary_first_word(self.prf.level_step());
        (0..OVERFLOW_LEVEL).find_map(|index| {
            let vacancy = self.first_free_in_head_level(word, index);
            word = word.wrapping_mul(self.prf.level_step());
            vacancy
        })
    }

    /// One step of the head walk: the first free lane of the key's bucket in
    /// head entry `index`, if it has one. `word` is the key's
    /// random word in that level, which the caller steps from the level
    /// before by [`FunnelPrf::level_step`].
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn first_free_in_head_level(
        &self,
        word: u64,
        index: usize,
    ) -> Option<HeadVacancy<SlotEntry<K, V>>> {
        let level = &self.head[index];
        let bucket = probe::ordinary_bucket_of_word(word, level.buckets);
        // Every head entry the walk visits is a level:
        // `FunnelShape::try_from_slots` builds no shape with fewer levels
        // than the walk.
        debug_assert!(index < self.shape.levels.len());
        // SAFETY: a head group ends at or before `slots`.
        let empty =
            unsafe { simd::free_lanes_group(level.group(bucket).cast(), self.head_lanes) }.0;
        (empty != 0).then(|| {
            let lane = (empty.trailing_zeros() / BITMASK_STRIDE) as usize;
            // One slot index for both addresses.
            let slot = bucket * GROUP_SIZE + lane;
            HeadVacancy {
                // SAFETY: a free lane of the bucket is a slot of the level.
                // Addressed from the level, not from the group just read,
                // which leaves that read its scaled bucket index.
                lane: unsafe { level.ctrl.add(slot) },
                // SAFETY: as above.
                entry: unsafe { level.entry(slot) },
                level_bit: level_bit_of(index),
            }
        })
    }

    /// Special-array leg of [`Self::search_vacancy`]: primary probes, then the
    /// two fallback buckets a lane of each in turn. Returns the bare
    /// slot: every special slot shares the overflow bit, and a slot alone
    /// returns in registers.
    #[inline(never)]
    fn search_vacancy_special(&self, probe: PreparedFastFunnelProbe) -> Option<usize> {
        let primary_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_PRIMARY_BASE);
        for logical_probe in 0..self.shape.loglog_ceiling {
            let local = Self::sample(
                &primary_probe,
                self.shape.encode_logical_probe(logical_probe),
                self.shape.primary_range,
            )?;
            let slot = self.shape.primary_offset + local;
            // SAFETY: a primary probe stays inside the primary range.
            if control::is_free(unsafe { self.storage.control_at(slot) }) {
                return Some(slot);
            }
        }

        let first_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_A_BASE);
        let first_bucket = Self::sample(&first_probe, 0, self.shape.fallback_bucket_range)?;
        let second_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_B_BASE);
        let second_bucket = Self::sample(&second_probe, 0, self.shape.fallback_bucket_range)?;
        for slot_in_bucket in 0..self.shape.fallback_bucket_width {
            for bucket in [first_bucket, second_bucket] {
                let slot = self.shape.fallback_offset
                    + bucket * self.shape.fallback_bucket_width
                    + slot_in_bucket;
                // SAFETY: both buckets lie inside the fallback range.
                if control::is_free(unsafe { self.storage.control_at(slot) }) {
                    return Some(slot);
                }
            }
        }
        None
    }

    /// Only epochs that placed a key outside its funnel reach this scan.
    #[cold]
    #[inline(never)]
    fn find_by_full_scan<Q>(&self, key: &Q, key_fingerprint: u8) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // SAFETY: `slot < slots`, the storage capacity, and a fingerprint match
        // means the slot is occupied.
        (0..self.shape.slots).find(|&slot| unsafe {
            self.storage.control_at(slot) == key_fingerprint
                && key.equivalent(&self.storage.get_ref(slot).key)
        })
    }

    #[inline]
    fn membership_ptr(&self) -> *mut FilterUnit {
        self.membership.base
    }

    /// This key's filter unit index and bit for the current epoch. Only an
    /// empty geometry has no units; its index is then zero, and the gate reads
    /// the shared all-zero unit, which no key passes.
    #[inline]
    fn membership_slot(&self, key_hash: u64) -> MembershipSlot {
        MembershipSlot {
            index: membership::word(key_hash, self.membership.region.words),
            bits: membership_bit(key_hash),
        }
    }

    /// Loads this key's filter unit without testing it, so a lookup can
    /// prepare the probe while the load is in flight.
    #[inline]
    fn membership_gate(&self, key_hash: u64) -> MembershipGate {
        self.membership_gate_at(self.membership_slot(key_hash))
    }

    /// [`Self::membership_gate`] for a slot the caller keeps, so an insert can
    /// record at the same slot without re-deriving it after placement.
    #[inline]
    fn membership_gate_at(&self, slot: MembershipSlot) -> MembershipGate {
        // SAFETY: `slot.index` is a multiply-high reduction below `words`, and
        // the arena's tail holds exactly that many units; with none it is
        // zero, and the base is the shared empty unit.
        let unit = unsafe { *self.membership_ptr().add(slot.index) };
        MembershipGate {
            unit,
            bits: slot.bits,
        }
    }

    /// Level-bin bit for an entry stored at `slot`. Levels are contiguous from
    /// slot zero, and the special arrays follow the last of them, so the slot
    /// alone names its level.
    #[inline]
    fn level_bit(&self, slot: usize) -> u16 {
        let levels = &self.shape.levels;
        let overflow_start = levels
            .get(OVERFLOW_LEVEL)
            .map_or(self.shape.primary_offset, |level| level.offset);
        if slot >= overflow_start {
            return OVERFLOW_LEVEL_BIT;
        }
        // Level zero starts at slot zero, so the later levels starting at or
        // before `slot` count up to its level. Most entries sit in the first
        // few levels, so the walk is short.
        level_bit_of(
            levels
                .iter()
                .skip(1)
                .take_while(|level| level.offset <= slot)
                .count(),
        )
    }

    /// First slot of level bin `bin`: the level of that index, or the start
    /// of the special arrays for the last bin and for any bin the table has
    /// no level for.
    #[inline]
    fn level_bin_start(&self, bin: usize) -> usize {
        self.shape
            .levels
            .get(bin)
            .map_or(self.shape.primary_offset, |level| level.offset)
    }

    /// Records a key under a filter location derived from this epoch, at the
    /// level-bin bit of the slot it is stored in, including entries
    /// exceptional recovery places outside their funnel.
    #[inline]
    fn record_membership(&mut self, membership: MembershipSlot, level_bit: u16) {
        debug_assert!(level_bit.is_power_of_two());
        if self.membership.region.words != 0 {
            // SAFETY: as in `membership_gate`; `&mut self` makes the borrow
            // exclusive.
            unsafe {
                *self.membership_ptr().add(membership.index) |= unit_of(membership.bits, level_bit);
            }
        }
    }

    fn clear_membership(&mut self) {
        // SAFETY: `region` was laid out for `self.arena`.
        unsafe {
            self.membership
                .region
                .clear::<FilterUnit>(self.arena.as_ptr());
        }
        self.stale_membership = 0;
    }

    /// Re-record the filter from the live entries, dropping the bits departed
    /// keys left behind. Entries stay put; only the filter tail is rewritten.
    /// A refresh that [`membership::hash_live_keys`] cannot finish leaves
    /// the filter as it was and stays owed to the next settling delete.
    #[cold]
    #[inline(never)]
    fn refresh_membership(&mut self) {
        // The scan yields slots in rising order, so the hashes of one level
        // bin are contiguous and a count per bin recovers each hash's bin.
        let mut bin_entries = [0_usize; OVERFLOW_LEVEL + 1];
        let mut bin = 0;
        let mut bin_end = self.level_bin_start(1);
        let mut in_bin = 0;
        let Some(hashes) = membership::hash_live_keys(
            core::slice::from_ref(&self.storage),
            self.entries(),
            &self.hash_builder,
            self.alloc.clone(),
            |slot| {
                while slot >= bin_end {
                    bin_entries[bin] = in_bin;
                    in_bin = 0;
                    bin += 1;
                    bin_end = if bin < OVERFLOW_LEVEL {
                        self.level_bin_start(bin + 1)
                    } else {
                        usize::MAX
                    };
                }
                in_bin += 1;
            },
        ) else {
            return;
        };
        bin_entries[bin] = in_bin;
        // The tombstones of the deletes the filter now forgets stay.
        self.refreshed_deletes = self.refreshed_deletes.wrapping_add(self.stale_membership);
        self.clear_membership();
        let mut hashes = hashes.into_iter();
        for (bin, entries) in bin_entries.into_iter().enumerate() {
            let level_bit = level_bit_of(bin);
            for hash in hashes.by_ref().take(entries) {
                self.record_membership(self.membership_slot(hash), level_bit);
            }
        }
    }

    /// Settles the counts after a bulk delete: a same-size cleanup if it
    /// left the table mostly tombstones, otherwise a filter refresh once
    /// departed keys pass its threshold. The cleanup rebuilds the filter
    /// too, so the two never stack.
    #[cold]
    #[inline(never)]
    fn settle_after_deletes(&mut self) {
        self.settle_counts();
        if self.cleanup_is_due() {
            self.resize_with_transition(self.shape.n, EpochTransition::TombstoneCleanup);
        } else {
            self.refresh_stale_membership();
        }
    }

    /// [`Self::settle_after_deletes`] for a lone delete, which moves no
    /// entry: a tombstone stays until a placement takes its lane or a
    /// rebuild drops it. No lookup stops at a tombstone, so a run of deletes
    /// re-places no survivor that a later delete of the run removes.
    #[cold]
    #[inline(never)]
    fn settle_after_delete(&mut self) {
        self.settle_counts();
        self.refresh_stale_membership();
    }

    fn refresh_stale_membership(&mut self) {
        if self.stale_membership > membership::refresh_deletes(self.shape.max_insertions) {
            self.refresh_membership();
            self.settle_counts();
        }
    }

    /// Whether a bulk delete leaves a cleanup due: the bound on the
    /// tombstones is past the cleanup threshold and a count of them
    /// confirms it. A count that leaves the cleanup off becomes the bound.
    ///
    /// A count reads every control byte, so the cleanup comes a group's
    /// share of the slots early: the deletes that then lie between two
    /// counts pay for a count at one group read each.
    fn cleanup_is_due(&mut self) -> bool {
        let threshold = capacity::tombstone_cleanup_threshold(self.shape.n);
        if self.refreshed_deletes.wrapping_add(self.stale_membership) <= threshold {
            return false;
        }
        // SAFETY: the storage holds `shape.slots` initialized control bytes,
        // and `&mut self` keeps writers out.
        let controls =
            unsafe { core::slice::from_raw_parts(self.storage.ctrl_ptr(), self.shape.slots) };
        let tombstones: usize = controls
            .iter()
            .map(|&control| usize::from(control == CTRL_TOMBSTONE))
            .sum();
        self.refreshed_deletes = tombstones.wrapping_sub(self.stale_membership);
        tombstones + self.shape.slots / GROUP_SIZE > threshold
    }

    /// The filter gate and exceptional full scan around the
    /// tombstone-blind lookup walk, which
    /// visits only the levels the key's bin has recorded.
    ///
    /// Forced inline down from the shell's lookups, as the walk behind the
    /// gate is: a lookup that finds its key then runs in its caller, which
    /// makes no call for it and reads the entry at the address the walk
    /// formed. The fingerprint is derived past the gate, so a filter-rejected
    /// miss prepares no probe.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn find_live<'a, Q, P>(&'a self, key: &Q, key_hash: u64) -> Option<P::Part>
    where
        Q: Equivalent<K> + ?Sized,
        P: FoundPart<'a, K, V>,
    {
        // The unit stays at register width, as the gate's load left it, so
        // the walk does not widen it again.
        let levels = self.membership_gate(key_hash).recorded()?;
        let probe = self.prf.prepare(key_hash);
        match self.first_match(key, probe, levels) {
            Ok(found) => Some(P::of(found)),
            Err(last) if self.unmatched_is_absent(last) => None,
            Err(_) => self.find_past_head::<Q, P>(key, key_hash),
        }
    }

    /// The slot whose control byte is `lane`, which must be one of the
    /// storage's.
    #[inline]
    fn slot_of(&self, lane: NonNull<u8>) -> usize {
        lane.as_ptr().addr() - self.storage.ctrl_ptr().addr()
    }

    /// The rest of a removal that [`TableBackend::take`] does not
    /// finish itself, which is every call a removal makes. `unlinked` is the
    /// entry of a key already tombstoned and counted, whose count needs
    /// settling; `None` leaves the key to the walk past the head. Returns the
    /// removed entry, still initialized, for the caller to take.
    ///
    /// The caller reads the entry from what this returns, also when it
    /// passed that entry in, so it keeps nothing across the call.
    ///
    /// # Safety
    ///
    /// `unlinked`, if any, must be an initialized entry of this table whose
    /// control byte is a tombstone and whose delete is counted and reported
    /// as needing its count settled, with no other owner of its key and
    /// value.
    #[inline(never)]
    unsafe fn finish_removal<Q>(
        &mut self,
        key: &Q,
        key_hash: u64,
        unlinked: Option<NonNull<SlotEntry<K, V>>>,
    ) -> Option<NonNull<SlotEntry<K, V>>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let (entry, settle) = if let Some(entry) = unlinked {
            (entry, true)
        } else {
            let levels = self.membership_gate(key_hash).levels();
            let slot = self.find_location_past_head(key, key_hash, levels)?;
            // SAFETY: the walk returns only occupied in-bounds slots, and
            // the data base is not null.
            let entry = unsafe {
                self.storage.mark_tombstone(slot);
                NonNull::new_unchecked(self.storage.slot_ptr(slot))
            };
            (entry, self.count_delete())
        };
        if settle {
            /// Drops the unlinked entry if settling unwinds, which a
            /// panicking hasher makes it do: nothing reaches the entry
            /// again once its control byte is a tombstone.
            struct DropOnUnwind<E>(NonNull<E>);
            impl<E> Drop for DropOnUnwind<E> {
                fn drop(&mut self) {
                    // SAFETY: the entry is initialized and out of the
                    // table's reach, and this runs only on unwind, when no
                    // caller takes it.
                    unsafe { self.0.as_ptr().drop_in_place() };
                }
            }
            let unwinding = DropOnUnwind(entry);
            // Settling a lone delete moves no entry and frees no arena, so
            // the entry stays readable where it is.
            self.settle_after_delete();
            mem::forget(unwinding);
        }
        Some(entry)
    }

    /// [`Self::find_location_past_head`] for a key [`Self::first_match`]
    /// found in none of the head groups it scanned.
    ///
    /// Probe preparation stays next to the walk so the prepared probe never
    /// crosses a call boundary, and the level bin is loaded again so the
    /// first-match scan keeps none of its state for this walk.
    #[inline(never)]
    fn find_past_head<'a, Q, P>(&'a self, key: &Q, key_hash: u64) -> Option<P::Part>
    where
        Q: Equivalent<K> + ?Sized,
        P: FoundPart<'a, K, V>,
    {
        let levels = self.membership_gate(key_hash).levels();
        let slot = self.find_location_past_head(key, key_hash, levels)?;
        // SAFETY: the walk returns only occupied in-bounds slots.
        Some(P::of(unsafe { self.found_at(slot) }))
    }

    /// The slot of a key [`Self::first_match`] found in none of the head
    /// groups it scanned, its bin `levels`: [`Self::lookup_past_head`], then
    /// the full scan in an epoch that placed a key outside its funnel.
    #[inline]
    fn find_location_past_head<Q>(&self, key: &Q, key_hash: u64, levels: u16) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let probe = self.prf.prepare(key_hash);
        let key_fingerprint = probe.fingerprint();
        match self.lookup_past_head(key, probe, key_fingerprint, levels) {
            Some(slot) => Some(slot),
            None if self.exceptional_placement => self.find_by_full_scan(key, key_fingerprint),
            None => None,
        }
    }

    /// The ordered walk's slot for a key with bin `levels`:
    /// [`Self::lookup_recorded_levels`], then the full scan in an epoch
    /// that placed a key outside its funnel. The reference every lookup
    /// answers as.
    #[cfg(test)]
    fn find_location_by_walk<Q>(&self, key: &Q, key_hash: u64, levels: u16) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let probe = self.prf.prepare(key_hash);
        let key_fingerprint = probe.fingerprint();
        match self.lookup_recorded_levels(key, probe, key_fingerprint, levels) {
            Some(slot) => Some(slot),
            None if self.exceptional_placement => self.find_by_full_scan(key, key_fingerprint),
            None => None,
        }
    }

    /// # Safety
    ///
    /// `slot` is in bounds and occupied.
    #[inline]
    unsafe fn found_at(&self, slot: usize) -> Found<'_, K, V> {
        Found {
            // SAFETY: the storage holds a control byte per slot, and its
            // base is not null.
            lane: unsafe { NonNull::new_unchecked(self.storage.ctrl_ptr().add(slot)) },
            // SAFETY: the caller keeps `slot` in bounds, and the data base
            // is not null.
            entry: unsafe { NonNull::new_unchecked(self.storage.slot_ptr(slot)) },
            table: PhantomData,
        }
    }

    #[inline]
    fn entries(&self) -> usize {
        self.entries_base - self.head_left - self.uncounted_deletes()
    }

    /// Deletes since the counts were last settled, which the entry,
    /// stale-filter and epoch counts have yet to see.
    #[inline]
    fn uncounted_deletes(&self) -> usize {
        self.settle_armed.wrapping_sub(self.settle_left)
    }

    /// The bound on the tombstones, with the uncounted deletes in it.
    #[cfg(test)]
    fn tombstone_bound(&self) -> usize {
        self.refreshed_deletes.wrapping_add(self.stale_membership())
    }

    #[cfg(test)]
    fn stale_membership(&self) -> usize {
        self.stale_membership + self.uncounted_deletes()
    }

    /// Counts one delete. `true` once the counters need settling.
    #[inline]
    fn count_delete(&mut self) -> bool {
        // Never below zero: every caller settles at zero, which leaves at
        // least one.
        debug_assert_ne!(self.settle_left, 0);
        self.settle_left -= 1;
        self.settle_left == 0
    }

    /// Sets the entry count, and with it [`Self::head_left`]. Also restores
    /// that word after a change to the shape, moves the uncounted deletes
    /// into the counts they belong to, and sets [`Self::settle_left`] to the
    /// deletes that cannot yet reach the threshold of
    /// [`Self::refresh_stale_membership`].
    fn set_entries(&mut self, entries: usize) {
        let deletes = self.uncounted_deletes();
        if deletes != 0 {
            self.stale_membership = self.stale_membership.saturating_add(deletes);
            self.epoch.note_deletes(deletes);
        }
        self.head_left = self.shape.head_insertions().saturating_sub(entries);
        self.entries_base = entries + self.head_left;
        let left = membership::refresh_deletes(self.shape.max_insertions)
            .saturating_sub(self.stale_membership);
        self.settle_left = left + 1;
        self.settle_armed = left + 1;
    }

    /// [`Self::set_entries`] at the count the table has.
    fn settle_counts(&mut self) {
        self.set_entries(self.entries());
    }

    /// The head placement: moves an absent key and its value to the first
    /// free lane of the head walk, EMPTY or a tombstone, and records the
    /// key in the filter, returning the lane it took. `None` when the head
    /// has no placement left or no vacancy for the key, which then stays
    /// where it is. Calls nothing.
    ///
    /// The placement is written out once per level, after that level's
    /// scan: each copy then records its own level bit as a constant. The
    /// pair comes by reference so that those copies keep none of their own
    /// on the stack.
    ///
    /// # Safety
    ///
    /// `unit` must be the filter unit of `membership`, itself from
    /// [`Self::membership_slot`], with no write to the table since either
    /// was read. After `Some` the caller must forget `key` and `value`:
    /// the table owns them.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    unsafe fn place_through_head(
        &mut self,
        key: &K,
        value: &V,
        membership: MembershipSlot,
        unit: FilterUnit,
        probe: PreparedFastFunnelProbe,
    ) -> Option<NonNull<u8>> {
        // No more placements than the limit less the entries, and none on
        // the far side of the limit.
        debug_assert!(
            self.head_left <= self.shape.head_insertions().saturating_sub(self.entries())
        );
        let head_left = self.head_left;
        if head_left == 0 {
            return None;
        }
        // SAFETY: head placements are left only in a table with slots, so
        // its filter has units and `membership.index` is below their count.
        let recorded = unsafe { self.membership_ptr().add(membership.index) };
        let level_step = self.prf.level_step();
        let mut word = probe.ordinary_first_word(level_step);
        // One copy of the step per level, each with a constant index: the
        // walk then keeps no index and checks no bound.
        macro_rules! walk {
            ($($index:literal)*) => {
                const { assert!([$($index),*].len() == OVERFLOW_LEVEL) };
                $(
                    if $index != 0 {
                        word = word.wrapping_mul(level_step);
                    }
                    if let Some(vacancy) = self.first_free_in_head_level(word, $index) {
                        let entry = vacancy.entry.cast::<SlotEntry<K, V>>();
                        // SAFETY: the vacancy is a free lane read just
                        // above, so its entry is writable and holds
                        // nothing; the caller gives up the pair. The
                        // caller vouches for the rest.
                        unsafe {
                            (&raw mut (*entry).key).copy_from_nonoverlapping(key, 1);
                            (&raw mut (*entry).value).copy_from_nonoverlapping(value, 1);
                            self.record_in_head(
                                head_left, recorded, membership, unit, probe, &vacancy,
                            );
                        }
                        // SAFETY: a lane of the storage is not null.
                        return Some(unsafe { NonNull::new_unchecked(vacancy.lane) });
                    }
                )*
            };
        }
        walk!(0 1 2 3 4 5 6 7 8 9 10 11 12 13 14);
        None
    }

    /// Makes the entry just written at `vacancy` a live one: records its key
    /// in the filter, counts it, and writes its control.
    ///
    /// # Safety
    ///
    /// `unit` must be the filter unit of `membership`, itself from
    /// [`Self::membership_slot`], `recorded` that unit's address, `head_left`
    /// the table's, and `vacancy` from [`Self::first_free_in_head_level`],
    /// with no write to the table since any of them was read but the
    /// entry's own.
    ///
    /// Every table word the placement needs comes as an argument, read
    /// before the entry's store, which could otherwise force each to be
    /// loaded again.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    unsafe fn record_in_head(
        &mut self,
        head_left: usize,
        recorded: *mut FilterUnit,
        membership: MembershipSlot,
        unit: FilterUnit,
        probe: PreparedFastFunnelProbe,
        vacancy: &HeadVacancy<SlotEntry<K, V>>,
    ) {
        debug_assert_ne!(self.membership.region.words, 0);
        #[cfg(debug_assertions)]
        {
            let slot = self.slot_of(NonNull::new(vacancy.lane).unwrap());
            assert_eq!(vacancy.level_bit, self.level_bit(slot));
            // SAFETY: a vacancy is a slot of the storage.
            assert_eq!(vacancy.entry.cast(), unsafe { self.storage.slot_ptr(slot) });
            // SAFETY: a vacancy's control is readable.
            assert!(control::is_free(unsafe { *vacancy.lane }));
        }
        debug_assert_eq!(head_left, self.head_left);
        // SAFETY: `recorded` is this key's filter unit, and `&mut self`
        // makes the access exclusive.
        unsafe { *recorded = unit | unit_of(membership.bits, vacancy.level_bit) };
        self.head_left = head_left - 1;
        // SAFETY: the vacancy is a lane of the storage. Its control is the
        // last store: after the entry it names, and where the per-level
        // copies of this placement share no more than their ends.
        unsafe { *vacancy.lane = probe.fingerprint() };
    }

    /// Every insert but the one [`map::TableBackend::insert`] finishes
    /// itself: the duplicate search for a key the filter recorded, then the
    /// placement of an absent one. `unit` is the key's filter unit, read at
    /// `index`. Out of line so the common insert makes no call.
    ///
    /// The search is a lookup's. Whatever it does not settle is the last
    /// thing this function does and another function's work, so an insert
    /// that replaces a value keeps nothing across a call.
    #[inline(never)]
    fn insert_general(
        &mut self,
        key: K,
        value: V,
        hash: u64,
        index: usize,
        unit: FilterUnit,
    ) -> Option<V> {
        let probe = self.prf.prepare(hash);
        if let Some(levels) = WideLevelBin::of_recording_unit(unit, membership_bit(hash)) {
            match self.first_match(&key, probe, levels) {
                Ok(found) => {
                    let mut entry = found.entry;
                    // SAFETY: a `Found` names an initialized entry of this
                    // table, which `&mut self` makes this call's alone.
                    let stored = unsafe { &mut entry.as_mut().value };
                    return Some(mem::replace(stored, value));
                }
                Err(last) if self.unmatched_is_absent(last) => {}
                Err(_) => return self.insert_past_head(key, value, hash, false),
            }
        } else if self.head_left != 0 || self.head_lanes == 0 {
            // The caller's head walk ran and found no free lane, or the
            // shape has none to walk.
            return self.insert_past_head(key, value, hash, true);
        }
        self.insert_absent(key, value, hash, index, unit, probe)
    }

    /// The rest of [`Self::insert_general`] for an absent key: through the
    /// head, which the deletes since the counts were last settled may have
    /// made room in, or else past it. `probe` is the key's.
    ///
    /// The head placement calls nothing, and the one call here is the last
    /// thing a key the head does not take needs.
    #[inline(never)]
    fn insert_absent(
        &mut self,
        key: K,
        value: V,
        hash: u64,
        index: usize,
        unit: FilterUnit,
        probe: PreparedFastFunnelProbe,
    ) -> Option<V> {
        let membership = MembershipSlot {
            index,
            bits: membership_bit(hash),
        };
        if self.head_left == 0 {
            self.reopen_head();
        }
        // SAFETY: the caller read `unit` at `index`, with no write since.
        if unsafe { self.place_through_head(&key, &value, membership, unit, probe) }.is_some() {
            // The table took both.
            mem::forget(key);
            mem::forget(value);
            return None;
        }
        self.insert_past_head(key, value, hash, true)
    }

    /// The rest of [`Self::insert_general`] for a key the head did not
    /// take: the walk past the head finds a key the first-match scan could
    /// not settle, and the placement walk places an `absent` one after the
    /// growth the table is due.
    ///
    /// One function for both, and the last thing its caller does, so that
    /// caller keeps nothing across a call.
    #[inline(never)]
    fn insert_past_head(&mut self, key: K, value: V, hash: u64, absent: bool) -> Option<V> {
        if !absent && let Some(lane) = self.find_past_head::<K, FoundLane>(&key, hash) {
            let slot = self.slot_of(lane);
            return Some(map::TableBackend::replace_value(self, slot, value));
        }
        self.insert_for_vacant_by_walk(key, value, hash);
        None
    }

    /// Gives a head without placements left those the deletes since the
    /// counts were last settled made room for.
    #[inline]
    fn reopen_head(&mut self) {
        debug_assert_eq!(self.head_left, 0);
        // A shape the head does not place in has no lanes, and no
        // placements either.
        if self.head_lanes == 0 {
            return;
        }
        // The entries are the base less the uncounted deletes.
        let room = (self.shape.max_insertions + self.uncounted_deletes())
            .saturating_sub(self.entries_base);
        debug_assert_eq!(room, self.shape.head_insertions() - self.entries());
        self.entries_base += room;
        self.head_left = room;
    }

    /// Only an exhausted placement walk reaches this scan.
    #[cold]
    #[inline(never)]
    fn first_free_global(&self) -> Option<usize> {
        let shape = &self.shape;
        // A padding lane is never placed in.
        let padding = |slot: usize| slot < shape.primary_offset && slot % GROUP_SIZE >= shape.beta;
        (0..shape.slots).find(|&slot| {
            // SAFETY: `slot` is below the storage capacity.
            !padding(slot) && control::is_free(unsafe { self.storage.control_at(slot) })
        })
    }

    /// Out of line: the rebuild loops place nearly every entry through the
    /// head and keep nothing live for this.
    #[inline(never)]
    fn place_new_entry(
        &mut self,
        vacancy: Vacancy,
        key: K,
        value: V,
        membership: MembershipSlot,
        key_fingerprint: u8,
        exceptional: bool,
    ) {
        let Vacancy { slot, level_bit } = vacancy;
        // SAFETY: callers pass a free slot from a probe within the storage,
        // and `key_fingerprint` is an occupied control.
        unsafe {
            self.storage
                .write_with_control(slot, SlotEntry { value, key }, key_fingerprint);
        }
        debug_assert_eq!(level_bit, self.level_bit(slot), "level bit of slot {slot}");
        self.record_membership(membership, level_bit);
        // One more entry: out of the head's placements while it has any,
        // which keeps them within the limit less the entries.
        if self.head_left == 0 {
            self.entries_base += 1;
        } else {
            self.head_left -= 1;
        }
        if exceptional {
            self.set_exceptional_placement(true);
        }
    }

    fn next_growth_slots(&self, needed: usize) -> Option<usize> {
        if needed >= isize::MAX as usize {
            return None;
        }
        let requested = needed.max(self.shape.max_insertions.saturating_mul(2));
        FunnelShape::for_insert_budget(requested, self.reserve_fraction)
            .ok()
            .map(|shape| shape.n)
    }

    /// Grows the table if the next insert would exceed the insertion limit.
    #[inline]
    fn prepare_vacant_insert(&mut self) {
        if self.entries() >= self.shape.max_insertions {
            self.grow_for_next_insert();
        }
    }

    #[cold]
    #[inline(never)]
    fn grow_for_next_insert(&mut self) {
        let slots = self
            .next_growth_slots(self.entries().saturating_add(1))
            .expect("capacity overflow");
        self.resize_with_transition(slots, EpochTransition::Growth);
    }

    /// Rebuilds at the same size under a fresh probe seed and walks `key_hash`
    /// again, returning the new vacancy and filter slot. Out of line so the
    /// insert paths carry one inlined copy of the placement walk, not two.
    #[cold]
    #[inline(never)]
    fn rebuild_for_placement(&mut self, key_hash: u64) -> (Option<Vacancy>, MembershipSlot) {
        self.resize_with_transition(self.shape.n, EpochTransition::PlacementRecovery);
        let membership = self.membership_slot(key_hash);
        let vacancy = self.search_vacancy(self.prf.prepare(key_hash));
        (vacancy, membership)
    }

    /// Maps a known-absent search to `(vacancy, exceptional)`: its vacancy, or
    /// the first free slot anywhere once the walk is exhausted. Both callers
    /// run under the insertion limit, which reserves a free slot.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn resolve_vacancy(&self, vacancy: Option<Vacancy>) -> (Vacancy, bool) {
        if let Some(vacancy) = vacancy {
            debug_assert!(
                // SAFETY: a vacancy is a probed in-bounds slot.
                control::is_free(unsafe { self.storage.control_at(vacancy.slot) }),
                "stale Funnel vacancy at slot {}",
                vacancy.slot
            );
            (vacancy, false)
        } else {
            let slot = self
                .first_free_global()
                .expect("Funnel insertion limit reserves a free slot");
            (self.vacancy_at(slot), true)
        }
    }

    /// Places a known-absent key at its walk's vacancy. An exhausted walk
    /// first rebuilds the table at the same size under a fresh probe seed,
    /// which clears tombstones and re-places every survivor, then walks
    /// again; only a second exhaustion places the key outside its funnel.
    fn place_absent_after_search(
        &mut self,
        key: K,
        value: V,
        key_hash: u64,
        mut membership: MembershipSlot,
        vacancy: Option<Vacancy>,
    ) -> usize {
        // An epoch that already placed outside its funnels was either rebuilt
        // for this reason or failed in its own rebuild; another would cost
        // O(n) per insert without helping.
        let rebuilt = vacancy.is_none() && !self.exceptional_placement;
        let vacancy = if rebuilt {
            let (recovered, slot) = self.rebuild_for_placement(key_hash);
            membership = slot;
            recovered
        } else {
            vacancy
        };
        let (vacancy, exceptional) = self.resolve_vacancy(vacancy);
        // Derived past the rebuild, whose fresh seed changes the fingerprint.
        let key_fingerprint = self.prf.prepare(key_hash).fingerprint();
        self.place_new_entry(
            vacancy,
            key,
            value,
            membership,
            key_fingerprint,
            exceptional,
        );
        if exceptional && rebuilt {
            self.epoch.note_placement_recovery();
        } else if exceptional {
            self.epoch
                .start_with_placement_recovery(EpochTransition::PlacementRecovery);
        }
        vacancy.slot
    }

    /// Places a key the caller has proven absent by the placement walk,
    /// after the growth the table is due. Apart from its callers,
    /// whose own placement then keeps nothing across a call.
    #[inline(never)]
    fn insert_for_vacant_by_walk(&mut self, key: K, value: V, hash: u64) -> usize {
        self.prepare_vacant_insert();
        // Past the growth, which changes the probe seed and the filter
        // geometry.
        let vacancy = self.search_vacancy(self.prf.prepare(hash));
        let membership = self.membership_slot(hash);
        self.place_absent_after_search(key, value, hash, membership, vacancy)
    }

    /// The first-match scan of [`map::TableBackend::find_for_entry`] for a
    /// key the filter recorded: the slot of a present key, [`ENTRY_ABSENT`]
    /// for one the scan settles as absent, and [`ENTRY_UNSETTLED`]
    /// otherwise. One word and no call, so a present key is found without
    /// a frame or a store.
    #[inline(never)]
    fn find_recorded_for_entry<Q>(&self, key: &Q, hash: u64, levels: WideLevelBin) -> usize
    where
        Q: Equivalent<K> + ?Sized,
    {
        let probe = self.prf.prepare(hash);
        match self.first_match(key, probe, levels) {
            Ok(found) => self.slot_of(found.lane),
            Err(last) if self.unmatched_is_absent(last) => ENTRY_ABSENT,
            Err(_) => ENTRY_UNSETTLED,
        }
    }

    fn resize_with_transition(&mut self, slots: usize, transition: EpochTransition) {
        let shape = FunnelShape::from_slots(slots, self.reserve_fraction)
            .expect("compatible Funnel resize geometry");
        let (padded, n) = (shape.slots, shape.n);
        if self.try_resize_to(shape, transition).is_err() {
            let layout = funnel_layout::<K, V>(padded, n).expect("constructed Funnel layout");
            allocator_api2::alloc::handle_alloc_error(layout.layout)
        }
    }

    /// Moves every entry into fresh storage for `shape`. A placement-recovery
    /// rebuild also advances the probe seed. Each key is hashed in place
    /// before its entry is copied, and the old storage is freed only after
    /// the last copy, so `Err` or a panicking hasher leaves the table intact.
    fn try_resize_to(
        &mut self,
        shape: FunnelShape,
        transition: EpochTransition,
    ) -> Result<(), TryReserveError> {
        let (arena, storage, head, membership) = try_allocate_storage(&shape, &self.alloc)?;
        let prf = if matches!(transition, EpochTransition::PlacementRecovery) {
            self.prf.reseeded(FUNNEL_RESEED_STEP)
        } else {
            self.prf
        };
        let recovered = rebuild::rebuild(
            self,
            FunnelGeneration {
                shape,
                storage,
                head,
                len: 0,
                arena,
                exceptional_placement: false,
                prf,
                membership,
                stale_membership: 0,
            },
        );
        self.refreshed_deletes = 0;
        self.epoch.start_epoch(transition, recovered);
        Ok(())
    }
}

/// The fields a resize replaces as a unit.
pub(crate) struct FunnelGeneration<K, V> {
    shape: FunnelShape,
    storage: FlatStorage<SlotEntry<K, V>>,
    /// Addresses into `storage`; the two move together.
    head: [HeadLevel<SlotEntry<K, V>>; HEAD_ENTRIES],
    len: usize,
    arena: Arena,
    exceptional_placement: bool,
    prf: FunnelPrf,
    membership: FilterTail,
    stale_membership: usize,
}

impl<K, V, S, A> Rebuildable for FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Key = K;
    type Value = V;
    type Region = FlatStorage<SlotEntry<K, V>>;
    type Generation = FunnelGeneration<K, V>;

    fn swap_generation(&mut self, other: &mut FunnelGeneration<K, V>) {
        mem::swap(&mut self.shape, &mut other.shape);
        mem::swap(&mut self.storage, &mut other.storage);
        mem::swap(&mut self.head, &mut other.head);
        self.head_lanes = self.shape.head_lanes();
        // The deletes this generation has yet to count are its own.
        self.settle_counts();
        let entries = mem::replace(&mut other.len, self.entries());
        mem::swap(&mut self.stale_membership, &mut other.stale_membership);
        self.set_entries(entries);
        mem::swap(&mut self.arena, &mut other.arena);
        mem::swap(
            &mut self.exceptional_placement,
            &mut other.exceptional_placement,
        );
        self.set_exceptional_placement(self.exceptional_placement);
        mem::swap(&mut self.prf, &mut other.prf);
        mem::swap(&mut self.membership, &mut other.membership);
    }

    fn regions(generation: &FunnelGeneration<K, V>) -> &[FlatStorage<SlotEntry<K, V>>] {
        core::slice::from_ref(&generation.storage)
    }

    fn release(&self, generation: FunnelGeneration<K, V>) {
        generation.arena.deallocate(&self.alloc);
    }

    fn hash_key(&self, key: &K) -> u64 {
        self.hash_builder.hash_one(key)
    }

    #[inline]
    fn prefetch_placement(&self, key_hash: u64) {
        let membership = self.membership_slot(key_hash);
        if self.membership.region.words != 0 {
            prefetch::prefetch_write(self.membership_ptr().wrapping_add(membership.index));
        }
        let Some(level) = self.shape.levels.first() else {
            return;
        };
        let probe = self.prf.prepare(key_hash);
        let bucket = Self::sample_ordinary(probe, level);
        self.storage
            .prefetch_slot(FunnelShape::head_start(level, bucket));
    }

    /// Inlined into both rebuild loops: outlining it costs a call per entry
    /// on the rebuild hot path.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn place_unique(&mut self, entry: SlotEntry<K, V>, key_hash: u64) -> bool {
        let probe = self.prf.prepare(key_hash);
        let membership = self.membership_slot(key_hash);
        // Until the head placements run out an entry goes where the common
        // insert puts an absent key.
        // SAFETY: the unit is read at the key's slot, with no write since.
        let placed = unsafe {
            let unit = *self.membership_ptr().add(membership.index);
            self.place_through_head(&entry.key, &entry.value, membership, unit, probe)
        };
        if placed.is_some() {
            // The table took both.
            mem::forget(entry);
            return false;
        }
        let key_fingerprint = probe.fingerprint();
        let (vacancy, exceptional) = self.resolve_vacancy(self.search_vacancy(probe));
        self.place_new_entry(
            vacancy,
            entry.key,
            entry.value,
            membership,
            key_fingerprint,
            exceptional,
        );
        exceptional
    }
}

#[allow(private_interfaces)]
impl<K, V, S, A> map::TableBackend<K, V> for FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Location = usize;
    type Vacant = FunnelVacant;
    type Hasher = S;
    type Alloc = A;
    type Scan = FunnelScan;

    const LOOKUP_IN_CALLER: bool = true;

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
        self.entries()
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.shape.max_insertions
    }

    #[inline]
    fn total_slots(&self) -> usize {
        self.shape.n
    }

    #[inline]
    fn reserve_config(&self) -> ReserveFraction {
        self.reserve_fraction
    }

    fn epoch_snapshot(&self) -> EpochSnapshot {
        // The epoch has yet to see the uncounted deletes, and the entry
        // count already has.
        let uncounted = self.uncounted_deletes();
        let mut snapshot = self.epoch.snapshot(self.entries() + uncounted);
        snapshot.had_delete |= uncounted != 0;
        snapshot
    }

    #[inline]
    unsafe fn slot_ref(&self, slot: usize) -> &SlotEntry<K, V> {
        // SAFETY: caller passes a live location, so `slot` is occupied.
        unsafe { self.storage.get_ref(slot) }
    }

    #[inline]
    unsafe fn slot_ptr(&self, slot: usize) -> *mut SlotEntry<K, V> {
        // SAFETY: caller passes a live location, so `slot` is in bounds.
        unsafe { self.storage.slot_ptr(slot) }
    }

    #[inline]
    fn replace_value(&mut self, slot: usize, value: V) -> V {
        // SAFETY: a live location names an occupied in-bounds slot.
        let entry = unsafe { self.storage.get_mut(slot) };
        mem::replace(&mut entry.value, value)
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn find<Q>(&self, key: &Q, hash: u64) -> Option<usize>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_live::<Q, FoundLane>(key, hash)
            .map(|lane| self.slot_of(lane))
    }

    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn find_entry<'a, Q>(&'a self, key: &Q, hash: u64) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_live::<Q, FoundEntry>(key, hash)
    }

    // The gate settles nearly every absent key, and the first-match scan
    // most of the rest. Only a key that scan leaves open takes the walk past
    // the head.
    //
    // Forced inline with the gate alone: an absent key's search then makes
    // no call and leaves its answer in registers.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn find_for_entry<Q>(&self, key: &Q, hash: u64) -> Result<usize, FunnelVacant>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        if let Some(levels) = self.membership_gate(hash).recorded() {
            let found = self.find_recorded_for_entry(key, hash, levels);
            // One test passes every slot: the reserved values are the
            // largest.
            if found < ENTRY_UNSETTLED {
                return Ok(found);
            }
            if found == ENTRY_UNSETTLED
                && let Some(lane) = self.find_past_head::<Q, FoundLane>(key, hash)
            {
                return Ok(self.slot_of(lane));
            }
        }
        Err(FunnelVacant { hash })
    }

    #[inline]
    fn insert_for_vacant(&mut self, key: K, value: V, vacant: FunnelVacant) -> usize {
        // An absent key goes where the insert puts one: the first free lane
        // of the head walk, which is the placement walk's slot, while the
        // head has placements left.
        let membership = self.membership_slot(vacant.hash);
        // SAFETY: as in `membership_gate_at`.
        let unit = unsafe { *self.membership_ptr().add(membership.index) };
        if self.head_left == 0 {
            self.reopen_head();
        }
        let probe = self.prf.prepare(vacant.hash);
        // SAFETY: slot and unit were read just above, with no write since.
        let placed = unsafe { self.place_through_head(&key, &value, membership, unit, probe) };
        if let Some(lane) = placed {
            // The table took both.
            mem::forget(key);
            mem::forget(value);
            return self.slot_of(lane);
        }
        self.insert_for_vacant_by_walk(key, value, vacant.hash)
    }

    // Forced inline with the shell's insert: the common insert then runs in
    // its caller, which makes no call for it.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn insert(&mut self, key: K, value: V, hash: u64) -> Option<V>
    where
        K: Hash + Eq,
    {
        // A key the filter never recorded is absent, so it needs no duplicate
        // search. That common insert calls nothing; every
        // other case is the general insert's.
        let membership = self.membership_slot(hash);
        // SAFETY: as in `membership_gate_at`.
        let unit = unsafe { *self.membership_ptr().add(membership.index) };
        if !unit_records(unit, membership.bits) {
            let probe = self.prf.prepare(hash);
            // SAFETY: slot and unit were read just above, with no write
            // since.
            if unsafe { self.place_through_head(&key, &value, membership, unit, probe) }.is_some() {
                // The table took both.
                mem::forget(key);
                mem::forget(value);
                return None;
            }
        }
        self.insert_general(key, value, hash, membership.index, unit)
    }

    // Forced inline with the shell's removal, as the lookups are.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn take<Q>(&mut self, key: &Q, hash: u64) -> Option<(K, V)>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let levels = self.membership_gate(hash).recorded()?;
        let probe = self.prf.prepare(hash);
        let unlinked = match self.first_match(key, probe, levels) {
            Ok(Found { lane, entry, .. }) => {
                // SAFETY: the scan found an occupied control byte of this
                // table's storage; `&mut self` makes the write exclusive.
                unsafe { lane.as_ptr().write(CTRL_TOMBSTONE) };
                if !self.count_delete() {
                    // SAFETY: the entry was occupied until its control byte
                    // was tombstoned, which keeps it from being read again.
                    let entry = unsafe { entry.as_ptr().read() };
                    return Some((entry.key, entry.value));
                }
                Some(entry)
            }
            Err(last) if self.unmatched_is_absent(last) => return None,
            Err(_) => None,
        };
        // SAFETY: an entry passed on was tombstoned and counted just above
        // and not read out, so the table still holds the only copy.
        let entry = unsafe { self.finish_removal(key, hash, unlinked) }?;
        // SAFETY: `finish_removal` returns an initialized entry the table
        // has unlinked and no longer owns, whether it was passed in or found
        // by the walk, and no slot has been written since.
        let entry = unsafe { entry.as_ptr().read() };
        Some((entry.key, entry.value))
    }

    fn remove(&mut self, slot: usize) -> (K, V) {
        // SAFETY: a live location names an occupied in-bounds slot; the
        // tombstone written next keeps it from being read again.
        let entry = unsafe { self.storage.take(slot) };
        // SAFETY: a live location names an in-bounds slot.
        unsafe { self.storage.mark_tombstone(slot) };
        if self.count_delete() {
            self.settle_after_delete();
        }
        (entry.key, entry.value)
    }

    #[inline]
    fn tombstone_slot(&mut self, slot: usize) {
        // SAFETY: a live location names an in-bounds slot.
        unsafe { self.storage.mark_tombstone(slot) };
    }

    #[inline]
    fn extract_finish(&mut self, slot: usize) {
        // SAFETY: a live location names an in-bounds slot.
        unsafe { self.storage.mark_tombstone(slot) };
        if self.count_delete() {
            self.settle_counts();
        }
    }

    fn finish_deferred_removals(&mut self) {
        self.settle_after_deletes();
    }

    #[inline]
    fn scan(&self) -> FunnelScan {
        FunnelScan {
            // Dense scans avoid lane extraction for nearly every slot. Only
            // sparse tables amortize masks over enough empty controls; choose
            // once so draining cannot switch modes midway through a group.
            mode: if self.entries() <= self.shape.slots / 4 {
                FunnelScanMode::Sparse(OccupiedIndices::new())
            } else {
                FunnelScanMode::Dense(
                    if self.shape.beta < GROUP_SIZE && self.shape.primary_offset != 0 {
                        DenseScan {
                            next: 0,
                            lane_end: self.shape.beta,
                            lanes: self.shape.beta,
                            padded_end: self.shape.primary_offset,
                        }
                    } else {
                        DenseScan {
                            next: 0,
                            lane_end: self.shape.slots,
                            lanes: 0,
                            padded_end: 0,
                        }
                    },
                )
            },
        }
    }

    #[inline]
    fn scan_next(&self, scan: &mut FunnelScan) -> Option<(*mut SlotEntry<K, V>, usize)> {
        match &mut scan.mode {
            FunnelScanMode::Dense(dense) => loop {
                while dense.next < dense.lane_end {
                    let slot = dense.next;
                    dense.next += 1;
                    // SAFETY: `lane_end` is at most `slots`, the storage
                    // capacity.
                    unsafe {
                        if control::is_occupied(self.storage.control_at(slot)) {
                            return Some((self.storage.slot_ptr(slot), slot));
                        }
                    }
                }
                let group_end = dense.lane_end - dense.lanes + GROUP_SIZE;
                if group_end < dense.padded_end {
                    dense.next = group_end;
                    dense.lane_end = group_end + dense.lanes;
                } else if dense.lane_end < self.shape.slots {
                    dense.next = dense.padded_end;
                    dense.lane_end = self.shape.slots;
                } else {
                    return None;
                }
            },
            FunnelScanMode::Sparse(cursor) => {
                let slot = cursor.step(&self.storage)?;
                // SAFETY: `step` yields in-bounds slots.
                Some((unsafe { self.storage.slot_ptr(slot) }, slot))
            }
        }
    }

    fn with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        Self::try_with_insert_budget(capacity, reserve, hash_builder, alloc)
            .expect("invalid Funnel construction")
    }

    fn try_with_capacity_and_reserve_and_hasher_in(
        capacity: usize,
        reserve: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        Self::try_with_insert_budget(capacity, reserve, hash_builder, alloc)
    }

    fn grow_capacity_for(&self, needed: usize) -> Option<usize> {
        self.next_growth_slots(needed)
    }

    fn resize(&mut self, new_capacity: usize) {
        self.resize_with_transition(new_capacity, EpochTransition::ExplicitResize);
    }

    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError> {
        let shape = FunnelShape::from_slots(new_capacity, self.reserve_fraction)?;
        self.try_resize_to(shape, EpochTransition::ExplicitResize)
    }

    fn shrink_to(&mut self, min_capacity: usize) {
        if self.entries() == 0 && min_capacity == 0 {
            if self.shape.n != 0 {
                self.resize_with_transition(0, EpochTransition::ExplicitResize);
            }
            return;
        }
        let requested = self.entries().max(min_capacity);
        // The insertion limit never falls as slots are added, so a shape
        // for more than this one's limit has no fewer slots.
        if requested > self.shape.max_insertions {
            return;
        }
        let Ok(shape) = FunnelShape::for_insert_budget(requested, self.reserve_fraction) else {
            panic!("capacity overflow");
        };
        if shape.n < self.shape.n {
            self.resize_with_transition(shape.n, EpochTransition::ExplicitResize);
        }
    }

    /// Lookups stop at `EMPTY`, so each value's slot becomes a tombstone
    /// before the value drops, and controls reset only after the last drop.
    /// A panicking `Drop` leaves every undropped entry reachable and counted,
    /// and a later `clear` finishes the job.
    fn clear(&mut self) {
        if mem::needs_drop::<SlotEntry<K, V>>() {
            let mut scan = OccupiedIndices::new();
            while let Some(slot) = scan.step(&self.storage) {
                // SAFETY: `step` yields occupied in-bounds slots; the slot is
                // marked a tombstone before `entry` drops, so it is never read
                // or dropped again.
                let entry = unsafe { self.storage.take(slot) };
                // SAFETY: `slot` is in bounds and its value was moved out.
                unsafe { self.storage.set_control(slot, CTRL_TOMBSTONE) };
                self.refreshed_deletes = self.refreshed_deletes.wrapping_add(1);
                self.set_entries(self.entries() - 1);
                drop(entry);
            }
        }
        self.wipe_all();
    }

    fn wipe_all(&mut self) {
        self.storage.clear_all_controls();
        // SAFETY: the storage holds `shape.slots` control bytes, and every
        // entry was dropped.
        unsafe { self.shape.reset_ordinary_controls(self.storage.ctrl_ptr()) };
        self.settle_counts();
        self.refreshed_deletes = 0;
        self.set_exceptional_placement(false);
        // Before the counts, which arm the next settle from the filter's
        // stale count.
        self.clear_membership();
        self.set_entries(0);
        self.epoch.start(EpochTransition::Clear);
    }

    fn clone_table(&self) -> Self
    where
        K: Clone,
        V: Clone,
        S: Clone,
    {
        let mut cloned = Self::try_from_shape(
            self.shape.clone(),
            self.reserve_fraction,
            self.hash_builder.clone(),
            self.alloc.clone(),
        )
        .unwrap_or_else(|error| panic!("Funnel clone allocation failed: {error}"));
        cloned.storage.clone_region_from(&self.storage);
        cloned.epoch = self.epoch;
        cloned.stale_membership = self.stale_membership;
        cloned.refreshed_deletes = self.refreshed_deletes;
        // The uncounted deletes come along: counted here, they land in the
        // clone's own counts.
        cloned.settle_left = cloned.settle_armed.wrapping_sub(self.uncounted_deletes());
        cloned.set_entries(self.entries());
        cloned.set_exceptional_placement(self.exceptional_placement);
        cloned.prf = self.prf;
        // Slots are copied rather than reinserted, so the filter comes with them.
        // SAFETY: each region belongs to its own table's arena; the source has
        // the same shape, so equal word counts; distinct arenas never overlap.
        unsafe {
            cloned.membership.region.copy_from::<FilterUnit>(
                cloned.arena.as_ptr(),
                self.membership.region,
                self.arena.as_ptr(),
            );
        };
        cloned
    }
}

#[cfg(test)]
mod tests;
