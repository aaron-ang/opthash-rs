//! Paper-exact Funnel placement with explicit dynamic-map epoch extensions.
use core::fmt;
use core::hash::{BuildHasher, Hash};
use core::mem::{self, MaybeUninit};

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
use crate::membership::{self, MembershipKey, MembershipRegion};
use crate::raw::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::raw::config::GROUP_SIZE;
use crate::raw::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE};
use crate::raw::iter::OccupiedIndices;
use crate::raw::rebuild::{self, Rebuildable};
use crate::raw::simd;
use crate::{macros, map};

const FUNNEL_PROBE_SEED: u64 = probe::WYHASH_DEFAULT_SECRET[3];
/// Added to the probe seed by each placement-recovery rebuild. The seed passes
/// through `mix64` before routing, so any odd step draws a fresh mapping.
const FUNNEL_RESEED_STEP: u64 = probe::WYHASH_DEFAULT_SECRET[0];

/// Pointerless scan progress through Funnel's flat storage.
#[derive(Clone, Debug)]
pub struct FunnelScan {
    mode: FunnelScanMode,
}

#[derive(Clone, Debug)]
enum FunnelScanMode {
    Dense(usize),
    Sparse(OccupiedIndices),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LevelShape {
    offset: usize,
    bucket_range: PreparedProbeRange,
    ordinary_counter_base: u64,
}

#[derive(Clone, Debug)]
struct FunnelShape {
    n: usize,
    max_insertions: usize,
    levels: Box<[LevelShape]>,
    beta: usize,
    loglog_ceiling: usize,
    primary_offset: usize,
    primary_range: PreparedProbeRange,
    fallback_offset: usize,
    fallback_bucket_width: usize,
    fallback_bucket_range: PreparedProbeRange,
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
        if n == 0 {
            return Ok(Self::empty());
        }
        let config = PaperConfig::new(n, reserve.exponent())
            .map_err(|_| TryReserveError::CapacityOverflow)?;
        let plan = config
            .funnel_plan()
            .map_err(|_| TryReserveError::CapacityOverflow)?;
        let mut offset = 0_usize;
        let mut levels = Vec::new();
        levels
            .try_reserve_exact(plan.alpha())
            .map_err(|_| TryReserveError::AllocError)?;
        for (level_index, bucket_count) in plan.ordinary_bucket_counts().enumerate() {
            levels.push(LevelShape {
                offset,
                bucket_range: PreparedProbeRange::new(bucket_count)
                    .map_err(|_| TryReserveError::CapacityOverflow)?,
                ordinary_counter_base: FunnelPrf::ordinary_counter_base(level_index as u64)
                    .ok_or(TryReserveError::CapacityOverflow)?,
            });
            offset = offset
                .checked_add(
                    bucket_count
                        .checked_mul(plan.beta())
                        .ok_or(TryReserveError::CapacityOverflow)?,
                )
                .ok_or(TryReserveError::CapacityOverflow)?;
        }
        let primary_offset = offset;
        let primary_len = plan.special_primary_len();
        let primary_range =
            PreparedProbeRange::new(primary_len).map_err(|_| TryReserveError::CapacityOverflow)?;
        let fallback_offset = primary_offset
            .checked_add(primary_len)
            .ok_or(TryReserveError::CapacityOverflow)?;
        let fallback_len = plan.special_fallback_len();
        if fallback_offset
            .checked_add(fallback_len)
            .ok_or(TryReserveError::CapacityOverflow)?
            != n
        {
            return Err(TryReserveError::CapacityOverflow);
        }
        let loglog_ceiling =
            u8::try_from(plan.loglog_ceiling()).map_err(|_| TryReserveError::CapacityOverflow)?;
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
                .map_err(|_| TryReserveError::CapacityOverflow)?,
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
        if !(3..usize::BITS).contains(&d) {
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
            if let Ok(shape) = Self::from_slots(n, reserve)
                && shape.max_insertions >= requested
            {
                return Ok(shape);
            }
            n = n.checked_add(1).ok_or(TryReserveError::CapacityOverflow)?;
        }
    }
}

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
// EMPTY, and is re-stamped before that arena is freed.
unsafe impl<T> ArenaSlots<T> for FlatStorage<T> {
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

/// One word of the membership filter tail.
type MembershipWord = u64;

/// One key's filter location: which word and which bits. Computed once per
/// operation and carried to the record step, so placement never re-derives it.
#[derive(Clone, Copy)]
struct MembershipSlot {
    index: usize,
    bits: u64,
}

/// A loaded filter word paired with the key's bits, split from the test so the
/// load can be issued before the work that hides its latency. An absent tail
/// yields a gate that never passes, matching an empty table. Two words, not
/// the slot: a lookup never records, and the extra field costs the miss path
/// on every call.
#[derive(Clone, Copy)]
struct MembershipGate {
    word: MembershipWord,
    bits: u64,
}

impl MembershipGate {
    /// `false` proves no insert ever recorded this key.
    #[inline]
    const fn passes(self) -> bool {
        self.word & self.bits == self.bits
    }
}

/// Where each region of one Funnel epoch's arena lives.
struct FunnelLayout {
    layout: Layout,
    data_offset: usize,
    control_bytes: usize,
    membership: MembershipRegion,
}

type FunnelStorageBuild<K, V> = (Arena, FlatStorage<SlotEntry<K, V>>, MembershipRegion);

fn try_allocate_storage<K, V, A: Allocator>(
    n: usize,
    alloc: &A,
) -> Result<FunnelStorageBuild<K, V>, TryReserveError> {
    let shape = funnel_layout::<K, V>(n)?;
    let arena = Arena::try_allocate_with_ctrl_zeroed(shape.layout, shape.control_bytes, alloc)?;
    // The arena zeroes control bytes only; an empty filter must read as
    // "nothing recorded".
    // SAFETY: `shape.membership` was laid out for this arena by `funnel_layout`.
    unsafe { shape.membership.clear::<MembershipWord>(arena.as_ptr()) };
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
    Ok((arena, storage, shape.membership))
}

fn funnel_layout<K, V>(n: usize) -> Result<FunnelLayout, TryReserveError> {
    let control_bytes = if n == 0 {
        0
    } else {
        n.checked_add(GROUP_SIZE - 1)
            .ok_or(TryReserveError::CapacityOverflow)?
    };
    let (base_layout, data_offset) = arena::layout_for_extents::<K, V>(control_bytes, n)?;
    let (layout, membership) = MembershipRegion::extend::<MembershipWord>(base_layout, n)?;
    Ok(FunnelLayout {
        layout,
        data_offset,
        control_bytes,
        membership,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchResult {
    Hit(usize),
    Vacant(usize),
    Full,
    RangeFailure,
}

/// A known-absent search, retained only while the entry borrows its map.
#[derive(Debug)]
pub struct FunnelVacant {
    hash: u64,
    // Allocated slot indices are below isize::MAX. Reserve the two largest
    // usize values for unsearched and exhausted walks, keeping the token to
    // a hash and one slot word instead of a prepared probe and enum payload.
    exact: usize,
}

impl FunnelVacant {
    const UNSEARCHED: usize = usize::MAX;
    const EXHAUSTED: usize = usize::MAX - 1;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BucketScanResult<T> {
    Hit(T),
    Empty(usize),
    Full,
}

/// Scans one masked SIMD group containing `logical_lanes` controls.
///
/// # Safety
///
/// `ctrl_ptr.add(start)` must be readable for `GROUP_SIZE` bytes,
/// `logical_lanes <= GROUP_SIZE`, and every slot passed to `inspect_match`
/// must be valid for the corresponding data arena.
#[inline]
unsafe fn scan_funnel_group<T>(
    ctrl_ptr: *const u8,
    start: usize,
    logical_lanes: usize,
    fingerprint: u8,
    first_tombstone: &mut Option<usize>,
    inspect_match: &mut impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    // SAFETY: caller guarantees `GROUP_SIZE` readable bytes at `start`.
    let group = unsafe { ctrl_ptr.add(start) };
    // SAFETY: as above, `group` is readable for one full group.
    let mut events = unsafe { simd::free_mask_group(group) };
    // SAFETY: as above.
    events.0 |= unsafe { simd::eq_mask_group(group, fingerprint) }.0;
    for lane in events {
        if lane >= logical_lanes {
            break;
        }
        let slot = start + lane;
        // SAFETY: `lane < logical_lanes <= GROUP_SIZE`, inside the readable group.
        let control = unsafe { *ctrl_ptr.add(slot) };
        if control == CTRL_TOMBSTONE {
            first_tombstone.get_or_insert(slot);
        } else if control == CTRL_EMPTY {
            return BucketScanResult::Empty(first_tombstone.unwrap_or(slot));
        } else if let Some(hit) = inspect_match(slot) {
            return BucketScanResult::Hit(hit);
        }
    }
    BucketScanResult::Full
}

/// Scans exactly `length` logical controls in order using masked SIMD groups.
///
/// # Safety
///
/// `ctrl_ptr.add(start)` must be readable through `length + GROUP_SIZE - 1`
/// bytes, and every slot passed to `inspect_match` must be a valid logical
/// slot for the corresponding data arena.
unsafe fn scan_funnel_bucket<T>(
    ctrl_ptr: *const u8,
    start: usize,
    length: usize,
    fingerprint: u8,
    first_tombstone: &mut Option<usize>,
    mut inspect_match: impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    if length <= GROUP_SIZE {
        // SAFETY: `length <= GROUP_SIZE`, so the caller's
        // `length + GROUP_SIZE - 1` readable bytes cover one full group.
        return unsafe {
            scan_funnel_group(
                ctrl_ptr,
                start,
                length,
                fingerprint,
                first_tombstone,
                &mut inspect_match,
            )
        };
    }
    // SAFETY: caller upholds this function's bounds, and `length > GROUP_SIZE`.
    unsafe {
        scan_funnel_bucket_multi_group(
            ctrl_ptr,
            start,
            length,
            fingerprint,
            first_tombstone,
            inspect_match,
        )
    }
}

/// Keeps the configurable multi-group case out of the default one-group path.
///
/// # Safety
///
/// The bounds requirements are identical to [`scan_funnel_bucket`], and
/// `length` must be greater than `GROUP_SIZE`.
#[inline(never)]
unsafe fn scan_funnel_bucket_multi_group<T>(
    ctrl_ptr: *const u8,
    start: usize,
    length: usize,
    fingerprint: u8,
    first_tombstone: &mut Option<usize>,
    mut inspect_match: impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    debug_assert!(length > GROUP_SIZE);
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
        // SAFETY: `position < start + length`, so a full group from `position`
        // stays within the caller's `length + GROUP_SIZE - 1` readable bytes.
        match unsafe {
            scan_funnel_group(
                ctrl_ptr,
                position,
                logical_lanes,
                fingerprint,
                first_tombstone,
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

/// Clean-epoch scan of one group: the first free lane is the terminating EMPTY.
///
/// # Safety
///
/// The bounds requirements are identical to [`scan_funnel_group`], and the
/// logical group must contain no tombstones.
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
    // Iterator search on purpose: `BitMask::first_below` is the same test, but
    // here LLVM lowers it to a select chain instead of one test-and-branch.
    // SAFETY: as above.
    let first_empty = unsafe { simd::free_mask_group(group) }
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

/// Clean-epoch specialization over `length` logical controls.
///
/// # Safety
///
/// The bounds requirements are identical to [`scan_funnel_bucket`], and the
/// logical table must contain no tombstones.
unsafe fn scan_clean_funnel_bucket<T>(
    ctrl_ptr: *const u8,
    start: usize,
    length: usize,
    fingerprint: u8,
    mut inspect_match: impl FnMut(usize) -> Option<T>,
) -> BucketScanResult<T> {
    if length <= GROUP_SIZE {
        // SAFETY: `length <= GROUP_SIZE`, so the caller's readable span covers
        // one full group; the caller also guarantees no tombstones.
        return unsafe {
            scan_clean_funnel_group(ctrl_ptr, start, length, fingerprint, &mut inspect_match)
        };
    }
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
        // SAFETY: `position < start + length`, so a full group from `position`
        // stays within the caller's readable span; no tombstones by contract.
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

/// First free (EMPTY or TOMBSTONE) slot among `length` logical controls: the
/// slot the general scan reports as `Vacant` for a key absent from the bucket,
/// without the fingerprint mask or key compares.
///
/// # Safety
///
/// The bounds requirements are identical to [`scan_funnel_bucket`].
#[inline]
unsafe fn first_free_in_bucket(ctrl_ptr: *const u8, start: usize, length: usize) -> Option<usize> {
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
        // SAFETY: `position < start + length`, so a full group from `position`
        // stays within the caller's `length + GROUP_SIZE - 1` readable bytes.
        let free = unsafe { simd::free_mask_group(ctrl_ptr.add(position)) };
        if let Some(lane) = free.first_below(logical_lanes) {
            return Some(position + lane);
        }
        position += logical_lanes;
    }
    None
}

/// Paper-exact Funnel hashing within each table epoch. Deletion, growth, and
/// exceptional collision recovery are built-in dynamic-map behavior beyond
/// the paper's fixed-size insertion model.
pub struct FunnelTable<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    shape: FunnelShape,
    storage: FlatStorage<SlotEntry<K, V>>,
    len: usize,
    tombstones: usize,
    reserve_fraction: ReserveFraction,
    hash_builder: S,
    alloc: A,
    arena: Arena,
    epoch: EpochState,
    exceptional_placement: bool,
    /// Seeds every probe sequence. Starts at [`FUNNEL_PROBE_SEED`]; a
    /// placement-recovery rebuild advances it, because survivors of slot-order
    /// deletes are skewed toward the buckets the old seed left full.
    probe_seed: u64,
    /// Cached location of the membership filter tail. Lookups load one word
    /// from it before probing; see [`crate::membership`].
    membership: MembershipRegion,
    /// Deletes since the filter last matched the live set; see
    /// [`membership::refresh_deletes`].
    stale_membership: usize,
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
        let (arena, storage, membership) = try_allocate_storage(shape.n, &alloc)?;
        Ok(Self {
            shape,
            storage,
            len: 0,
            tombstones: 0,
            reserve_fraction,
            hash_builder,
            alloc,
            arena,
            epoch: EpochState::initial(),
            exceptional_placement: false,
            probe_seed: FUNNEL_PROBE_SEED,
            membership,
            stale_membership: 0,
        })
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
    /// `slot < self.shape.n`.
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

    /// Lookup-side search over a probe the caller already prepared.
    fn search_exact_prepared<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        key_fingerprint: u8,
    ) -> SearchResult
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.search_exact_mode::<Q, false>(key, probe, key_fingerprint)
    }

    #[cfg(test)]
    fn search_exact_for_insert<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> SearchResult
    where
        Q: Equivalent<K> + ?Sized,
    {
        let probe = FunnelPrf::new(self.probe_seed).prepare(key_hash);
        self.search_exact_prepared_for_insert(key, probe, key_fingerprint)
    }

    /// Duplicate search ahead of an insert: the clean-epoch scan when no
    /// tombstone can sit on the walk, the general scan otherwise.
    ///
    /// Kept out of line on purpose: inlined next to the placement walk, LLVM
    /// turns the per-level free-lane test into a costlier select chain.
    #[inline(never)]
    fn search_exact_prepared_for_insert<Q>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        key_fingerprint: u8,
    ) -> SearchResult
    where
        Q: Equivalent<K> + ?Sized,
    {
        if self.tombstones == 0 {
            self.search_exact_mode::<Q, true>(key, probe, key_fingerprint)
        } else {
            self.search_exact_mode::<Q, false>(key, probe, key_fingerprint)
        }
    }

    fn search_exact_mode<Q, const CLEAN_EPOCH: bool>(
        &self,
        key: &Q,
        probe: PreparedFastFunnelProbe,
        key_fingerprint: u8,
    ) -> SearchResult
    where
        Q: Equivalent<K> + ?Sized,
    {
        if self.shape.n == 0 {
            return SearchResult::Full;
        }
        let mut first_tombstone = None;

        for level in &self.shape.levels {
            let level_probe = probe.prepare_counter_base(level.ordinary_counter_base);
            let Some(bucket) = Self::sample(&level_probe, 0, level.bucket_range) else {
                return first_tombstone.map_or(SearchResult::RangeFailure, SearchResult::Vacant);
            };
            let start = level.offset + bucket * self.shape.beta;
            let scan = if CLEAN_EPOCH {
                // SAFETY: an ordinary bucket ends at or before `n`, and the
                // control array pads `GROUP_SIZE - 1` bytes past `n`;
                // `CLEAN_EPOCH` is only chosen with zero tombstones; matched
                // lanes carry the fingerprint, so they are occupied.
                unsafe {
                    scan_clean_funnel_bucket(
                        self.storage.ctrl_ptr(),
                        start,
                        self.shape.beta,
                        key_fingerprint,
                        |slot| {
                            let entry = self.storage.get_ref(slot);
                            key.equivalent(&entry.key).then_some(slot)
                        },
                    )
                }
            } else {
                // SAFETY: an ordinary bucket ends at or before `n`, and the
                // control array pads `GROUP_SIZE - 1` bytes past `n`; matched
                // lanes carry the fingerprint, so they are occupied.
                unsafe {
                    scan_funnel_bucket(
                        self.storage.ctrl_ptr(),
                        start,
                        self.shape.beta,
                        key_fingerprint,
                        &mut first_tombstone,
                        |slot| {
                            let entry = self.storage.get_ref(slot);
                            key.equivalent(&entry.key).then_some(slot)
                        },
                    )
                }
            };
            match scan {
                BucketScanResult::Hit(slot) => return SearchResult::Hit(slot),
                BucketScanResult::Empty(slot) => return SearchResult::Vacant(slot),
                BucketScanResult::Full => {}
            }
        }

        // The special-array tail stays inline. Outlining it as a `#[cold]` call
        // costs the ordinary walk more in call setup than it recovers in
        // register pressure, on hits and misses alike.
        let primary_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_PRIMARY_BASE);
        for logical_probe in 0..self.shape.loglog_ceiling {
            let Some(local) = Self::sample(
                &primary_probe,
                self.shape.encode_logical_probe(logical_probe),
                self.shape.primary_range,
            ) else {
                return first_tombstone.map_or(SearchResult::RangeFailure, SearchResult::Vacant);
            };
            let slot = self.shape.primary_offset + local;
            // SAFETY: a primary probe stays inside the primary range.
            if unsafe { self.storage.control_at(slot) } == CTRL_TOMBSTONE {
                first_tombstone.get_or_insert(slot);
                continue;
            }
            // SAFETY: a primary probe stays inside the primary range.
            match unsafe { self.inspect_slot(slot, key_fingerprint, key) } {
                Some(true) => return SearchResult::Hit(slot),
                Some(false) => return SearchResult::Vacant(first_tombstone.unwrap_or(slot)),
                None => {}
            }
        }

        let first_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_A_BASE);
        let Some(first_bucket) = Self::sample(&first_probe, 0, self.shape.fallback_bucket_range)
        else {
            return first_tombstone.map_or(SearchResult::RangeFailure, SearchResult::Vacant);
        };
        let second_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_B_BASE);
        let Some(second_bucket) = Self::sample(&second_probe, 0, self.shape.fallback_bucket_range)
        else {
            return first_tombstone.map_or(SearchResult::RangeFailure, SearchResult::Vacant);
        };
        for slot_in_bucket in 0..self.shape.fallback_bucket_width {
            for bucket in [first_bucket, second_bucket] {
                let slot = self.shape.fallback_offset
                    + bucket * self.shape.fallback_bucket_width
                    + slot_in_bucket;
                // SAFETY: both buckets lie inside the fallback range.
                if unsafe { self.storage.control_at(slot) } == CTRL_TOMBSTONE {
                    first_tombstone.get_or_insert(slot);
                    continue;
                }
                // SAFETY: both buckets lie inside the fallback range.
                match unsafe { self.inspect_slot(slot, key_fingerprint, key) } {
                    Some(true) => return SearchResult::Hit(slot),
                    Some(false) => {
                        return SearchResult::Vacant(first_tombstone.unwrap_or(slot));
                    }
                    None => {}
                }
            }
        }
        first_tombstone.map_or(SearchResult::Full, SearchResult::Vacant)
    }

    /// Placement walk for a key already known to be absent: the buckets of
    /// `search_exact_mode` in the same order, returning the first free slot,
    /// which is the `Vacant` slot the exact search reports for an absent key.
    /// No fingerprint mask, no key compares, never `Hit`.
    ///
    /// Forced inline: the loop keeps many registers live, so a call costs more
    /// in prologue and epilogue than the walk. The special-array tail stays out
    /// of line because almost every insert finds its slot in the funnel. It
    /// duplicates the exact search's special leg on purpose: a shared
    /// closure-driven walker slows the exact search's misses.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn search_vacancy(&self, probe: PreparedFastFunnelProbe) -> SearchResult {
        #[cfg(test)]
        tests::VACANCY_WALKS.with(|walks| walks.set(walks.get() + 1));
        if self.shape.n == 0 {
            return SearchResult::Full;
        }
        let ctrl_ptr = self.storage.ctrl_ptr();
        for level in &self.shape.levels {
            let level_probe = probe.prepare_counter_base(level.ordinary_counter_base);
            let Some(bucket) = Self::sample(&level_probe, 0, level.bucket_range) else {
                return SearchResult::RangeFailure;
            };
            let start = level.offset + bucket * self.shape.beta;
            // SAFETY: an ordinary bucket ends at or before `n`, and the control
            // array pads `GROUP_SIZE - 1` bytes past `n`.
            if let Some(slot) = unsafe { first_free_in_bucket(ctrl_ptr, start, self.shape.beta) } {
                return SearchResult::Vacant(slot);
            }
        }
        self.search_vacancy_special(probe)
    }

    /// Special-array leg of [`Self::search_vacancy`]: primary probes, then the
    /// two fallback buckets, in the exact search's order.
    #[inline(never)]
    fn search_vacancy_special(&self, probe: PreparedFastFunnelProbe) -> SearchResult {
        let primary_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_PRIMARY_BASE);
        for logical_probe in 0..self.shape.loglog_ceiling {
            let Some(local) = Self::sample(
                &primary_probe,
                self.shape.encode_logical_probe(logical_probe),
                self.shape.primary_range,
            ) else {
                return SearchResult::RangeFailure;
            };
            let slot = self.shape.primary_offset + local;
            // SAFETY: a primary probe stays inside the primary range.
            if control::is_free(unsafe { self.storage.control_at(slot) }) {
                return SearchResult::Vacant(slot);
            }
        }

        let first_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_A_BASE);
        let Some(first_bucket) = Self::sample(&first_probe, 0, self.shape.fallback_bucket_range)
        else {
            return SearchResult::RangeFailure;
        };
        let second_probe = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_B_BASE);
        let Some(second_bucket) = Self::sample(&second_probe, 0, self.shape.fallback_bucket_range)
        else {
            return SearchResult::RangeFailure;
        };
        for slot_in_bucket in 0..self.shape.fallback_bucket_width {
            for bucket in [first_bucket, second_bucket] {
                let slot = self.shape.fallback_offset
                    + bucket * self.shape.fallback_bucket_width
                    + slot_in_bucket;
                // SAFETY: both buckets lie inside the fallback range.
                if control::is_free(unsafe { self.storage.control_at(slot) }) {
                    return SearchResult::Vacant(slot);
                }
            }
        }
        SearchResult::Full
    }

    fn find_by_full_scan<Q>(&self, key: &Q, key_fingerprint: u8) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // SAFETY: `slot < n`, the storage capacity, and a fingerprint match
        // means the slot is occupied.
        (0..self.shape.n).find(|&slot| unsafe {
            self.storage.control_at(slot) == key_fingerprint
                && key.equivalent(&self.storage.get_ref(slot).key)
        })
    }

    #[inline]
    fn membership_ptr(&self) -> *mut MembershipWord {
        // SAFETY: `self.membership` was laid out for `self.arena`; both are
        // replaced together on every resize.
        unsafe { self.membership.ptr::<MembershipWord>(self.arena.as_ptr()) }
    }

    /// `false` proves no insert ever recorded this key.
    #[cfg(test)]
    #[inline]
    fn membership_maybe_contains(&self, key_hash: u64) -> bool {
        let words = self.membership.words;
        if words == 0 {
            return false;
        }
        let bits = MembershipKey::from_signature(key_hash).bits();
        let word = MembershipKey::word(key_hash, words);
        // SAFETY: `word` is a multiply-high reduction below `words`, and the
        // arena's tail holds exactly that many zero-initialized words.
        unsafe { *self.membership_ptr().add(word) & bits == bits }
    }

    /// This key's filter word index and bits for the current epoch. Only an
    /// empty geometry has no words; its slot is never dereferenced.
    #[inline]
    fn membership_slot(&self, key_hash: u64) -> MembershipSlot {
        MembershipSlot {
            index: MembershipKey::word(key_hash, self.membership.words),
            bits: MembershipKey::from_signature(key_hash).bits(),
        }
    }

    /// Loads this key's filter word without testing it, so a lookup can run the
    /// probe's mix chain while the load is in flight.
    #[inline]
    fn membership_gate(&self, key_hash: u64) -> MembershipGate {
        self.membership_gate_at(self.membership_slot(key_hash))
    }

    /// [`Self::membership_gate`] for a slot the caller keeps, so an insert can
    /// record at the same slot without re-deriving it after placement.
    #[inline]
    fn membership_gate_at(&self, slot: MembershipSlot) -> MembershipGate {
        if self.membership.words == 0 {
            return MembershipGate {
                word: 0,
                bits: u64::MAX,
            };
        }
        MembershipGate {
            // SAFETY: `slot.index` is a multiply-high reduction below `words`,
            // and the arena's tail holds exactly that many words.
            word: unsafe { *self.membership_ptr().add(slot.index) },
            bits: slot.bits,
        }
    }

    /// Records a key at a slot derived from this epoch, including entries
    /// exceptional recovery places outside their funnel.
    #[inline]
    fn record_membership(&mut self, slot: MembershipSlot) {
        if self.membership.words != 0 {
            // SAFETY: as in `membership_gate`.
            unsafe { *self.membership_ptr().add(slot.index) |= slot.bits };
        }
    }

    fn clear_membership(&mut self) {
        // SAFETY: as in `membership_ptr`.
        unsafe { self.membership.clear::<MembershipWord>(self.arena.as_ptr()) };
        self.stale_membership = 0;
    }

    /// Shared tail of `clear` and `wipe_all` once every slot is free.
    fn finish_clear(&mut self) {
        self.exceptional_placement = false;
        self.clear_membership();
        self.epoch.start(EpochTransition::Clear);
    }

    /// Re-record the filter from the live entries, dropping the bits departed
    /// keys left behind. Entries stay put; only the filter tail is rewritten.
    #[cold]
    #[inline(never)]
    fn refresh_membership(&mut self) {
        self.clear_membership();
        let mut scan = OccupiedIndices::new();
        while let Some(slot) = scan.step(&self.storage) {
            let hash = {
                // SAFETY: `step` yields occupied in-bounds slots.
                let entry = unsafe { self.storage.get_ref(slot) };
                self.hash_builder.hash_one(&entry.key)
            };
            let membership = self.membership_slot(hash);
            self.record_membership(membership);
        }
    }

    /// Same-size cleanup once tombstones pass their threshold; otherwise a
    /// filter refresh once departed keys pass theirs. The cleanup rebuilds
    /// the filter too, so the two never stack.
    fn settle_after_deletes(&mut self) {
        if self.tombstones > capacity::tombstone_cleanup_threshold(self.shape.n) {
            self.resize_with_transition(self.shape.n, EpochTransition::TombstoneCleanup);
        } else if self.stale_membership > membership::refresh_deletes(self.shape.max_insertions) {
            self.refresh_membership();
        }
    }

    fn copy_membership_from(&mut self, source: &Self) {
        // SAFETY: each region belongs to its own table's arena; the source has
        // the same shape, so equal word counts; distinct arenas never overlap.
        unsafe {
            self.membership.copy_from::<MembershipWord>(
                self.arena.as_ptr(),
                source.membership,
                source.arena.as_ptr(),
            );
        };
    }

    fn find_location<Q>(&self, key: &Q, key_hash: u64, key_fingerprint: u8) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.locate(key, key_hash, key_fingerprint, |_| ()).ok()
    }

    /// Lookup protocol shared by reads and entries. `Err(None)` means the
    /// filter rejected the key before any walk; `Err(Some(_))` maps the exact
    /// walk's miss, which is never `Hit`, through `on_miss`.
    #[inline]
    fn locate<Q, R>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
        on_miss: impl FnOnce(SearchResult) -> R,
    ) -> Result<usize, Option<R>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // Issue the filter load, then prepare the probe while it is in flight. A
        // key the filter never recorded was never inserted, so neither the walk
        // nor the exceptional full scan can find it.
        let gate = self.membership_gate(key_hash);
        let probe = FunnelPrf::new(self.probe_seed).prepare(key_hash);
        if !gate.passes() {
            return Err(None);
        }
        match self.search_exact_prepared(key, probe, key_fingerprint) {
            SearchResult::Hit(slot) => Ok(slot),
            miss if self.exceptional_placement => self
                .find_by_full_scan(key, key_fingerprint)
                .ok_or_else(|| Some(on_miss(miss))),
            miss => Err(Some(on_miss(miss))),
        }
    }

    fn find_entry_ref<'a, Q>(
        &'a self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let slot = self.find_location(key, key_hash, key_fingerprint)?;
        // SAFETY: `find_location` returns only occupied in-bounds slots.
        Some(unsafe { self.storage.get_ref(slot) })
    }

    fn first_free_global(&self) -> Option<usize> {
        // SAFETY: `slot < n`, the storage capacity.
        (0..self.shape.n).find(|&slot| control::is_free(unsafe { self.storage.control_at(slot) }))
    }

    fn place_new_entry(
        &mut self,
        slot: usize,
        key: K,
        value: V,
        membership: MembershipSlot,
        key_fingerprint: u8,
        exceptional: bool,
    ) {
        // SAFETY: callers pass a free slot from a probe within the storage.
        let was_tombstone = unsafe { self.storage.control_at(slot) } == CTRL_TOMBSTONE;
        // SAFETY: as above, and `key_fingerprint` is an occupied control.
        unsafe {
            self.storage
                .write_with_control(slot, SlotEntry { key, value }, key_fingerprint);
        }
        self.record_membership(membership);
        self.len += 1;
        if was_tombstone {
            self.tombstones -= 1;
        }
        if exceptional {
            self.exceptional_placement = true;
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
    /// Returns `true` when a resize ran, so a search from before it is stale.
    #[inline]
    fn prepare_vacant_insert(&mut self) -> bool {
        if self.len >= self.shape.max_insertions {
            self.grow_for_next_insert();
            true
        } else {
            false
        }
    }

    #[cold]
    #[inline(never)]
    fn grow_for_next_insert(&mut self) {
        let slots = self
            .next_growth_slots(self.len.saturating_add(1))
            .expect("capacity overflow");
        self.resize_with_transition(slots, EpochTransition::Growth);
    }

    /// Places a known-absent key at its search's vacancy. An exhausted walk
    /// first rebuilds the table at the same size under a fresh probe seed,
    /// which clears tombstones and re-places every survivor, then walks
    /// again; only a second exhaustion places the key outside its funnel.
    fn place_absent_after_search(
        &mut self,
        key: K,
        value: V,
        key_hash: u64,
        mut membership: MembershipSlot,
        exact: SearchResult,
    ) -> usize {
        let key_fingerprint = control::control_fingerprint(key_hash);
        // An epoch that already placed outside its funnels was either rebuilt
        // for this reason or failed in its own rebuild; another would cost
        // O(n) per insert without helping.
        let rebuilt = !matches!(exact, SearchResult::Vacant(_)) && !self.exceptional_placement;
        let exact = if rebuilt {
            self.resize_with_transition(self.shape.n, EpochTransition::PlacementRecovery);
            membership = self.membership_slot(key_hash);
            self.search_vacancy(FunnelPrf::new(self.probe_seed).prepare(key_hash))
        } else {
            exact
        };
        let (slot, exceptional) = self.resolve_vacancy(exact);
        self.place_new_entry(slot, key, value, membership, key_fingerprint, exceptional);
        if exceptional && rebuilt {
            self.epoch.note_placement_recovery();
        } else if exceptional {
            self.epoch
                .start_with_placement_recovery(EpochTransition::PlacementRecovery);
        }
        slot
    }

    /// Maps a known-absent search to `(slot, exceptional)`: its vacancy, or
    /// the first free slot anywhere once the walk is exhausted. Both callers
    /// run under the insertion limit, which reserves a free slot.
    #[allow(clippy::inline_always)]
    #[inline(always)]
    fn resolve_vacancy(&self, exact: SearchResult) -> (usize, bool) {
        match exact {
            SearchResult::Vacant(slot) => {
                debug_assert!(
                    // SAFETY: a vacancy is a probed in-bounds slot.
                    control::is_free(unsafe { self.storage.control_at(slot) }),
                    "stale Funnel vacancy at slot {slot}"
                );
                (slot, false)
            }
            SearchResult::Hit(_) => unreachable!("known-absent Funnel search found a key"),
            SearchResult::Full | SearchResult::RangeFailure => (
                self.first_free_global()
                    .expect("Funnel insertion limit reserves a free slot"),
                true,
            ),
        }
    }

    /// Inserts a key the caller has proven absent. Runs the placement walk
    /// only, which lands on the same slot the exact search would report.
    #[cfg(test)]
    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> usize {
        let vacant = FunnelVacant {
            hash: key_hash,
            exact: FunnelVacant::UNSEARCHED,
        };
        map::TableBackend::insert_for_vacant(self, key, value, vacant)
    }

    fn resize_with_transition(&mut self, slots: usize, transition: EpochTransition) {
        let shape = FunnelShape::from_slots(slots, self.reserve_fraction)
            .expect("compatible Funnel resize geometry");
        let n = shape.n;
        if self.try_resize_to(shape, transition).is_err() {
            let layout = funnel_layout::<K, V>(n).expect("constructed Funnel layout");
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
        let (arena, storage, membership) = try_allocate_storage(shape.n, &self.alloc)?;
        let probe_seed = if matches!(transition, EpochTransition::PlacementRecovery) {
            self.probe_seed.wrapping_add(FUNNEL_RESEED_STEP)
        } else {
            self.probe_seed
        };
        let recovered = rebuild::rebuild(
            self,
            FunnelGeneration {
                shape,
                storage,
                len: 0,
                tombstones: 0,
                arena,
                exceptional_placement: false,
                probe_seed,
                membership,
                stale_membership: 0,
            },
        );
        self.epoch.start_epoch(transition, recovered);
        Ok(())
    }
}

/// The fields a resize replaces as a unit.
pub(crate) struct FunnelGeneration<K, V> {
    shape: FunnelShape,
    storage: FlatStorage<SlotEntry<K, V>>,
    len: usize,
    tombstones: usize,
    arena: Arena,
    exceptional_placement: bool,
    probe_seed: u64,
    membership: MembershipRegion,
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
        mem::swap(&mut self.len, &mut other.len);
        mem::swap(&mut self.tombstones, &mut other.tombstones);
        mem::swap(&mut self.arena, &mut other.arena);
        mem::swap(
            &mut self.exceptional_placement,
            &mut other.exceptional_placement,
        );
        mem::swap(&mut self.probe_seed, &mut other.probe_seed);
        mem::swap(&mut self.membership, &mut other.membership);
        mem::swap(&mut self.stale_membership, &mut other.stale_membership);
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

    fn place_unique(&mut self, entry: SlotEntry<K, V>, key_hash: u64) -> bool {
        let key_fingerprint = control::control_fingerprint(key_hash);
        let probe = FunnelPrf::new(self.probe_seed).prepare(key_hash);
        let (slot, exceptional) = self.resolve_vacancy(self.search_vacancy(probe));
        let membership = self.membership_slot(key_hash);
        self.place_new_entry(
            slot,
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
        self.len
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
        self.epoch.snapshot(self.len)
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

    #[inline]
    fn find<Q>(&self, key: &Q, hash: u64) -> Option<usize>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_location(key, hash, control::control_fingerprint(hash))
    }

    #[inline]
    fn find_entry<'a, Q>(&'a self, key: &Q, hash: u64) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_entry_ref(key, hash, control::control_fingerprint(hash))
    }

    #[inline]
    fn find_for_entry<Q>(&self, key: &Q, hash: u64) -> Result<usize, FunnelVacant>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        let found = self.locate(
            key,
            hash,
            control::control_fingerprint(hash),
            |miss| match miss {
                SearchResult::Vacant(slot) => slot,
                _ => FunnelVacant::EXHAUSTED,
            },
        );
        let exact = match found {
            Ok(slot) => return Ok(slot),
            Err(exact) => exact.unwrap_or(FunnelVacant::UNSEARCHED),
        };
        Err(FunnelVacant { hash, exact })
    }

    #[inline]
    fn insert_for_vacant(&mut self, key: K, value: V, vacant: FunnelVacant) -> usize {
        let exact = if self.prepare_vacant_insert() || vacant.exact == FunnelVacant::UNSEARCHED {
            // Growth invalidates any recorded slot or exhaustion; an unsearched
            // token never had one.
            let probe = FunnelPrf::new(self.probe_seed).prepare(vacant.hash);
            self.search_vacancy(probe)
        } else if vacant.exact == FunnelVacant::EXHAUSTED {
            // Both exhaustion reasons take the same recovery path.
            SearchResult::Full
        } else {
            SearchResult::Vacant(vacant.exact)
        };
        // Filter geometry may have changed during growth too.
        let membership = self.membership_slot(vacant.hash);
        self.place_absent_after_search(key, value, vacant.hash, membership, exact)
    }

    fn insert(&mut self, key: K, value: V, hash: u64) -> Option<V>
    where
        K: Hash + Eq,
    {
        // Same gate as a lookup: a key the filter never recorded is absent, so
        // the duplicate search and the exceptional full scan are skipped and
        // only the placement walk runs.
        let mut membership = self.membership_slot(hash);
        let gate = self.membership_gate_at(membership);
        let probe = FunnelPrf::new(self.probe_seed).prepare(hash);
        let fingerprint = control::control_fingerprint(hash);
        let mut exact = SearchResult::Full;
        let mut searched = false;
        if gate.passes() {
            exact = self.search_exact_prepared_for_insert(&key, probe, fingerprint);
            if let SearchResult::Hit(slot) = exact {
                return Some(self.replace_value(slot, value));
            }
            if self.exceptional_placement
                && let Some(slot) = self.find_by_full_scan(&key, fingerprint)
            {
                return Some(self.replace_value(slot, value));
            }
            searched = true;
        }
        if self.prepare_vacant_insert() {
            // Growth rebuilt the arena and its filter; both the search and the
            // filter slot from before it are stale.
            membership = self.membership_slot(hash);
            exact = self.search_vacancy(probe);
        } else if !searched {
            exact = self.search_vacancy(probe);
        }
        self.place_absent_after_search(key, value, hash, membership, exact);
        None
    }

    fn remove(&mut self, slot: usize) -> (K, V) {
        // SAFETY: a live location names an occupied in-bounds slot;
        // `extract_finish` tombstones it so it is never read again.
        let entry = unsafe { self.storage.take(slot) };
        self.extract_finish(slot);
        self.settle_after_deletes();
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
        self.len -= 1;
        self.tombstones += 1;
        self.stale_membership += 1;
        self.epoch.note_delete();
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
            mode: if self.len <= self.shape.n / 4 {
                FunnelScanMode::Sparse(OccupiedIndices::new())
            } else {
                FunnelScanMode::Dense(0)
            },
        }
    }

    #[inline]
    fn scan_next(&self, scan: &mut FunnelScan) -> Option<(*mut SlotEntry<K, V>, usize)> {
        match &mut scan.mode {
            FunnelScanMode::Dense(next) => {
                while *next < self.shape.n {
                    let slot = *next;
                    *next += 1;
                    // SAFETY: `slot < n`, the storage capacity.
                    unsafe {
                        if control::is_occupied(self.storage.control_at(slot)) {
                            return Some((self.storage.slot_ptr(slot), slot));
                        }
                    }
                }
                None
            }
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
        if self.len == 0 && min_capacity == 0 {
            if self.shape.n != 0 {
                self.resize_with_transition(0, EpochTransition::ExplicitResize);
            }
            return;
        }
        let requested = self.len.max(min_capacity);
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
                self.len -= 1;
                self.tombstones += 1;
                drop(entry);
            }
        }
        self.wipe_all();
    }

    fn wipe_all(&mut self) {
        self.storage.clear_all_controls();
        self.len = 0;
        self.tombstones = 0;
        self.finish_clear();
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
        cloned.len = self.len;
        cloned.tombstones = self.tombstones;
        cloned.epoch = self.epoch;
        cloned.exceptional_placement = self.exceptional_placement;
        cloned.probe_seed = self.probe_seed;
        // Slots are copied rather than reinserted, so the filter comes with them.
        cloned.copy_membership_from(self);
        cloned.stale_membership = self.stale_membership;
        cloned
    }
}

#[cfg(test)]
mod tests;
