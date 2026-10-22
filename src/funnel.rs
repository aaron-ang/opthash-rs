//! Paper-exact Funnel placement with explicit dynamic-map epoch extensions.
use core::hash::{BuildHasher, Hash};
use core::mem::{self, MaybeUninit};

use alloc::{boxed::Box, vec::Vec};
use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::ReserveFraction;
use crate::capacity;
use crate::epoch::{EpochSnapshot, EpochState, EpochTransition};
use crate::error::{TryBuildError, TryReserveError};
use crate::exact::geometry::PaperConfig;
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
use crate::raw::simd;
use crate::{macros, map};

const FUNNEL_PROBE_SEED: u64 = probe::WYHASH_DEFAULT_SECRET[3];

/// Pointerless scan progress through Funnel's flat storage.
#[derive(Clone)]
pub struct FunnelScan {
    mode: FunnelScanMode,
}

#[derive(Clone)]
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
        let scale = 1_u128 << d;
        let denominator = scale - 1;
        // Invert `n - floor(n / scale) >= requested` exactly. Using
        // `ceil(requested * scale / (scale - 1))` skips a valid `n` at many
        // floor boundaries and can change geometry for a request that the
        // preceding map already reports as its capacity.
        let requested_wide = requested as u128;
        let n_lower_bound = requested_wide
            .checked_add((requested_wide - 1) / denominator)
            .ok_or(TryReserveError::CapacityOverflow)?;
        let mut n = usize::try_from(n_lower_bound)
            .map_err(|_| TryReserveError::CapacityOverflow)?
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

struct FlatStorage<T> {
    ctrl_ptr: *mut u8,
    data_ptr: *mut MaybeUninit<T>,
    capacity: usize,
}

unsafe impl<T: Send> Send for FlatStorage<T> {}
unsafe impl<T: Sync> Sync for FlatStorage<T> {}

impl<T> ArenaSlots<T> for FlatStorage<T> {
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
        self.drop_values();
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
/// the slot: a lookup never records, and the extra field cost the miss path
/// four instructions per call.
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
    unsafe { shape.membership.clear::<MembershipWord>(arena.as_ptr()) };
    let storage = FlatStorage {
        ctrl_ptr: arena.as_ptr(),
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
    let group = unsafe { ctrl_ptr.add(start) };
    let mut events = unsafe { simd::free_mask_group(group) };
    events.0 |= unsafe { simd::eq_mask_group(group, fingerprint) }.0;
    for lane in events {
        if lane >= logical_lanes {
            break;
        }
        let slot = start + lane;
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
    let group = unsafe { ctrl_ptr.add(start) };
    let matches = unsafe { simd::eq_mask_group(group, fingerprint) };
    // Iterator search on purpose: `BitMask::first_below` is the same test, but
    // here LLVM lowers it to a select chain instead of one test-and-branch.
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
        return unsafe {
            scan_clean_funnel_group(ctrl_ptr, start, length, fingerprint, &mut inspect_match)
        };
    }
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
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
    /// Cached location of the membership filter tail. Lookups load one word
    /// from it before probing; see [`crate::membership`].
    membership: MembershipRegion,
    /// Deletes since the filter last matched the live set; see
    /// [`membership::refresh_deletes`].
    stale_membership: usize,
}

unsafe impl<K: Send, V: Send, S: Send, A: Allocator + Clone + Send> Send
    for FunnelTable<K, V, S, A>
{
}
unsafe impl<K: Sync, V: Sync, S: Sync, A: Allocator + Clone + Sync> Sync
    for FunnelTable<K, V, S, A>
{
}

impl<K, V, S, A: Allocator + Clone> Drop for FunnelTable<K, V, S, A> {
    fn drop(&mut self) {
        let storage = &mut self.storage;
        self.arena.drop_table(&self.alloc, || storage.drop_values());
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
        /// Iterator yielding values removed by set `extract_if`.
        FunnelSetExtractIf => ExtractIf,
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

    #[inline]
    fn inspect_slot<Q>(&self, slot: usize, key_fingerprint: u8, key: &Q) -> Option<bool>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let ctrl = self.storage.control_at(slot);
        if ctrl == CTRL_EMPTY {
            return Some(false);
        }
        if ctrl == key_fingerprint {
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
        let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(key_hash);
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
            if self.storage.control_at(slot) == CTRL_TOMBSTONE {
                first_tombstone.get_or_insert(slot);
                continue;
            }
            match self.inspect_slot(slot, key_fingerprint, key) {
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
                if self.storage.control_at(slot) == CTRL_TOMBSTONE {
                    first_tombstone.get_or_insert(slot);
                    continue;
                }
                match self.inspect_slot(slot, key_fingerprint, key) {
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
            if control::is_free(self.storage.control_at(slot)) {
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
                if control::is_free(self.storage.control_at(slot)) {
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
        (0..self.shape.n).find(|&slot| {
            self.storage.control_at(slot) == key_fingerprint
                && key.equivalent(&unsafe { self.storage.get_ref(slot) }.key)
        })
    }

    #[inline]
    fn membership_ptr(&self) -> *mut MembershipWord {
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
        unsafe { self.membership.clear::<MembershipWord>(self.arena.as_ptr()) };
        self.stale_membership = 0;
    }

    /// Re-record the filter from the live entries, dropping the bits departed
    /// keys left behind. Entries stay put; only the filter tail is rewritten.
    #[cold]
    #[inline(never)]
    fn refresh_membership(&mut self) {
        self.clear_membership();
        for slot in 0..self.shape.n {
            if !control::is_occupied(self.storage.control_at(slot)) {
                continue;
            }
            let hash = {
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
        let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(key_hash);
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
        Some(unsafe { self.storage.get_ref(slot) })
    }

    fn first_free_global(&self) -> Option<usize> {
        (0..self.shape.n).find(|&slot| control::is_free(self.storage.control_at(slot)))
    }

    fn place_new_entry(
        &mut self,
        slot: usize,
        key: K,
        value: V,
        membership: MembershipSlot,
        key_fingerprint: u8,
        exceptional: bool,
    ) -> usize {
        let was_tombstone = self.storage.control_at(slot) == CTRL_TOMBSTONE;
        self.storage
            .write_with_control(slot, SlotEntry { key, value }, key_fingerprint);
        self.record_membership(membership);
        self.len += 1;
        if was_tombstone {
            self.tombstones -= 1;
        }
        if exceptional {
            self.exceptional_placement = true;
        }
        slot
    }

    /// Rebuild insertion. The input comes from a table that held each key
    /// once, so the placement walk never needs to look for a duplicate.
    fn insert_unique(&mut self, key: K, value: V) -> bool {
        let key_hash = self.hash_builder.hash_one(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(key_hash);
        let (slot, exceptional) = match self.search_vacancy(probe) {
            SearchResult::Vacant(slot) => (slot, false),
            SearchResult::Full | SearchResult::RangeFailure => (
                self.first_free_global()
                    .expect("Funnel rebuild has enough logical capacity"),
                true,
            ),
            SearchResult::Hit(_) => unreachable!("vacancy walk never reports a hit"),
        };
        let membership = self.membership_slot(key_hash);
        self.place_new_entry(slot, key, value, membership, key_fingerprint, exceptional);
        exceptional
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

    fn place_absent_after_search(
        &mut self,
        key: K,
        value: V,
        membership: MembershipSlot,
        key_fingerprint: u8,
        exact: SearchResult,
    ) -> usize {
        let (slot, exceptional) = match exact {
            SearchResult::Vacant(slot) => {
                debug_assert!(
                    control::is_free(self.storage.control_at(slot)),
                    "stale Funnel vacancy at slot {slot}"
                );
                (slot, false)
            }
            SearchResult::Hit(_) => unreachable!("known-absent Funnel insertion found a key"),
            SearchResult::Full | SearchResult::RangeFailure => (
                self.first_free_global()
                    .expect("Funnel insertion limit reserves a free slot"),
                true,
            ),
        };
        let location =
            self.place_new_entry(slot, key, value, membership, key_fingerprint, exceptional);
        if exceptional {
            self.epoch
                .start_with_placement_recovery(EpochTransition::PlacementRecovery);
        }
        location
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
        let (new_arena, new_storage, new_membership) = try_allocate_storage(shape.n, &self.alloc)
            .unwrap_or_else(|_| {
                let shape = funnel_layout::<K, V>(shape.n).expect("constructed Funnel layout");
                allocator_api2::alloc::handle_alloc_error(shape.layout)
            });

        let old_arena = mem::replace(&mut self.arena, new_arena);
        let old_storage = mem::replace(&mut self.storage, new_storage);
        self.membership = new_membership;
        self.stale_membership = 0;
        self.shape = shape;
        self.len = 0;
        self.tombstones = 0;
        self.exceptional_placement = false;

        let mut guard = arena::ArenaDropGuard::new(old_arena, old_storage, self.alloc.clone());
        let mut recovered = false;
        guard.regions_mut().drain_values_and_clear(|entry| {
            recovered |= self.insert_unique(entry.key, entry.value);
        });
        drop(guard);
        if recovered {
            self.epoch.start_with_placement_recovery(transition);
        } else {
            self.epoch.start(transition);
        }
    }

    fn try_resize_exact(&mut self, slots: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        let prior_epoch = self.epoch;
        let shape = FunnelShape::from_slots(slots, self.reserve_fraction)?;
        let mut old_map = Self::try_from_shape(
            shape,
            self.reserve_fraction,
            self.hash_builder.clone(),
            self.alloc.clone(),
        )?;
        mem::swap(self, &mut old_map);
        let mut recovered = false;
        old_map.storage.drain_values_and_clear(|entry| {
            recovered |= self.insert_unique(entry.key, entry.value);
        });
        drop(old_map);
        self.epoch = prior_epoch;
        if recovered {
            self.epoch
                .start_with_placement_recovery(EpochTransition::ExplicitResize);
        } else {
            self.epoch.start(EpochTransition::ExplicitResize);
        }
        Ok(())
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
        unsafe { self.storage.get_ref(slot) }
    }

    #[inline]
    unsafe fn slot_ptr(&self, slot: usize) -> *mut SlotEntry<K, V> {
        self.storage.slot_ptr(slot)
    }

    #[inline]
    fn replace_value(&mut self, slot: usize, value: V) -> V {
        let entry = unsafe { self.storage.get_mut(slot) };
        mem::replace(&mut entry.value, value)
    }

    #[inline]
    fn find<Q>(&self, key: &Q, hash: u64, fingerprint: u8) -> Option<usize>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_location(key, hash, fingerprint)
    }

    #[inline]
    fn find_entry<'a, Q>(
        &'a self,
        key: &Q,
        hash: u64,
        fingerprint: u8,
    ) -> Option<&'a SlotEntry<K, V>>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_entry_ref(key, hash, fingerprint)
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
            let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(vacant.hash);
            self.search_vacancy(probe)
        } else if vacant.exact == FunnelVacant::EXHAUSTED {
            // Both exhaustion reasons use the same exceptional placement.
            SearchResult::Full
        } else {
            SearchResult::Vacant(vacant.exact)
        };
        // Filter geometry may have changed during growth too.
        let membership = self.membership_slot(vacant.hash);
        let fingerprint = control::control_fingerprint(vacant.hash);
        self.place_absent_after_search(key, value, membership, fingerprint, exact)
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
        let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(hash);
        let fingerprint = control::control_fingerprint(hash);
        let mut exact = SearchResult::Full;
        let mut searched = false;
        if gate.passes() {
            exact = self.search_exact_prepared_for_insert(&key, probe, fingerprint);
            if let SearchResult::Hit(slot) = exact {
                let entry = unsafe { self.storage.get_mut(slot) };
                return Some(mem::replace(&mut entry.value, value));
            }
            if self.exceptional_placement
                && let Some(slot) = self.find_by_full_scan(&key, fingerprint)
            {
                let entry = unsafe { self.storage.get_mut(slot) };
                return Some(mem::replace(&mut entry.value, value));
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
        self.place_absent_after_search(key, value, membership, fingerprint, exact);
        None
    }

    fn remove(&mut self, slot: usize) -> (K, V) {
        let entry = unsafe { self.storage.take(slot) };
        self.extract_finish(slot);
        self.settle_after_deletes();
        (entry.key, entry.value)
    }

    #[inline]
    fn tombstone_slot(&mut self, slot: usize) {
        self.storage.mark_tombstone(slot);
    }

    #[inline]
    fn extract_finish(&mut self, slot: usize) {
        self.storage.mark_tombstone(slot);
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
                    if control::is_occupied(self.storage.control_at(slot)) {
                        return Some((self.storage.slot_ptr(slot), slot));
                    }
                }
                None
            }
            FunnelScanMode::Sparse(cursor) => {
                let slot = cursor.step(&self.storage)?;
                Some((self.storage.slot_ptr(slot), slot))
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
            .unwrap_or_else(|error| panic!("invalid Funnel construction: {error}"))
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

    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        self.try_resize_exact(new_capacity)
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

    fn clear(&mut self) {
        for slot in 0..self.shape.n {
            if self.storage.control_at(slot) == CTRL_TOMBSTONE {
                self.storage.set_control(slot, CTRL_EMPTY);
            }
        }
        self.tombstones = 0;
        let len = &mut self.len;
        self.storage.clear_occupied_slots_with(|slot| {
            *len -= 1;
            unsafe { core::ptr::drop_in_place(slot) };
        });
        debug_assert_eq!(self.len, 0);
        self.exceptional_placement = false;
        self.clear_membership();
        self.epoch.start(EpochTransition::Clear);
    }

    fn wipe_all(&mut self) {
        self.storage.clear_all_controls();
        self.len = 0;
        self.tombstones = 0;
        self.exceptional_placement = false;
        self.clear_membership();
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
        cloned.len = self.len;
        cloned.tombstones = self.tombstones;
        cloned.epoch = self.epoch;
        cloned.exceptional_placement = self.exceptional_placement;
        // Slots are copied rather than reinserted, so the filter comes with them.
        cloned.copy_membership_from(self);
        cloned.stale_membership = self.stale_membership;
        cloned
    }
}

#[cfg(test)]
mod tests;
