//! Paper-exact Funnel placement with explicit dynamic-map epoch extensions.
#![allow(clippy::similar_names)]

use core::hash::{BuildHasher, Hash};
use core::mem::{self, MaybeUninit};

use alloc::{boxed::Box, vec::Vec};
use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::ReserveFraction;
use crate::common::DefaultHashBuilder;
use crate::common::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::common::config::GROUP_SIZE;
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use crate::common::error::{TryBuildError, TryReserveError};
use crate::common::exact::{
    FunnelPrf, PaperConfig, PreparedFastFunnelDomainProbe, PreparedProbeRange, ProbeDomain,
    unbiased_prepared_funnel_probe_index_in_range,
};
use crate::common::math::capacity;
use crate::common::simd;
use crate::epoch::{EpochSnapshot, EpochState, EpochTransition};
use crate::{macros, map};

const FUNNEL_PROBE_SEED: u64 = 0x8A5C_7D31_6E29_B4F0;
const RANGE_WORD_CAP: u32 = 8;

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

    fn from_slots(n: usize, reserve: ReserveFraction) -> Result<Self, TryReserveError> {
        if n == 0 {
            return Ok(Self::empty());
        }
        let config = PaperConfig::new(n, reserve.delta_log2())
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
        Ok(Self {
            n,
            max_insertions: config.target_insertions(),
            levels: levels.into_boxed_slice(),
            beta: plan.beta(),
            loglog_ceiling: plan.loglog_ceiling(),
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
        let d = reserve.delta_log2();
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

fn try_allocate_storage<K, V, A: Allocator>(
    n: usize,
    alloc: &A,
) -> Result<(Arena, FlatStorage<SlotEntry<K, V>>), TryReserveError> {
    let (layout, data_offset, control_bytes) = funnel_layout::<K, V>(n)?;
    let arena = Arena::try_allocate_with_ctrl_zeroed(layout, control_bytes, alloc)?;
    let storage = FlatStorage {
        ctrl_ptr: arena.as_ptr(),
        data_ptr: unsafe {
            arena
                .as_ptr()
                .add(data_offset)
                .cast::<MaybeUninit<SlotEntry<K, V>>>()
        },
        capacity: n,
    };
    Ok((arena, storage))
}

fn funnel_layout<K, V>(n: usize) -> Result<(Layout, usize, usize), TryReserveError> {
    let control_bytes = if n == 0 {
        0
    } else {
        n.checked_add(GROUP_SIZE - 1)
            .ok_or(TryReserveError::CapacityOverflow)?
    };
    let (layout, data_offset) = arena::layout_for_extents::<K, V>(control_bytes, n)?;
    Ok((layout, data_offset, control_bytes))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SearchResult {
    Hit(usize),
    Vacant(usize),
    Full,
    RangeFailure,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BucketScanResult<T> {
    Hit(T),
    Empty(usize),
    Full,
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
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
        let group = unsafe { ctrl_ptr.add(position) };
        let mut events = unsafe { simd::free_mask_group(group) };
        events.0 |= unsafe { simd::eq_mask_group(group, fingerprint) }.0;
        for lane in events {
            if lane >= logical_lanes {
                break;
            }
            let slot = position + lane;
            let control = unsafe { *ctrl_ptr.add(slot) };
            if control == CTRL_TOMBSTONE {
                first_tombstone.get_or_insert(slot);
            } else if control == CTRL_EMPTY {
                return BucketScanResult::Empty(first_tombstone.unwrap_or(slot));
            } else if let Some(hit) = inspect_match(slot) {
                return BucketScanResult::Hit(hit);
            }
        }
        position += logical_lanes;
    }
    BucketScanResult::Full
}

/// Clean-epoch specialization: without tombstones, the first free lane is the
/// paper's terminating EMPTY lane.
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
    let end = start + length;
    let mut position = start;
    while position < end {
        let logical_lanes = GROUP_SIZE.min(end - position);
        let group = unsafe { ctrl_ptr.add(position) };
        let matches = unsafe { simd::eq_mask_group(group, fingerprint) };
        let first_empty = unsafe { simd::free_mask_group(group) }
            .into_iter()
            .find(|&lane| lane < logical_lanes);
        let semantic_lanes = first_empty.unwrap_or(logical_lanes);

        for lane in matches {
            if lane >= semantic_lanes {
                break;
            }
            let slot = position + lane;
            if let Some(hit) = inspect_match(slot) {
                return BucketScanResult::Hit(hit);
            }
        }
        if let Some(empty_lane) = first_empty {
            return BucketScanResult::Empty(position + empty_lane);
        }
        position += logical_lanes;
    }
    BucketScanResult::Full
}

/// Paper-exact Funnel hashing with dynamic allocation epochs for the ordinary
/// map API. Deletion, growth, and exceptional collision recovery are explicit
/// library API extensions around each fixed-size insertion epoch.
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
        "Open-addressed hash map using funnel hashing." FunnelHashMap => HashMap,
        "Consuming iterator over owned `(K, V)`." FunnelIntoIter => IntoIter,
        "Owned `K` iterator." FunnelIntoKeys => IntoKeys,
        "Owned `V` iterator." FunnelIntoValues => IntoValues,
    },
    map_ref {
        "A view into a single entry, occupied or vacant." FunnelEntry => Entry,
        "View of an occupied entry." FunnelOccupiedEntry => OccupiedEntry,
        "View of a vacant entry." FunnelVacantEntry => VacantEntry,
        "Error returned by `try_insert` on key collision." FunnelOccupiedError => OccupiedError,
        "Borrowing iterator over `(&K, &V)`." FunnelIter => Iter,
        "Borrowing iterator over `(&K, &mut V)`." FunnelIterMut => IterMut,
        "`&K` iterator." FunnelKeys => Keys,
        "`&V` iterator." FunnelValues => Values,
        "`&mut V` iterator." FunnelValuesMut => ValuesMut,
        "Draining iterator that empties the map." FunnelDrain => Drain,
    },
    map_extract_if {
        "Iterator yielding entries removed by `extract_if`." FunnelExtractIf
    },
    set_no_lifetime {
        "Hash set using funnel hashing." FunnelHashSet => HashSet,
        "Consuming iterator over set values." FunnelSetIntoIter => IntoIter,
    },
    set_ref {
        "Borrowing iterator over set values." FunnelSetIter => Iter,
        "Draining iterator that empties the set." FunnelSetDrain => Drain,
        "Iterator yielding values removed by set `extract_if`." FunnelSetExtractIf => ExtractIf,
        "Iterator over values present only in the first set." FunnelDifference => Difference,
        "Iterator over values present in both sets." FunnelIntersection => Intersection,
        "Iterator over values present in exactly one set." FunnelSymmetricDifference => SymmetricDifference,
        "Iterator over values present in either set." FunnelUnion => Union,
        "A view into a single set entry." FunnelSetEntry => Entry,
        "View of an occupied set entry." FunnelSetOccupiedEntry => OccupiedEntry,
        "View of a vacant set entry." FunnelSetVacantEntry => VacantEntry,
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
        let (arena, storage) = try_allocate_storage(shape.n, &alloc)?;
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
        })
    }

    fn try_with_insert_budget(
        capacity: usize,
        reserve_fraction: ReserveFraction,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryBuildError> {
        if reserve_fraction.delta_log2() < 3 {
            return Err(TryBuildError::FunnelDeltaLog2BelowMinimum {
                delta_log2: reserve_fraction.delta_log2(),
                minimum: 3,
            });
        }
        let shape = FunnelShape::for_insert_budget(capacity, reserve_fraction)?;
        Self::try_from_shape(shape, reserve_fraction, hash_builder, alloc).map_err(Into::into)
    }

    #[inline]
    fn sample(
        probe: &PreparedFastFunnelDomainProbe,
        logical_probe: u64,
        range: PreparedProbeRange,
    ) -> Option<usize> {
        unbiased_prepared_funnel_probe_index_in_range(probe, logical_probe, range, RANGE_WORD_CAP)
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

    fn search_exact<Q>(&self, key: &Q, key_hash: u64, key_fingerprint: u8) -> SearchResult
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.search_exact_with_clean_scan(key, key_hash, key_fingerprint, false)
    }

    fn search_exact_for_insert<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> SearchResult
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.search_exact_with_clean_scan(key, key_hash, key_fingerprint, self.tombstones == 0)
    }

    fn search_exact_with_clean_scan<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
        clean_epoch: bool,
    ) -> SearchResult
    where
        Q: Equivalent<K> + ?Sized,
    {
        if self.shape.n == 0 {
            return SearchResult::Full;
        }
        let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(key_hash);
        let mut first_tombstone = None;

        for level in &self.shape.levels {
            let level_probe = probe.prepare_counter_base(level.ordinary_counter_base);
            let Some(bucket) = Self::sample(&level_probe, 0, level.bucket_range) else {
                return SearchResult::RangeFailure;
            };
            let start = level.offset + bucket * self.shape.beta;
            let scan = if clean_epoch {
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

        let primary_probe = probe
            .prepare_domain(ProbeDomain::FunnelSpecialPrimary)
            .expect("fixed Funnel primary domain must fit its counter encoding");
        for logical_probe in 0..self.shape.loglog_ceiling {
            let Some(local) = Self::sample(
                &primary_probe,
                logical_probe as u64,
                self.shape.primary_range,
            ) else {
                return SearchResult::RangeFailure;
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

        let fallback_a_probe = probe
            .prepare_domain(ProbeDomain::FunnelSpecialFallbackChoiceA)
            .expect("fixed Funnel fallback-A domain must fit its counter encoding");
        let Some(bucket_a) = Self::sample(&fallback_a_probe, 0, self.shape.fallback_bucket_range)
        else {
            return SearchResult::RangeFailure;
        };
        let fallback_b_probe = probe
            .prepare_domain(ProbeDomain::FunnelSpecialFallbackChoiceB)
            .expect("fixed Funnel fallback-B domain must fit its counter encoding");
        let Some(bucket_b) = Self::sample(&fallback_b_probe, 0, self.shape.fallback_bucket_range)
        else {
            return SearchResult::RangeFailure;
        };
        for slot_in_bucket in 0..self.shape.fallback_bucket_width {
            for bucket in [bucket_a, bucket_b] {
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

    fn find_by_full_scan<Q>(&self, key: &Q, key_fingerprint: u8) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        (0..self.shape.n).find(|&slot| {
            self.storage.control_at(slot) == key_fingerprint
                && key.equivalent(&unsafe { self.storage.get_ref(slot) }.key)
        })
    }

    fn find_location<Q>(&self, key: &Q, key_hash: u64, key_fingerprint: u8) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        match self.search_exact(key, key_hash, key_fingerprint) {
            SearchResult::Hit(slot) => Some(slot),
            _ if self.exceptional_placement => self.find_by_full_scan(key, key_fingerprint),
            _ => None,
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
        (0..self.shape.n).find(|&slot| self.storage.control_at(slot).is_free())
    }

    fn place_new_entry(
        &mut self,
        slot: usize,
        key: K,
        value: V,
        key_fingerprint: u8,
        exceptional: bool,
    ) -> usize {
        let was_tombstone = self.storage.control_at(slot) == CTRL_TOMBSTONE;
        self.storage
            .write_with_control(slot, SlotEntry { key, value }, key_fingerprint);
        self.len += 1;
        if was_tombstone {
            self.tombstones -= 1;
        }
        if exceptional {
            self.exceptional_placement = true;
        }
        slot
    }

    fn insert_unique(&mut self, key: K, value: V) -> bool {
        let key_hash = self.hash_builder.hash_one(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let exact = self.search_exact_for_insert(&key, key_hash, key_fingerprint);
        let (slot, exceptional) = match exact {
            SearchResult::Vacant(slot) => (slot, false),
            SearchResult::Full | SearchResult::RangeFailure => (
                self.first_free_global()
                    .expect("Funnel rebuild has enough logical capacity"),
                true,
            ),
            SearchResult::Hit(_) => unreachable!("rebuild input contains duplicate keys"),
        };
        self.place_new_entry(slot, key, value, key_fingerprint, exceptional);
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

    fn prepare_vacant_insert(&mut self) -> bool {
        if self.len >= self.shape.max_insertions {
            let slots = self
                .next_growth_slots(self.len.saturating_add(1))
                .expect("capacity overflow");
            self.resize_with_transition(slots, EpochTransition::Growth);
            true
        } else {
            false
        }
    }

    fn place_absent_after_search(
        &mut self,
        key: K,
        value: V,
        key_fingerprint: u8,
        exact: SearchResult,
    ) -> usize {
        let (slot, exceptional) = match exact {
            SearchResult::Vacant(slot) => (slot, false),
            SearchResult::Hit(_) => unreachable!("known-absent Funnel insertion found a key"),
            SearchResult::Full | SearchResult::RangeFailure => (
                self.first_free_global()
                    .expect("Funnel insertion limit reserves a free slot"),
                true,
            ),
        };
        let location = self.place_new_entry(slot, key, value, key_fingerprint, exceptional);
        if exceptional {
            self.epoch.start_placement_recovery(self.len);
        }
        location
    }

    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> usize {
        self.prepare_vacant_insert();
        let key_fingerprint = control::control_fingerprint(key_hash);
        let exact = self.search_exact_for_insert(&key, key_hash, key_fingerprint);
        self.place_absent_after_search(key, value, key_fingerprint, exact)
    }

    fn resize_with_transition(&mut self, slots: usize, transition: EpochTransition) {
        let shape = FunnelShape::from_slots(slots, self.reserve_fraction)
            .expect("compatible Funnel resize geometry");
        let (new_arena, new_storage) =
            try_allocate_storage(shape.n, &self.alloc).unwrap_or_else(|_| {
                let (layout, _, _) =
                    funnel_layout::<K, V>(shape.n).expect("constructed Funnel layout");
                allocator_api2::alloc::handle_alloc_error(layout)
            });

        let old_arena = mem::replace(&mut self.arena, new_arena);
        let old_storage = mem::replace(&mut self.storage, new_storage);
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
            self.epoch
                .start_with_placement_recovery(transition, self.len);
        } else {
            self.epoch.start(transition, self.len);
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
                .start_with_placement_recovery(EpochTransition::ExplicitResize, self.len);
        } else {
            self.epoch.start(EpochTransition::ExplicitResize, self.len);
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
    type Hasher = S;
    type Alloc = A;
    type Scan = usize;

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
    fn insert_for_vacant(&mut self, key: K, value: V, hash: u64) -> usize {
        self.insert_for_vacant_entry(key, value, hash)
    }

    fn insert(&mut self, key: K, value: V, hash: u64) -> Option<V>
    where
        K: Hash + Eq,
    {
        let fingerprint = control::control_fingerprint(hash);
        let mut exact = self.search_exact_for_insert(&key, hash, fingerprint);
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
        if self.prepare_vacant_insert() {
            exact = self.search_exact_for_insert(&key, hash, fingerprint);
        }
        self.place_absent_after_search(key, value, fingerprint, exact);
        None
    }

    fn remove(&mut self, slot: usize) -> (K, V) {
        let entry = unsafe { self.storage.take(slot) };
        self.storage.mark_tombstone(slot);
        self.len -= 1;
        self.tombstones += 1;
        self.epoch.note_delete();
        if self.tombstones > capacity::tombstone_cleanup_threshold(self.shape.n) {
            self.resize_with_transition(self.shape.n, EpochTransition::TombstoneCleanup);
        }
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
        self.epoch.note_delete();
    }

    fn finish_deferred_removals(&mut self) {
        if self.tombstones > capacity::tombstone_cleanup_threshold(self.shape.n) {
            self.resize_with_transition(self.shape.n, EpochTransition::TombstoneCleanup);
        }
    }

    #[inline]
    fn scan(&self) -> usize {
        0
    }

    fn scan_next(&self, scan: &mut usize) -> Option<(*mut SlotEntry<K, V>, usize)> {
        while *scan < self.shape.n {
            let slot = *scan;
            *scan += 1;
            if self.storage.control_at(slot).is_occupied() {
                return Some((self.storage.slot_ptr(slot), slot));
            }
        }
        None
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
        self.epoch.start(EpochTransition::Clear, 0);
    }

    fn wipe_all(&mut self) {
        self.storage.clear_all_controls();
        self.len = 0;
        self.tombstones = 0;
        self.exceptional_placement = false;
        self.epoch.start(EpochTransition::Clear, 0);
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
        for slot in 0..self.shape.n {
            let ctrl = self.storage.control_at(slot);
            if ctrl.is_occupied() {
                let entry = unsafe { self.storage.get_ref(slot) }.clone();
                cloned.storage.write_with_control(slot, entry, ctrl);
            } else if ctrl == CTRL_TOMBSTONE {
                cloned.storage.mark_tombstone(slot);
            }
        }
        cloned.len = self.len;
        cloned.tombstones = self.tombstones;
        cloned.epoch = self.epoch;
        cloned.exceptional_placement = self.exceptional_placement;
        cloned
    }
}

#[cfg(test)]
mod tests {
    use core::hash::{BuildHasher, Hasher};
    use core::mem::ManuallyDrop;
    use core::num::NonZeroU32;
    use core::ptr::NonNull;
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use alloc::sync::Arc;
    use allocator_api2::alloc::AllocError as RawAllocError;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;
    use crate::common::exact::reference::{ScalarFunnel, ScalarFunnelInsert};
    use crate::common::exact::unbiased_probe_index;

    #[derive(Clone, Copy, Default)]
    struct IdentityBuildHasher;

    struct IdentityHasher(u64);

    struct PanicOnFirstDrop {
        drops: &'static AtomicUsize,
    }

    struct PanicHashKey {
        id: u64,
        armed: &'static AtomicBool,
        drops: &'static AtomicUsize,
    }

    #[derive(Clone)]
    struct ToggleAllocator {
        fail: Arc<AtomicBool>,
        allocations: Arc<AtomicUsize>,
        deallocations: Arc<AtomicUsize>,
    }

    unsafe impl Allocator for ToggleAllocator {
        fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, RawAllocError> {
            if self.fail.load(Ordering::SeqCst) {
                Err(RawAllocError)
            } else {
                let allocation = Global.allocate(layout)?;
                self.allocations.fetch_add(1, Ordering::SeqCst);
                Ok(allocation)
            }
        }

        unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
            self.deallocations.fetch_add(1, Ordering::SeqCst);
            unsafe { Global.deallocate(ptr, layout) };
        }
    }

    impl PartialEq for PanicHashKey {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }

    impl Eq for PanicHashKey {}

    impl Hash for PanicHashKey {
        fn hash<H: Hasher>(&self, state: &mut H) {
            assert!(!self.armed.load(Ordering::SeqCst), "armed key hash");
            state.write_u64(self.id);
        }
    }

    impl Drop for PanicHashKey {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Drop for PanicOnFirstDrop {
        fn drop(&mut self) {
            assert!(
                self.drops.fetch_add(1, Ordering::SeqCst) != 0,
                "first value drop"
            );
        }
    }

    impl Hasher for IdentityHasher {
        fn finish(&self) -> u64 {
            self.0
        }

        fn write(&mut self, bytes: &[u8]) {
            let mut value = 0_u64;
            for (index, byte) in bytes.iter().take(8).enumerate() {
                value |= u64::from(*byte) << (index * 8);
            }
            self.0 = value;
        }

        fn write_u64(&mut self, value: u64) {
            self.0 = value;
        }
    }

    impl BuildHasher for IdentityBuildHasher {
        type Hasher = IdentityHasher;

        fn build_hasher(&self) -> Self::Hasher {
            IdentityHasher(0)
        }
    }

    fn raw_table(n: usize, d: u32) -> FunnelTable<u64, u64, IdentityBuildHasher> {
        let reserve = ReserveFraction::from_delta_log2(d).unwrap();
        FunnelTable::try_from_shape(
            FunnelShape::from_slots(n, reserve).unwrap(),
            reserve,
            IdentityBuildHasher,
            Global,
        )
        .unwrap()
    }

    #[test]
    fn selector_finds_known_minimum_exact_geometries() {
        for &(d, expected) in &[
            (3, 144),
            (4, 344),
            (6, 1_372),
            (8, 5_472),
            (9, 10_924),
            (10, 21_856),
        ] {
            let reserve = ReserveFraction::from_delta_log2(d).unwrap();
            let shape = FunnelShape::for_insert_budget(1, reserve).unwrap();
            assert_eq!(shape.n, expected, "d={d}");
            assert!(PaperConfig::new(shape.n, d).unwrap().funnel_plan().is_ok());
        }
    }

    #[test]
    fn selector_reuses_a_geometry_at_its_reported_capacity() {
        let reserve = ReserveFraction::from_delta_log2(3).unwrap();
        for requested in 1..512 {
            let selected = FunnelShape::for_insert_budget(requested, reserve).unwrap();
            let at_capacity =
                FunnelShape::for_insert_budget(selected.max_insertions, reserve).unwrap();
            assert_eq!(at_capacity.n, selected.n, "request={requested}");
            assert_eq!(at_capacity.max_insertions, selected.max_insertions);
        }
        let headline = FunnelShape::for_insert_budget(28_672, reserve).unwrap();
        assert_eq!(headline.n, 32_767);
        assert_eq!(headline.max_insertions, 28_672);
    }

    #[test]
    fn funnel_locations_match_the_independent_scalar_oracle() {
        for &(n, d) in &[(144, 3), (344, 4), (1_372, 6), (5_472, 8), (21_856, 10)] {
            let config = PaperConfig::new(n, d).unwrap();
            let mut scalar = ScalarFunnel::new(
                config,
                FunnelPrf::new(FUNNEL_PROBE_SEED),
                NonZeroU32::new(RANGE_WORD_CAP).unwrap(),
            );
            let mut table = raw_table(n, d);
            let mut locations = Vec::with_capacity(config.target_insertions());
            for identity in 0..config.target_insertions() as u64 {
                let (result, _) = scalar.insert(identity).unwrap();
                let ScalarFunnelInsert::Inserted(expected) = result else {
                    panic!("scalar insertion failed at {identity}");
                };
                assert_eq!(
                    <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(
                        &mut table,
                        identity,
                        identity ^ 0x55,
                        identity,
                    ),
                    None
                );
                let actual = table
                    .find_location(&identity, identity, control::control_fingerprint(identity))
                    .unwrap();
                assert_eq!(actual, expected.global_slot(), "n={n} key={identity}");
                locations.push((identity, actual, table.storage.slot_ptr(actual) as usize));
                assert_eq!(
                    table.find_location(
                        &identity,
                        identity,
                        control::control_fingerprint(identity),
                    ),
                    Some(actual)
                );
            }
            assert_eq!(table.len, scalar.len());
            for &(identity, location, pointer) in &locations {
                assert_eq!(
                    table.find_location(
                        &identity,
                        identity,
                        control::control_fingerprint(identity),
                    ),
                    Some(location),
                    "moved n={n} key={identity}"
                );
                assert_eq!(table.storage.slot_ptr(location) as usize, pointer);
            }

            let duplicate = config.target_insertions() as u64 / 2;
            let len = table.len;
            assert_eq!(
                <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(
                    &mut table,
                    duplicate,
                    u64::MAX,
                    duplicate,
                ),
                Some(duplicate ^ 0x55)
            );
            assert_eq!(table.len, len);
            assert_eq!(
                table.find_location(
                    &duplicate,
                    duplicate,
                    control::control_fingerprint(duplicate),
                ),
                Some(locations[duplicate as usize].1)
            );

            let absent = config.target_insertions() as u64 + 1_000_000;
            assert_eq!(
                table.find_location(&absent, absent, control::control_fingerprint(absent)),
                None
            );
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn funnel_search_reaches_primary_and_alternating_fallback_in_order() {
        fn sample(identity: u64, domain: ProbeDomain, logical: u64, upper: usize) -> usize {
            unbiased_probe_index(
                &FunnelPrf::new(FUNNEL_PROBE_SEED),
                identity,
                domain,
                logical,
                upper,
                RANGE_WORD_CAP,
            )
            .unwrap()
            .index
        }

        fn occupy(
            table: &mut FunnelTable<u64, u64, IdentityBuildHasher>,
            slot: usize,
            key: u64,
            fingerprint: u8,
        ) {
            if table.storage.control_at(slot).is_free() {
                table
                    .storage
                    .write_with_control(slot, SlotEntry { key, value: key }, fingerprint);
                table.len += 1;
            }
        }

        let mut table = raw_table(32_768, 3);
        let fallback_count = table.shape.fallback_bucket_range.upper();
        let identity = (0..10_000_u64)
            .find(|&identity| {
                sample(
                    identity,
                    ProbeDomain::FunnelSpecialFallbackChoiceA,
                    0,
                    fallback_count,
                ) != sample(
                    identity,
                    ProbeDomain::FunnelSpecialFallbackChoiceB,
                    0,
                    fallback_count,
                )
            })
            .unwrap();
        let fingerprint = control::control_fingerprint(identity);
        let dummy_fingerprint = if fingerprint == 1 { 2 } else { 1 };

        for level_index in 0..table.shape.levels.len() {
            let level = table.shape.levels[level_index];
            let bucket = sample(
                identity,
                ProbeDomain::FunnelOrdinary {
                    level: level_index as u64,
                },
                0,
                level.bucket_range.upper(),
            );
            let start = level.offset + bucket * table.shape.beta;
            for lane in 0..table.shape.beta {
                occupy(
                    &mut table,
                    start + lane,
                    u64::MAX - (start + lane) as u64,
                    dummy_fingerprint,
                );
            }
        }

        let first_primary = sample(
            identity,
            ProbeDomain::FunnelSpecialPrimary,
            0,
            table.shape.primary_range.upper(),
        );
        assert_eq!(
            table.search_exact_for_insert(&identity, identity, fingerprint),
            SearchResult::Vacant(table.shape.primary_offset + first_primary)
        );
        for logical in 0..table.shape.loglog_ceiling {
            let local = sample(
                identity,
                ProbeDomain::FunnelSpecialPrimary,
                logical as u64,
                table.shape.primary_range.upper(),
            );
            let slot = table.shape.primary_offset + local;
            occupy(&mut table, slot, u64::MAX - local as u64, dummy_fingerprint);
        }

        let bucket_a = sample(
            identity,
            ProbeDomain::FunnelSpecialFallbackChoiceA,
            0,
            fallback_count,
        );
        let bucket_b = sample(
            identity,
            ProbeDomain::FunnelSpecialFallbackChoiceB,
            0,
            fallback_count,
        );
        assert_ne!(bucket_a, bucket_b);
        let width = table.shape.fallback_bucket_width;
        let slot_a0 = table.shape.fallback_offset + bucket_a * width;
        let slot_b0 = table.shape.fallback_offset + bucket_b * width;
        assert_eq!(
            table.search_exact_for_insert(&identity, identity, fingerprint),
            SearchResult::Vacant(slot_a0)
        );

        occupy(&mut table, slot_a0, u64::MAX - 1, dummy_fingerprint);
        occupy(&mut table, slot_b0, u64::MAX - 2, dummy_fingerprint);
        let slot_a1 = slot_a0 + 1;
        let slot_b1 = slot_b0 + 1;
        assert_eq!(
            table.search_exact_for_insert(&identity, identity, fingerprint),
            SearchResult::Vacant(slot_a1)
        );
        occupy(&mut table, slot_a1, u64::MAX - 3, dummy_fingerprint);
        assert_eq!(
            table.search_exact_for_insert(&identity, identity, fingerprint),
            SearchResult::Vacant(slot_b1)
        );

        occupy(&mut table, slot_b1, identity, fingerprint);
        let direct = core::ptr::from_ref(
            table
                .find_entry_ref(&identity, identity, fingerprint)
                .unwrap(),
        );
        assert_eq!(direct, table.storage.slot_ptr(slot_b1).cast_const());
    }

    #[test]
    fn exact_geometry_sums_to_n() {
        let mut table = raw_table(512, 3);
        for key in 0..128_u64 {
            table.insert_for_vacant_entry(key, key, key);
        }
        let ordinary_slots = table
            .shape
            .levels
            .iter()
            .map(|level| level.bucket_range.upper() * table.shape.beta)
            .sum::<usize>();
        assert_eq!(
            ordinary_slots
                + table.shape.primary_range.upper()
                + table.shape.fallback_bucket_range.upper() * table.shape.fallback_bucket_width,
            table.shape.n
        );
        assert_eq!(table.storage.capacity(), table.shape.n);
    }

    #[test]
    fn tombstones_never_hide_survivors_and_are_reused() {
        let mut table = raw_table(512, 3);
        for key in 0..200_u64 {
            table.insert_for_vacant_entry(key, key, key);
        }
        let removed = table
            .find_location(&7, 7, control::control_fingerprint(7))
            .unwrap();
        let (key, value) =
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::remove(&mut table, removed);
        assert_eq!((key, value), (7, 7));
        for key in 0..200_u64 {
            if key != 7 {
                assert!(
                    table
                        .find_location(&key, key, control::control_fingerprint(key))
                        .is_some(),
                    "lost key {key}"
                );
            }
        }
        let tombstones = table.tombstones;
        let replacement = table.insert_for_vacant_entry(10_000, 1, 7);
        assert_eq!(replacement, removed);
        assert_eq!(table.tombstones, tombstones - 1);
        assert_eq!(table.len, 200);
    }

    #[test]
    fn tombstone_before_a_duplicate_does_not_hide_the_duplicate() {
        let mut table = raw_table(144, 3);
        let first = table.insert_for_vacant_entry(100, 1, 42);
        let second = table.insert_for_vacant_entry(200, 2, 42);
        assert_ne!(first, second);
        let _ = <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::remove(&mut table, first);

        assert_eq!(
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(&mut table, 200, 20, 42,),
            Some(2)
        );
        assert_eq!(table.len, 1);
        assert_eq!(table.tombstones, 1);
        assert_eq!(
            table.find_location(&200, 42, control::control_fingerprint(42)),
            Some(second)
        );

        let reused = table.insert_for_vacant_entry(300, 3, 42);
        assert_eq!(reused, first);
        assert_eq!(table.tombstones, 0);
    }

    #[test]
    fn clear_marks_each_slot_empty_before_dropping_its_value() {
        let drops = Box::leak(Box::new(AtomicUsize::new(0)));
        let reserve = ReserveFraction::from_delta_log2(3).unwrap();
        let shape = FunnelShape::from_slots(144, reserve).unwrap();
        let mut table = ManuallyDrop::new(
            FunnelTable::<u64, PanicOnFirstDrop, IdentityBuildHasher>::try_from_shape(
                shape,
                reserve,
                IdentityBuildHasher,
                Global,
            )
            .unwrap(),
        );
        for key in 0..3 {
            table.insert_for_vacant_entry(key, PanicOnFirstDrop { drops }, key);
        }
        let first_occupied = (0..table.shape.n)
            .find(|&slot| table.storage.control_at(slot).is_occupied())
            .unwrap();

        let result = catch_unwind(AssertUnwindSafe(|| {
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::clear(&mut table);
        }));
        assert!(result.is_err());
        assert_eq!(table.storage.control_at(first_occupied), CTRL_EMPTY);
        assert_eq!(
            table.len,
            (0..table.shape.n)
                .filter(|&slot| table.storage.control_at(slot).is_occupied())
                .count()
        );

        <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::clear(&mut table);
        assert_eq!(table.len, 0);
        assert_eq!(drops.load(Ordering::SeqCst), 3);
        unsafe { ManuallyDrop::drop(&mut table) };
    }

    #[test]
    fn failed_fallible_resize_leaves_a_valid_table() {
        let armed = Box::leak(Box::new(AtomicBool::new(false)));
        let drops = Box::leak(Box::new(AtomicUsize::new(0)));
        let reserve = ReserveFraction::from_delta_log2(3).unwrap();
        let shape = FunnelShape::from_slots(144, reserve).unwrap();
        let mut table = FunnelTable::<PanicHashKey, u64, IdentityBuildHasher>::try_from_shape(
            shape,
            reserve,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
        for id in 0..3 {
            let key = PanicHashKey { id, armed, drops };
            let hash = id;
            assert_eq!(
                <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(
                    &mut table, key, id, hash,
                ),
                None
            );
        }
        let next_shape = FunnelShape::for_insert_budget(256, reserve).unwrap();

        armed.store(true, Ordering::SeqCst);
        let result = catch_unwind(AssertUnwindSafe(|| {
            table.try_resize_exact(next_shape.n).unwrap();
        }));
        assert!(result.is_err());
        assert_eq!(
            table.len,
            (0..table.shape.n)
                .filter(|&slot| table.storage.control_at(slot).is_occupied())
                .count()
        );

        armed.store(false, Ordering::SeqCst);
        let replacement = PanicHashKey {
            id: 99,
            armed,
            drops,
        };
        assert_eq!(
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(
                &mut table,
                replacement,
                99,
                99,
            ),
            None
        );
        assert_eq!(
            table.len,
            (0..table.shape.n)
                .filter(|&slot| table.storage.control_at(slot).is_occupied())
                .count()
        );
        drop(table);
        assert_eq!(drops.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn allocator_failure_is_typed_and_leaves_populated_resize_unchanged() {
        let fail = Arc::new(AtomicBool::new(true));
        let allocations = Arc::new(AtomicUsize::new(0));
        let deallocations = Arc::new(AtomicUsize::new(0));
        let alloc = ToggleAllocator {
            fail: fail.clone(),
            allocations: allocations.clone(),
            deallocations: deallocations.clone(),
        };
        let reserve = ReserveFraction::from_delta_log2(3).unwrap();
        let shape = FunnelShape::from_slots(144, reserve).unwrap();
        assert!(matches!(
            FunnelTable::<u64, u64, IdentityBuildHasher, _>::try_from_shape(
                shape.clone(),
                reserve,
                IdentityBuildHasher,
                alloc.clone(),
            ),
            Err(TryReserveError::AllocError)
        ));
        assert_eq!(allocations.load(Ordering::SeqCst), 0);

        fail.store(false, Ordering::SeqCst);
        let mut table = FunnelTable::<u64, u64, IdentityBuildHasher, _>::try_from_shape(
            shape,
            reserve,
            IdentityBuildHasher,
            alloc,
        )
        .unwrap();
        for key in 0..32_u64 {
            assert_eq!(
                <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(
                    &mut table, key, key, key,
                ),
                None
            );
        }
        let arena_bytes = table.arena.layout_size();
        let locations: Vec<_> = (0..32_u64)
            .map(|key| {
                (
                    key,
                    table
                        .find_location(&key, key, control::control_fingerprint(key))
                        .unwrap(),
                )
            })
            .collect();
        let next = FunnelShape::for_insert_budget(512, reserve).unwrap();
        fail.store(true, Ordering::SeqCst);
        assert_eq!(
            table.try_resize_exact(next.n),
            Err(TryReserveError::AllocError)
        );
        assert_eq!(table.len, 32);
        assert_eq!(table.shape.n, 144);
        assert_eq!(table.arena.layout_size(), arena_bytes);
        for (key, location) in locations {
            assert_eq!(
                table.find_location(&key, key, control::control_fingerprint(key)),
                Some(location)
            );
        }

        fail.store(false, Ordering::SeqCst);
        drop(table);
        assert_eq!(allocations.load(Ordering::SeqCst), 1);
        assert_eq!(deallocations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn vector_bucket_scan_matches_scalar_order_for_every_default_pattern() {
        const FP: u8 = 7;
        const OTHER: u8 = 1;
        const WIDTH: usize = 6;
        const PATTERN_COUNT: usize = 4_usize.pow(6);
        let states = [CTRL_EMPTY, CTRL_TOMBSTONE, OTHER, FP];

        for encoded in 0..PATTERN_COUNT {
            let mut controls = [FP; WIDTH + crate::common::config::GROUP_SIZE - 1];
            let mut value = encoded;
            for control in &mut controls[..WIDTH] {
                *control = states[value & 3];
                value >>= 2;
            }
            for hit_lane in 0..=WIDTH {
                let expected_hit = (hit_lane < WIDTH).then_some(hit_lane);
                let mut expected_first_tombstone = None;
                let mut expected_compared = Vec::new();
                let mut expected = BucketScanResult::Full;
                for (lane, &control) in controls[..WIDTH].iter().enumerate() {
                    if control == CTRL_TOMBSTONE {
                        expected_first_tombstone.get_or_insert(lane);
                    } else if control == CTRL_EMPTY {
                        expected =
                            BucketScanResult::Empty(expected_first_tombstone.unwrap_or(lane));
                        break;
                    } else if control == FP {
                        expected_compared.push(lane);
                        if Some(lane) == expected_hit {
                            expected = BucketScanResult::Hit(lane);
                            break;
                        }
                    }
                }

                let mut actual_first_tombstone = None;
                let mut actual_compared = Vec::new();
                let actual = unsafe {
                    scan_funnel_bucket(
                        controls.as_ptr(),
                        0,
                        WIDTH,
                        FP,
                        &mut actual_first_tombstone,
                        |slot| {
                            actual_compared.push(slot);
                            (Some(slot) == expected_hit).then_some(slot)
                        },
                    )
                };
                assert_eq!(actual, expected, "pattern={encoded} hit={hit_lane}");
                assert_eq!(
                    actual_first_tombstone, expected_first_tombstone,
                    "pattern={encoded} hit={hit_lane}"
                );
                assert_eq!(
                    actual_compared, expected_compared,
                    "pattern={encoded} hit={hit_lane}"
                );

                if !controls[..WIDTH].contains(&CTRL_TOMBSTONE) {
                    let mut clean_compared = Vec::new();
                    let clean = unsafe {
                        scan_clean_funnel_bucket(controls.as_ptr(), 0, WIDTH, FP, |slot| {
                            clean_compared.push(slot);
                            (Some(slot) == expected_hit).then_some(slot)
                        })
                    };
                    assert_eq!(clean, expected, "clean pattern={encoded} hit={hit_lane}");
                    assert_eq!(
                        clean_compared, expected_compared,
                        "clean pattern={encoded} hit={hit_lane}"
                    );
                }
            }
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn vector_bucket_scan_preserves_order_across_group_boundaries_and_padding() {
        const FP: u8 = 7;
        const OTHER: u8 = 1;

        fn scalar(
            controls: &[u8],
            start: usize,
            width: usize,
            hit_slot: Option<usize>,
            mut first_tombstone: Option<usize>,
        ) -> (BucketScanResult<usize>, Option<usize>, Vec<usize>) {
            let mut compared = Vec::new();
            for (slot, &control) in controls.iter().enumerate().skip(start).take(width) {
                match control {
                    CTRL_TOMBSTONE => {
                        first_tombstone.get_or_insert(slot);
                    }
                    CTRL_EMPTY => {
                        return (
                            BucketScanResult::Empty(first_tombstone.unwrap_or(slot)),
                            first_tombstone,
                            compared,
                        );
                    }
                    FP => {
                        compared.push(slot);
                        if Some(slot) == hit_slot {
                            return (BucketScanResult::Hit(slot), first_tombstone, compared);
                        }
                    }
                    _ => {}
                }
            }
            (BucketScanResult::Full, first_tombstone, compared)
        }

        let start = 3;
        for width in [10, 15, 16, 18, 32, 34] {
            for existing_tombstone in [None, Some(1)] {
                let mut controls = vec![OTHER; start + width + GROUP_SIZE - 1];
                let logical_end = start + width;
                for (index, control) in controls[logical_end..].iter_mut().enumerate() {
                    *control = if index.is_multiple_of(2) {
                        FP
                    } else {
                        CTRL_EMPTY
                    };
                }
                let tombstone = start + width / 4;
                let collision = start + (GROUP_SIZE - 1).min(width - 2);
                let hit = start + GROUP_SIZE.min(width - 2);
                controls[tombstone] = CTRL_TOMBSTONE;
                controls[collision] = FP;
                controls[hit] = FP;
                controls[logical_end - 1] = CTRL_EMPTY;

                let expected = scalar(&controls, start, width, Some(hit), existing_tombstone);
                let mut actual_first_tombstone = existing_tombstone;
                let mut actual_compared = Vec::new();
                let actual = unsafe {
                    scan_funnel_bucket(
                        controls.as_ptr(),
                        start,
                        width,
                        FP,
                        &mut actual_first_tombstone,
                        |slot| {
                            actual_compared.push(slot);
                            (slot == hit).then_some(slot)
                        },
                    )
                };
                assert_eq!(actual, expected.0, "width={width}");
                assert_eq!(actual_first_tombstone, expected.1, "width={width}");
                assert_eq!(actual_compared, expected.2, "width={width}");

                controls.fill(OTHER);
                controls[start + width / 2] = CTRL_EMPTY;
                controls[logical_end - 1] = FP;
                controls[logical_end..].fill(FP);
                let expected = scalar(
                    &controls,
                    start,
                    width,
                    Some(logical_end - 1),
                    existing_tombstone,
                );
                let mut actual_first_tombstone = existing_tombstone;
                let mut actual_compared = Vec::new();
                let actual = unsafe {
                    scan_funnel_bucket(
                        controls.as_ptr(),
                        start,
                        width,
                        FP,
                        &mut actual_first_tombstone,
                        |slot| {
                            actual_compared.push(slot);
                            (slot == logical_end - 1).then_some(slot)
                        },
                    )
                };
                assert_eq!(actual, expected.0, "empty width={width}");
                assert_eq!(actual_first_tombstone, expected.1, "empty width={width}");
                assert_eq!(actual_compared, expected.2, "empty width={width}");
            }
        }
    }
}
