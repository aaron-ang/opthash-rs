use std::borrow::Borrow;
use std::fmt;
use std::hash::{BuildHasher, Hash};
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::mem;
use std::ops::{ControlFlow, Range};
use std::ptr;

use crate::common::config::{
    DEFAULT_RESERVE_FRACTION, GROUP_SIZE, INITIAL_CAPACITY, MAX_FUNNEL_RESERVE_FRACTION,
};
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use crate::common::error::{EntryView, OccupiedError as CommonOccupiedError};
use crate::common::iter::{
    IntoKeys as CommonIntoKeys, IntoValues as CommonIntoValues, Keys as CommonKeys,
    Values as CommonValues,
};
use crate::common::layout::{OccupiedCursor, RawTable, SlotEntry};
use crate::common::math::{self, align, capacity, cast, probe};
use crate::common::{Allocator, DefaultHashBuilder, Global, TryReserveError};

/// One funnel level `A_i` (paper §5). Fixed grid of `β`-sized buckets `A_{i,j}`;
/// inserts hash to one bucket and probe within it. Overflow spills to `A_{i+1}`
/// (or the special array `A_{α+1}`).
struct BucketLevel<K, V, A: Allocator = Global> {
    /// Structure of Arrays control bytes + entries.
    table: RawTable<SlotEntry<K, V>, A>,
    /// Live entry count.
    len: usize,
    /// Deleted-slot count.
    tombstones: usize,
    /// Per-level salt mixed into the key hash so each level distributes differently.
    salt: u64,
    /// `bucket_count - 1`; `bucket_count` is pow2 so `bucket_index` is `hash & mask`.
    bucket_count_mask: usize,
    /// `bucket_size` is pow2 so `bucket_idx * bucket_size` is `bucket_idx << bucket_size_log2`.
    bucket_size_log2: u32,
}

impl<K, V, A: Allocator> BucketLevel<K, V, A> {
    fn with_bucket_count_in(bucket_count: usize, bucket_size: usize, salt: u64, alloc: A) -> Self {
        let bucket_count = if bucket_count == 0 {
            0
        } else {
            bucket_count.next_power_of_two()
        };
        let bucket_size = bucket_size.next_power_of_two();
        let total_capacity = bucket_count.saturating_mul(bucket_size);
        Self {
            table: RawTable::new_in(total_capacity, alloc),
            len: 0,
            tombstones: 0,
            salt,
            bucket_count_mask: bucket_count.saturating_sub(1),
            bucket_size_log2: bucket_size.trailing_zeros(),
        }
    }

    /// Fallible counterpart to [`BucketLevel::with_bucket_count_in`].
    fn try_with_bucket_count_in(
        bucket_count: usize,
        bucket_size: usize,
        salt: u64,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let bucket_count = if bucket_count == 0 {
            0
        } else {
            bucket_count.next_power_of_two()
        };
        let bucket_size = bucket_size.next_power_of_two();
        let total_capacity = bucket_count.saturating_mul(bucket_size);
        let table = RawTable::try_new_in(total_capacity, alloc)
            .map_err(|()| TryReserveError::AllocError)?;
        Ok(Self {
            table,
            len: 0,
            tombstones: 0,
            salt,
            bucket_count_mask: bucket_count.saturating_sub(1),
            bucket_size_log2: bucket_size.trailing_zeros(),
        })
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.table.capacity()
    }

    /// Hash → bucket via pow2 mask, salted so each level distributes differently.
    #[allow(clippy::cast_possible_truncation)]
    #[inline]
    fn bucket_index(&self, key_hash: u64) -> usize {
        ((key_hash ^ self.salt) as usize) & self.bucket_count_mask
    }

    /// Slot index range covering all entries in `bucket_idx`.
    #[inline]
    fn bucket_range(&self, bucket_idx: usize) -> Range<usize> {
        let start = bucket_idx << self.bucket_size_log2;
        let size = 1 << self.bucket_size_log2;
        start..start + size
    }

    /// Paper §5 attempted insertion: hash `key_hash` to one bucket `A_{i,j}`,
    /// return the first empty slot in that bucket (or `None` if full).
    fn first_free_in_bucket(&self, key_hash: u64) -> Option<usize> {
        if self.len >= self.capacity() {
            return None;
        }

        let bucket_idx = self.bucket_index(key_hash);
        let bucket_range = self.bucket_range(bucket_idx);
        // SAFETY: `bucket_size` is `GROUP_SIZE`-aligned at construction.
        // Hinting elides the `& ~0xF` LLVM emits to fold `(start / 16) * 16`.
        debug_assert_eq!(bucket_range.start % GROUP_SIZE, 0);
        if !bucket_range.start.is_multiple_of(GROUP_SIZE) {
            unsafe { std::hint::unreachable_unchecked() };
        }
        let group_idx = bucket_range.start / GROUP_SIZE;
        self.table
            .group_free_mask(group_idx)
            .lowest()
            .map(|offset| bucket_range.start + offset)
    }

    /// Probe one bucket for `key`. SIMD fingerprint scan + key compare.
    /// `StopSearch` on EMPTY byte: bucket never overflowed, so the key cannot
    /// be at a deeper level. See [`Candidate`] for the tracking modes.
    #[inline]
    fn find_in_bucket<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        candidate: Candidate<'_, usize>,
    ) -> LookupStep
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        if self.len == 0 {
            if self.table.capacity() == 0 {
                return LookupStep::Continue;
            }
            // Record the chosen bucket's first slot so the insert candidate
            // isn't lost.
            if candidate.wants_free() {
                let bucket_idx = self.bucket_index(key_hash);
                let bucket_start = bucket_idx << self.bucket_size_log2;
                candidate.record(Some(bucket_start));
            }
            // No tombstones ⇒ the cascade never placed a key deeper than this
            // level, so we can stop probing.
            if self.tombstones == 0 {
                return LookupStep::StopSearch;
            }
            return LookupStep::Continue;
        }

        let bucket_idx = self.bucket_index(key_hash);
        let bucket_range = self.bucket_range(bucket_idx);
        // SAFETY: `bucket_size` is `GROUP_SIZE`-aligned at construction.
        // Hinting elides the `& ~0xF` LLVM emits to fold `(start / 16) * 16`.
        debug_assert_eq!(bucket_range.start % GROUP_SIZE, 0);
        if !bucket_range.start.is_multiple_of(GROUP_SIZE) {
            unsafe { std::hint::unreachable_unchecked() };
        }
        let group_idx = bucket_range.start / GROUP_SIZE;

        for relative_idx in self.table.group_match_mask(group_idx, key_fingerprint) {
            let slot_idx = bucket_range.start + relative_idx;
            let entry = unsafe { self.table.get_ref(slot_idx) };
            if entry.key.borrow() == key {
                return LookupStep::Found(slot_idx);
            }
        }

        if candidate.wants_free() {
            let slot = self
                .table
                .group_free_mask(group_idx)
                .lowest()
                .map(|o| bucket_range.start + o);
            candidate.record(slot);
        }

        // StopSearch: bucket has an EMPTY byte → no key ever overflowed past
        // here. Tombstones don't disable termination since the empty byte
        // still proves the probe chain terminated naturally.
        if self.table.group_match_mask(group_idx, CTRL_EMPTY).any() {
            LookupStep::StopSearch
        } else {
            LookupStep::Continue
        }
    }
}

impl<K: Clone, V: Clone, A: Allocator + Clone> Clone for BucketLevel<K, V, A> {
    fn clone(&self) -> Self {
        Self {
            table: self.table.clone(),
            len: self.len,
            tombstones: self.tombstones,
            salt: self.salt,
            bucket_count_mask: self.bucket_count_mask,
            bucket_size_log2: self.bucket_size_log2,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.table.clone_from(&source.table);
        self.len = source.len;
        self.tombstones = source.tombstones;
        self.salt = source.salt;
        self.bucket_count_mask = source.bucket_count_mask;
        self.bucket_size_log2 = source.bucket_size_log2;
    }
}

/// Per-key odd-step probe over pow2 group count (paper §5 `SpecialPrimary`).
/// Step coprime to `group_count` ⇒ permutation over all groups.
struct ProbeSeq {
    group: usize,
    step: usize,
}

impl ProbeSeq {
    #[inline]
    fn new(group: usize, step: usize) -> Self {
        Self { group, step }
    }

    #[inline]
    fn advance(&mut self, mask: usize) {
        self.group = (self.group + self.step) & mask;
    }
}

/// Half `B` of the special array `A_{α+1}` (paper §5):
/// uniform-probing table capped at `primary_probe_limit` ≈ log log n probes.
/// SIMD-group open addressing with per-key odd-step probing over pow2 `group_count`
/// (step coprime to `group_count` ⇒ permutation over all groups).
struct SpecialPrimary<K, V, A: Allocator = Global> {
    /// `SoA` control bytes + entries.
    table: RawTable<SlotEntry<K, V>, A>,
    /// Live entry count.
    len: usize,
    /// Total tombstones; drives the global 50%-capacity resize trigger.
    tombstones: usize,
    /// `group_count - 1`. `group_count` is pow2 by construction,
    ///  so `(idx + step) & mask` wraps in one op.
    group_count_mask: usize,
}

impl<K, V, A: Allocator + Clone> SpecialPrimary<K, V, A> {
    fn with_capacity_in(capacity: usize, alloc: A) -> Self {
        let inflated = align::round_up_to_pow2_groups(capacity);
        let table = RawTable::new_in(inflated, alloc.clone());
        let group_count = table.group_count();
        debug_assert!(
            group_count == 0 || group_count.is_power_of_two(),
            "SpecialPrimary group_count must be pow2",
        );
        Self {
            table,
            len: 0,
            tombstones: 0,
            group_count_mask: group_count.saturating_sub(1),
        }
    }

    /// Fallible counterpart to [`SpecialPrimary::with_capacity_in`].
    fn try_with_capacity_in(capacity: usize, alloc: A) -> Result<Self, TryReserveError> {
        let inflated = align::round_up_to_pow2_groups(capacity);
        let table =
            RawTable::try_new_in(inflated, alloc).map_err(|()| TryReserveError::AllocError)?;
        let group_count = table.group_count();
        Ok(Self {
            table,
            len: 0,
            tombstones: 0,
            group_count_mask: group_count.saturating_sub(1),
        })
    }

    /// Start group for the probe sequence.
    #[inline]
    fn group_start(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash.rotate_left(11)) & self.group_count_mask
    }

    /// Per-key odd step over the pow2 `group_count`. The `| 1` forces odd ⇒
    /// coprime to pow2 ⇒ `(group_idx + step) & mask` visits every group
    /// within `group_count` iterations.
    #[inline]
    fn group_step(&self, key_hash: u64) -> usize {
        (probe::hash_to_usize(key_hash.rotate_left(43)) | 1) & self.group_count_mask
    }

    #[inline]
    fn first_free_in_group(&self, group_idx: usize) -> Option<usize> {
        self.table.first_free_in_group(group_idx)
    }
}

impl<K: Clone, V: Clone, A: Allocator + Clone> Clone for SpecialPrimary<K, V, A> {
    fn clone(&self) -> Self {
        Self {
            table: self.table.clone(),
            len: self.len,
            tombstones: self.tombstones,
            group_count_mask: self.group_count_mask,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.table.clone_from(&source.table);
        self.len = source.len;
        self.tombstones = source.tombstones;
        self.group_count_mask = source.group_count_mask;
    }
}

/// Half `C` of the special array `A_{α+1}` (paper §5):
/// two-choice table with buckets of size `2 * primary_probe_limit` ≈ 2 log log n.
/// Reached only when a key exhausts the primary's probe budget.
struct SpecialFallback<K, V, A: Allocator = Global> {
    /// Structure of Arrays control bytes + entries.
    table: RawTable<SlotEntry<K, V>, A>,
    /// Live entry count.
    len: usize,
    /// Deleted-slot count.
    tombstones: usize,
    /// Number of buckets.
    bucket_count: usize,
    /// `bucket_size` is pow2 so `bucket_idx * bucket_size` is `bucket_idx << bucket_size_log2`.
    bucket_size_log2: u32,
}

impl<K, V, A: Allocator> SpecialFallback<K, V, A> {
    fn with_capacity_in(capacity: usize, bucket_size: usize, alloc: A) -> Self {
        let bucket_size = bucket_size.next_power_of_two();
        let bucket_count = if bucket_size == 0 {
            0
        } else {
            capacity.div_ceil(bucket_size)
        };
        Self {
            table: RawTable::new_in(capacity, alloc),
            len: 0,
            tombstones: 0,
            bucket_count,
            bucket_size_log2: bucket_size.trailing_zeros(),
        }
    }

    /// Fallible counterpart to [`SpecialFallback::with_capacity_in`].
    fn try_with_capacity_in(
        capacity: usize,
        bucket_size: usize,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let bucket_size = bucket_size.next_power_of_two();
        let bucket_count = if bucket_size == 0 {
            0
        } else {
            capacity.div_ceil(bucket_size)
        };
        let table =
            RawTable::try_new_in(capacity, alloc).map_err(|()| TryReserveError::AllocError)?;
        Ok(Self {
            table,
            len: 0,
            tombstones: 0,
            bucket_count,
            bucket_size_log2: bucket_size.trailing_zeros(),
        })
    }

    #[inline]
    fn capacity(&self) -> usize {
        self.table.capacity()
    }

    #[inline]
    fn bucket_range(&self, bucket_idx: usize) -> Range<usize> {
        let start = bucket_idx << self.bucket_size_log2;
        let size = 1 << self.bucket_size_log2;
        let end = (start + size).min(self.table.capacity());
        start..end
    }

    #[inline]
    fn bucket_a(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash.rotate_left(19)) % self.bucket_count
    }

    #[inline]
    fn bucket_b(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash.rotate_left(37)) % self.bucket_count
    }
}

impl<K: Clone, V: Clone, A: Allocator + Clone> Clone for SpecialFallback<K, V, A> {
    fn clone(&self) -> Self {
        Self {
            table: self.table.clone(),
            len: self.len,
            tombstones: self.tombstones,
            bucket_count: self.bucket_count,
            bucket_size_log2: self.bucket_size_log2,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.table.clone_from(&source.table);
        self.len = source.len;
        self.tombstones = source.tombstones;
        self.bucket_count = source.bucket_count;
        self.bucket_size_log2 = source.bucket_size_log2;
    }
}

/// Combines the special primary (probed first) and the special fallback
/// (when primary hits its probe limit). Together they catch keys that
/// overflowed every bucket level.
struct SpecialArray<K, V, A: Allocator + Clone = Global> {
    /// Probed first; bounded by `primary_probe_limit`.
    primary: SpecialPrimary<K, V, A>,
    /// Probed after primary hits its limit.
    fallback: SpecialFallback<K, V, A>,
    /// `primary.len + fallback.len`. Cached so the lookup fast path can
    /// short-circuit on a single load when the special tables are empty.
    total_len: usize,
}

impl<K, V, A: Allocator + Clone> SpecialArray<K, V, A> {
    fn with_capacity_in(capacity: usize, primary_probe_limit: usize, alloc: A) -> Self {
        let fallback_bucket_size = (2usize.saturating_mul(primary_probe_limit)).max(2);
        let primary_capacity = capacity.div_ceil(2);
        let fallback_capacity = capacity.saturating_sub(primary_capacity);
        Self {
            primary: SpecialPrimary::with_capacity_in(primary_capacity, alloc.clone()),
            fallback: SpecialFallback::with_capacity_in(
                fallback_capacity,
                fallback_bucket_size,
                alloc,
            ),
            total_len: 0,
        }
    }

    /// Fallible counterpart to [`SpecialArray::with_capacity_in`].
    fn try_with_capacity_in(
        capacity: usize,
        primary_probe_limit: usize,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let fallback_bucket_size = (2usize.saturating_mul(primary_probe_limit)).max(2);
        let primary_capacity = capacity.div_ceil(2);
        let fallback_capacity = capacity.saturating_sub(primary_capacity);
        Ok(Self {
            primary: SpecialPrimary::try_with_capacity_in(primary_capacity, alloc.clone())?,
            fallback: SpecialFallback::try_with_capacity_in(
                fallback_capacity,
                fallback_bucket_size,
                alloc,
            )?,
            total_len: 0,
        })
    }
}

impl<K: Clone, V: Clone, A: Allocator + Clone> Clone for SpecialArray<K, V, A> {
    fn clone(&self) -> Self {
        Self {
            primary: self.primary.clone(),
            fallback: self.fallback.clone(),
            total_len: self.total_len,
        }
    }

    fn clone_from(&mut self, source: &Self) {
        self.primary.clone_from(&source.primary);
        self.fallback.clone_from(&source.fallback);
        self.total_len = source.total_len;
    }
}

/// Where in the funnel structure a key/slot lives. Returned by lookups,
/// consumed by inserts / removes to avoid recomputing the location.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SlotLocation {
    Level { level_idx: usize, slot_idx: usize },
    SpecialPrimary { slot_idx: usize },
    SpecialFallback { slot_idx: usize },
}

/// Outcome of probing one bucket / group during lookup.
/// - `Found(slot_idx)`: key matched at slot.
/// - `Continue`: bucket has tombstones; keep probing for the key elsewhere.
/// - `StopSearch`: bucket has free space and no tombstones — key cannot
///   exist further along this hash chain, abort the search.
enum LookupStep {
    Found(usize),
    Continue,
    StopSearch,
}

/// Candidate-tracking mode for `find_in_*` scans.
///
/// - `Lookup`: pure lookup — skip the free-slot SIMD scan.
/// - `Track(out)`: record the first FREE-or-TOMBSTONE slot into `*out` when
///   `*out` is `None`; if already `Some`, the scan acts like `Lookup` (caller
///   has an earlier candidate, no need to find another).
enum Candidate<'a, T> {
    Lookup,
    Track(&'a mut Option<T>),
}

impl<T> Candidate<'_, T> {
    /// True when this scan should look for a free slot (caller passed
    /// `Track` and `*out` is still `None`).
    #[inline]
    fn wants_free(&self) -> bool {
        matches!(self, Candidate::Track(out) if out.is_none())
    }

    /// Record `slot` into `*out`, only if `Track` and `*out` is `None`.
    #[inline]
    fn record(self, slot: Option<T>) {
        if let Candidate::Track(out) = self
            && out.is_none()
        {
            *out = slot;
        }
    }
}

/// Open-addressed hash map using funnel hashing.
///
/// Capacity is split between a stack of bucket-grouped `levels` (each level
/// half the size of the previous) and a `special` array catching overflow.
/// Inserts try level 0 first, then descend to deeper levels, then to
/// `special.primary`, then `special.fallback`. Lookups follow the same
/// order. The funnel structure trades a small probe budget per level for
/// hard worst-case guarantees on lookup cost.
pub struct FunnelHashMap<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    /// Bucket-grouped levels, each half the size of the previous; length fixed at ctor.
    levels: Box<[BucketLevel<K, V, A>]>,
    /// Overflow-catching tables (primary + fallback).
    special: SpecialArray<K, V, A>,
    /// Total live entries across levels + special.
    len: usize,
    /// Total slot count.
    capacity: usize,
    /// Insert count that triggers `resize(2x)`.
    max_insertions: usize,
    /// Slot reserve fraction. Set at construction.
    reserve_fraction: f64,
    /// Cap on groups probed in the special primary before fallback.
    primary_probe_limit: usize,
    /// Highest level index ever written; bounds the lookup probe loop.
    max_populated_level: usize,
    /// Hash builder. Cloned across resizes to preserve probe sequences.
    hash_builder: S,
    /// Allocator used for all per-capacity allocations (tables, summaries).
    alloc: A,
}

impl<K: fmt::Debug, V: fmt::Debug, S, A: Allocator + Clone> fmt::Debug
    for FunnelHashMap<K, V, S, A>
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunnelHashMap")
            .field("len", &self.len)
            .field("capacity", &self.capacity)
            .field("max_populated_level", &self.max_populated_level)
            .finish_non_exhaustive()
    }
}

impl<K, V> Default for FunnelHashMap<K, V, DefaultHashBuilder, Global>
where
    K: Eq + Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

// Global allocator + default hasher constructors.
impl<K, V> FunnelHashMap<K, V, DefaultHashBuilder, Global>
where
    K: Eq + Hash,
{
    #[must_use]
    pub fn new() -> Self {
        Self::with_capacity_and_reserve_fraction(0, DEFAULT_RESERVE_FRACTION)
    }

    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_reserve_fraction(capacity, DEFAULT_RESERVE_FRACTION)
    }

    #[must_use]
    pub fn with_reserve_fraction(reserve_fraction: f64) -> Self {
        Self::with_capacity_and_reserve_fraction(0, reserve_fraction)
    }

    #[must_use]
    pub fn with_capacity_and_reserve_fraction(capacity: usize, reserve_fraction: f64) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            DefaultHashBuilder::default(),
            Global,
        )
    }
}

// Global allocator + custom hasher constructors.
impl<K, V, S> FunnelHashMap<K, V, S, Global>
where
    K: Eq + Hash,
    S: BuildHasher,
{
    #[must_use]
    pub fn with_hasher(hash_builder: S) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            DEFAULT_RESERVE_FRACTION,
            hash_builder,
            Global,
        )
    }

    #[must_use]
    pub fn with_capacity_and_hasher(capacity: usize, hash_builder: S) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            DEFAULT_RESERVE_FRACTION,
            hash_builder,
            Global,
        )
    }

    #[must_use]
    pub fn with_reserve_fraction_and_hasher(reserve_fraction: f64, hash_builder: S) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            reserve_fraction,
            hash_builder,
            Global,
        )
    }

    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: S,
    ) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            reserve_fraction,
            hash_builder,
            Global,
        )
    }
}

// Default hasher + custom allocator constructors.
impl<K, V, A> FunnelHashMap<K, V, DefaultHashBuilder, A>
where
    K: Eq + Hash,
    A: Allocator + Clone,
{
    #[must_use]
    pub fn new_in(alloc: A) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            0,
            DEFAULT_RESERVE_FRACTION,
            DefaultHashBuilder::default(),
            alloc,
        )
    }

    #[must_use]
    pub fn with_capacity_in(capacity: usize, alloc: A) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
            capacity,
            DEFAULT_RESERVE_FRACTION,
            DefaultHashBuilder::default(),
            alloc,
        )
    }
}

impl<K, V, S, A> FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Full constructor. `resize` also calls this with the existing
    /// `hash_builder` and allocator so all keys keep the same hash sequence
    /// across grows.
    ///
    /// # Panics
    ///
    /// Panics if no representable capacity satisfies the requested budget.
    #[must_use]
    pub fn with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        // Paper §5 precondition: δ ≤ 1/8.
        let reserve_fraction =
            capacity::sanitize_reserve_fraction(reserve_fraction).min(MAX_FUNNEL_RESERVE_FRACTION);
        let capacity = if capacity == 0 {
            0
        } else {
            capacity::capacity_for(INITIAL_CAPACITY, capacity, reserve_fraction)
                .expect("capacity overflow")
        };
        let max_insertions = capacity::max_insertions(capacity, reserve_fraction);

        let level_count = compute_level_count(reserve_fraction);
        let bucket_width = align::round_up_to_group(compute_bucket_width(reserve_fraction));
        let primary_probe_limit = probe::log_log_probe_limit(capacity).max(1);

        let mut special_capacity =
            choose_special_capacity(capacity, reserve_fraction, bucket_width);
        let mut main_capacity = capacity.saturating_sub(special_capacity);
        let main_remainder = main_capacity % bucket_width.max(1);
        if main_remainder != 0 {
            main_capacity = main_capacity.saturating_sub(main_remainder);
            special_capacity = capacity.saturating_sub(main_capacity);
        }

        let total_main_buckets = main_capacity.checked_div(bucket_width).unwrap_or(0);
        let level_bucket_counts = partition_funnel_buckets(total_main_buckets, level_count);
        let levels: Box<[BucketLevel<K, V, A>]> = level_bucket_counts
            .into_iter()
            .enumerate()
            .map(|(level_idx, bucket_count)| {
                BucketLevel::with_bucket_count_in(
                    bucket_count,
                    bucket_width,
                    math::level_salt(level_idx),
                    alloc.clone(),
                )
            })
            .collect();

        let special =
            SpecialArray::with_capacity_in(special_capacity, primary_probe_limit, alloc.clone());

        Self {
            levels,
            special,
            len: 0,
            capacity,
            max_insertions,
            reserve_fraction,
            primary_probe_limit,
            max_populated_level: 0,
            hash_builder,
            alloc,
        }
    }

    /// Reference to the map's allocator.
    #[must_use]
    pub fn allocator(&self) -> &A {
        &self.alloc
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum number of inserts the map can absorb before the next resize.
    /// Mirrors [`std::collections::HashMap::capacity`]. Returns
    /// `max_insertions` (the budget), not the raw slot count.
    #[must_use]
    #[allow(clippy::misnamed_getters)]
    pub fn capacity(&self) -> usize {
        self.max_insertions
    }

    /// Grow capacity so at least `additional` more inserts fit. No-op if
    /// already large enough. Probe-budget exhaustion may still trigger a
    /// resize mid-fill.
    ///
    /// # Panics
    ///
    /// Panics on capacity overflow. Use [`Self::try_reserve`] for fallible
    /// growth.
    pub fn reserve(&mut self, additional: usize) {
        let needed = self.len.saturating_add(additional);
        if needed <= self.max_insertions {
            return;
        }
        let new_capacity = self.grow_capacity_for(needed).expect("capacity overflow");
        self.resize(new_capacity);
    }

    /// Fallible counterpart to [`Self::reserve`].
    ///
    /// # Errors
    ///
    /// [`TryReserveError::CapacityOverflow`] if `self.len + additional`
    /// overflows; [`TryReserveError::AllocError`] on allocator failure.
    pub fn try_reserve(&mut self, additional: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        let needed = self
            .len
            .checked_add(additional)
            .ok_or(TryReserveError::CapacityOverflow)?;
        if needed <= self.max_insertions {
            return Ok(());
        }
        let new_capacity = self
            .grow_capacity_for(needed)
            .ok_or(TryReserveError::CapacityOverflow)?;
        self.try_resize(new_capacity)
    }

    /// Shrinks the capacity as much as possible while preserving all live
    /// entries. Mirrors [`std::collections::HashMap::shrink_to_fit`].
    pub fn shrink_to_fit(&mut self) {
        self.shrink_to(0);
    }

    /// Shrinks the capacity with a lower bound. The table won't shrink below
    /// the larger of `min_capacity` and `self.len`. Mirrors
    /// [`std::collections::HashMap::shrink_to`].
    ///
    /// # Panics
    ///
    /// Panics if no representable capacity satisfies
    /// `capacity::max_insertions(cap) >= min_capacity`.
    pub fn shrink_to(&mut self, min_capacity: usize) {
        if self.len == 0 && min_capacity == 0 {
            if self.capacity > 0 {
                self.resize(0);
            }
            return;
        }
        let lower = self.len.max(min_capacity).max(INITIAL_CAPACITY);
        let new_capacity = capacity::capacity_for(INITIAL_CAPACITY, lower, self.reserve_fraction)
            .expect("capacity overflow");
        if new_capacity >= self.capacity {
            return;
        }
        self.resize(new_capacity);
    }

    /// Round up to the smallest capacity whose `max_insertions` accommodates
    /// `needed` live entries. Returns `None` if no representable capacity
    /// suffices.
    fn grow_capacity_for(&self, needed: usize) -> Option<usize> {
        capacity::capacity_for(
            self.capacity.max(INITIAL_CAPACITY),
            needed,
            self.reserve_fraction,
        )
    }

    /// # Panics
    ///
    /// Panics if a resize succeeds but no free slot can be found for the new key.
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let key_hash = self.hash_key(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);

        // Scan levels: on match, replace; on miss, retain the first free
        // slot we saw as the insertion candidate.
        let mut candidate: Option<SlotLocation> = None;
        let (found, chain_clean) = self.find_in_levels(
            &key,
            key_hash,
            key_fingerprint,
            Candidate::Track(&mut candidate),
        );
        if let Some(location) = found {
            return Some(self.replace_existing_value(location, value));
        }

        // Fast path: skip special-array dedup if either:
        // (1) special is entirely empty, OR
        // (2) the level chain terminated via a clean EMPTY byte — no
        //     TOMBSTONE seen, so the key cannot have overflowed to special.
        // Both require a level-side candidate to place the new entry.
        if candidate.is_some() && (self.special.total_len == 0 || chain_clean) {
            return self.insert_at_location_after_resize_check(
                candidate,
                key_hash,
                key,
                value,
                key_fingerprint,
            );
        }

        // Cold path: key might be in the special array. Outlined into its
        // own function to keep insert's hot code compact.
        if let Some(location) =
            self.scan_special_for_key(&key, key_hash, key_fingerprint, &mut candidate)
        {
            return Some(self.replace_existing_value(location, value));
        }

        self.insert_at_location_after_resize_check(candidate, key_hash, key, value, key_fingerprint)
    }

    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);

        match self.find_slot_location_with_hash(key, key_hash, key_fingerprint)? {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => Some(unsafe { &self.levels[level_idx].table.get_ref(slot_idx).value }),
            SlotLocation::SpecialPrimary { slot_idx } => {
                Some(unsafe { &self.special.primary.table.get_ref(slot_idx).value })
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                Some(unsafe { &self.special.fallback.table.get_ref(slot_idx).value })
            }
        }
    }

    /// Like [`Self::get`] but returns the stored key alongside its value.
    pub fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);

        let entry = match self.find_slot_location_with_hash(key, key_hash, key_fingerprint)? {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { self.levels[level_idx].table.get_ref(slot_idx) },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                self.special.primary.table.get_ref(slot_idx)
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                self.special.fallback.table.get_ref(slot_idx)
            },
        };
        Some((&entry.key, &entry.value))
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);

        match self.find_slot_location_with_hash(key, key_hash, key_fingerprint)? {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => Some(unsafe { &mut self.levels[level_idx].table.get_mut(slot_idx).value }),
            SlotLocation::SpecialPrimary { slot_idx } => {
                Some(unsafe { &mut self.special.primary.table.get_mut(slot_idx).value })
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                Some(unsafe { &mut self.special.fallback.table.get_mut(slot_idx).value })
            }
        }
    }

    /// Returns `N` disjoint mutable references, mirroring
    /// [`std::collections::HashMap::get_disjoint_mut`]: `None` if any key
    /// misses, panic on aliasing.
    ///
    /// # Panics
    ///
    /// If two input keys resolve to the same physical slot.
    /// Returns `N` disjoint mutable references, mirroring
    /// [`std::collections::HashMap::get_disjoint_mut`]: per-key `Option`
    /// for each lookup, panic on aliasing among the hits.
    ///
    /// # Panics
    ///
    /// If two input keys resolve to the same slot.
    pub fn get_disjoint_mut<Q, const N: usize>(&mut self, keys: [&Q; N]) -> [Option<&mut V>; N]
    where
        K: Borrow<Q> + Eq,
        Q: Hash + Eq + ?Sized,
    {
        let locations = self.locate_disjoint(keys);
        check_disjoint_aliasing_funnel(&locations);

        let levels_ptr: *mut BucketLevel<K, V, A> = self.levels.as_mut_ptr();
        let primary_ptr: *mut SpecialPrimary<K, V, A> = &raw mut self.special.primary;
        let fallback_ptr: *mut SpecialFallback<K, V, A> = &raw mut self.special.fallback;
        core::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: locations are unique among Somes (asserted above).
                // Raw-pointer chain — no intermediate `&mut BucketLevel`,
                // `&mut SpecialPrimary`, or `&mut SpecialFallback`.
                let value_ptr: *mut V =
                    unsafe { funnel_slot_value_ptr(levels_ptr, primary_ptr, fallback_ptr, loc) };
                unsafe { &mut *value_ptr }
            })
        })
    }

    /// Like [`Self::get_disjoint_mut`] but each yielded element is
    /// `(&K, &mut V)`. Mirrors `std`'s `get_disjoint_key_value_mut`.
    ///
    /// # Panics
    ///
    /// If two input keys resolve to the same slot.
    pub fn get_disjoint_key_value_mut<Q, const N: usize>(
        &mut self,
        keys: [&Q; N],
    ) -> [Option<(&K, &mut V)>; N]
    where
        K: Borrow<Q> + Eq,
        Q: Hash + Eq + ?Sized,
    {
        let locations = self.locate_disjoint(keys);
        check_disjoint_aliasing_funnel(&locations);

        let levels_ptr: *mut BucketLevel<K, V, A> = self.levels.as_mut_ptr();
        let primary_ptr: *mut SpecialPrimary<K, V, A> = &raw mut self.special.primary;
        let fallback_ptr: *mut SpecialFallback<K, V, A> = &raw mut self.special.fallback;
        core::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: as in `get_disjoint_mut`.
                let (k_ptr, v_ptr) =
                    unsafe { funnel_slot_kv_ptrs(levels_ptr, primary_ptr, fallback_ptr, loc) };
                (unsafe { &*k_ptr }, unsafe { &mut *v_ptr })
            })
        })
    }

    /// Unsafe variant of [`Self::get_disjoint_mut`] that skips the
    /// alias check. Mirrors [`std::collections::HashMap::get_disjoint_unchecked_mut`].
    ///
    /// # Safety
    ///
    /// Among the keys that resolve to occupied slots, all must reference
    /// distinct entries; otherwise the returned references alias and
    /// behavior is undefined.
    pub unsafe fn get_disjoint_unchecked_mut<Q, const N: usize>(
        &mut self,
        keys: [&Q; N],
    ) -> [Option<&mut V>; N]
    where
        K: Borrow<Q> + Eq,
        Q: Hash + Eq + ?Sized,
    {
        let locations = self.locate_disjoint(keys);

        let levels_ptr: *mut BucketLevel<K, V, A> = self.levels.as_mut_ptr();
        let primary_ptr: *mut SpecialPrimary<K, V, A> = &raw mut self.special.primary;
        let fallback_ptr: *mut SpecialFallback<K, V, A> = &raw mut self.special.fallback;
        core::array::from_fn(|i| {
            locations[i].map(|loc| {
                // SAFETY: caller guarantees the hits are pairwise distinct.
                let value_ptr: *mut V =
                    unsafe { funnel_slot_value_ptr(levels_ptr, primary_ptr, fallback_ptr, loc) };
                unsafe { &mut *value_ptr }
            })
        })
    }

    #[inline]
    fn locate_disjoint<Q, const N: usize>(&self, keys: [&Q; N]) -> [Option<SlotLocation>; N]
    where
        K: Borrow<Q> + Eq,
        Q: Hash + Eq + ?Sized,
    {
        core::array::from_fn(|i| {
            let key = keys[i];
            let key_hash = self.hash_key(key);
            let key_fingerprint = control::control_fingerprint(key_hash);
            self.find_slot_location_with_hash(key, key_hash, key_fingerprint)
        })
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        self.find_slot_location_with_hash(key, key_hash, key_fingerprint)
            .is_some()
    }

    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.remove_inner(key).map(|(_, v)| v)
    }

    /// Like [`Self::remove`] but returns the stored key alongside its value.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.remove_inner(key)
    }

    fn remove_inner<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let key_hash = self.hash_key(key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let location = self.find_slot_location_with_hash(key, key_hash, key_fingerprint)?;

        let (removed_entry, needs_resize) = match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let level = &mut self.levels[level_idx];
                let removed = unsafe { level.table.take(slot_idx) };
                if level.table.erase(slot_idx) {
                    level.tombstones += 1;
                }
                level.len -= 1;
                let needs_resize = level.tombstones > level.capacity() / 2;
                (removed, needs_resize)
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let primary = &mut self.special.primary;
                let removed = unsafe { primary.table.take(slot_idx) };
                if primary.table.erase(slot_idx) {
                    primary.tombstones += 1;
                }
                primary.len -= 1;
                self.special.total_len -= 1;
                let needs_resize = primary.tombstones > primary.table.capacity() / 2;
                (removed, needs_resize)
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let fallback = &mut self.special.fallback;
                let removed = unsafe { fallback.table.take(slot_idx) };
                if fallback.table.erase(slot_idx) {
                    fallback.tombstones += 1;
                }
                fallback.len -= 1;
                self.special.total_len -= 1;
                let needs_resize = fallback.tombstones > fallback.capacity() / 2;
                (removed, needs_resize)
            }
        };

        self.len -= 1;
        self.shrink_max_populated_level();
        if needs_resize {
            self.resize(self.capacity);
        }
        Some((removed_entry.key, removed_entry.value))
    }

    /// Borrowing iterator over `&K`. Order matches [`Self::iter`].
    #[must_use]
    pub fn keys(&self) -> Keys<'_, K, V, A> {
        Keys::new(self.iter())
    }

    /// Borrowing iterator over `&V`. Order matches [`Self::iter`].
    #[must_use]
    pub fn values(&self) -> Values<'_, K, V, A> {
        Values::new(self.iter())
    }

    /// Reference to the map's [`BuildHasher`].
    #[must_use]
    pub fn hasher(&self) -> &S {
        &self.hash_builder
    }

    #[must_use]
    pub fn iter(&self) -> FunnelIter<'_, K, V, A> {
        FunnelIter {
            tables: FunnelTables {
                levels: self.levels.iter(),
                primary: Some(&self.special.primary.table),
                fallback: Some(&self.special.fallback.table),
            },
            current: None,
            cursor: OccupiedCursor::new(),
            remaining: self.len,
        }
    }

    /// Mutable iterator yielding `(&K, &mut V)`. Mirrors `HashMap::iter_mut`.
    pub fn iter_mut(&mut self) -> FunnelIterMut<'_, K, V, A> {
        let levels_len = self.levels.len();
        let levels = self.levels.as_mut_ptr();
        let primary = ptr::from_mut(&mut self.special.primary);
        let fallback = ptr::from_mut(&mut self.special.fallback);
        let remaining = self.len;
        FunnelIterMut {
            levels,
            levels_len,
            primary,
            fallback,
            phase: FunnelIterPhase::Levels,
            level_idx: 0,
            cursor: OccupiedCursor::new(),
            remaining,
            _marker: PhantomData,
        }
    }

    /// Mutable iterator yielding `&mut V`. Mirrors `HashMap::values_mut`.
    pub fn values_mut(&mut self) -> FunnelValuesMut<'_, K, V, A> {
        FunnelValuesMut {
            inner: self.iter_mut(),
        }
    }

    /// Consuming iterator yielding owned keys. Mirrors `HashMap::into_keys`.
    #[must_use]
    pub fn into_keys(self) -> FunnelIntoKeys<K, V, S, A> {
        FunnelIntoKeys::new(self.into_iter())
    }

    /// Consuming iterator yielding owned values. Mirrors `HashMap::into_values`.
    #[must_use]
    pub fn into_values(self) -> FunnelIntoValues<K, V, S, A> {
        FunnelIntoValues::new(self.into_iter())
    }

    /// Returns an [`Entry`] for in-place manipulation of `key`'s slot.
    /// Mirrors [`std::collections::HashMap::entry`].
    pub fn entry(&mut self, key: K) -> Entry<'_, K, V, S, A> {
        let key_hash = self.hash_key(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        if let Some(location) = self.find_slot_location_with_hash(&key, key_hash, key_fingerprint) {
            Entry::Occupied(OccupiedEntry {
                map: self,
                location,
            })
        } else {
            Entry::Vacant(VacantEntry {
                map: self,
                key,
                key_hash,
            })
        }
    }

    /// Inserts `key`/`value` if absent. Mirrors the unstable
    /// [`std::collections::HashMap::try_insert`].
    ///
    /// # Errors
    ///
    /// Returns [`OccupiedError`] if `key` was already present.
    pub fn try_insert(
        &mut self,
        key: K,
        value: V,
    ) -> Result<&mut V, OccupiedError<'_, K, V, S, A>> {
        match self.entry(key) {
            Entry::Occupied(entry) => Err(OccupiedError { entry, value }),
            Entry::Vacant(entry) => Ok(entry.insert(value)),
        }
    }

    /// Post-lookup insert for a key known to be absent. Returns the chosen
    /// slot so the caller can borrow into it without re-probing.
    fn insert_for_vacant_entry(&mut self, key: K, value: V, key_hash: u64) -> SlotLocation {
        let key_fingerprint = control::control_fingerprint(key_hash);

        let mut location = if self.len < self.max_insertions {
            self.choose_slot_for_new_key(key_hash)
        } else {
            None
        };

        if location.is_none() {
            let new_capacity = if self.capacity == 0 {
                INITIAL_CAPACITY
            } else {
                self.capacity.saturating_mul(2)
            };
            self.resize(new_capacity);
            location = Some(
                self.choose_slot_for_new_key(key_hash)
                    .expect("no free slot found after resize"),
            );
        }

        let final_location = location.expect("location set above");
        self.place_new_entry(final_location, key, value, key_fingerprint);
        final_location
    }

    /// Drops every entry for which `f(&K, &mut V)` returns `false`.
    /// Mirrors [`std::collections::HashMap::retain`].
    pub fn retain<F>(&mut self, mut f: F)
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        self.extract_if(|k, v| !f(k, v)).for_each(drop);
    }

    /// Returns a draining iterator that empties the map. Mirrors
    /// [`std::collections::HashMap::drain`].
    pub fn drain(&mut self) -> Drain<'_, K, V, S, A> {
        Drain {
            map: self,
            phase: DrainPhase::Levels,
            level_idx: 0,
            cursor: OccupiedCursor::new(),
        }
    }

    /// Yields and removes `(K, V)` pairs where `f` returned `true`; kept
    /// entries remain in the map. Mirrors
    /// [`std::collections::HashMap::extract_if`].
    pub fn extract_if<F>(&mut self, f: F) -> ExtractIf<'_, K, V, F, S, A>
    where
        F: FnMut(&K, &mut V) -> bool,
    {
        ExtractIf {
            map: self,
            pred: f,
            phase: DrainPhase::Levels,
            level_idx: 0,
            cursor: OccupiedCursor::new(),
        }
    }

    pub fn clear(&mut self) {
        for level in &mut self.levels {
            for idx in 0..level.table.capacity() {
                if level.table.control_at(idx).is_occupied() {
                    unsafe { level.table.drop_in_place(idx) };
                }
            }
            level.table.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }

        for idx in 0..self.special.primary.table.capacity() {
            if self.special.primary.table.control_at(idx).is_occupied() {
                unsafe { self.special.primary.table.drop_in_place(idx) };
            }
        }
        self.special.primary.table.clear_all_controls();
        self.special.primary.len = 0;
        self.special.primary.tombstones = 0;

        for idx in 0..self.special.fallback.table.capacity() {
            if self.special.fallback.table.control_at(idx).is_occupied() {
                unsafe { self.special.fallback.table.drop_in_place(idx) };
            }
        }
        self.special.fallback.table.clear_all_controls();
        self.special.fallback.len = 0;
        self.special.fallback.tombstones = 0;
        self.special.total_len = 0;

        self.len = 0;
        self.max_populated_level = 0;
    }

    /// Fallible counterpart to [`Self::resize`]. Common path leaves `self`
    /// intact on `Err`; a failing 2x-retry allocation may empty `self`.
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        let mut target = new_capacity;
        let mut new_map = Self::try_with_slots_and_reserve_fraction_and_hasher_in(
            target,
            self.reserve_fraction,
            self.hash_builder.clone(),
            self.alloc.clone(),
        )?;

        let mut entries: Vec<(K, V)> = Vec::new();
        entries
            .try_reserve(self.len)
            .map_err(|_| TryReserveError::AllocError)?;
        self.drain_entries_into(&mut entries);

        loop {
            let mut overflow: Vec<(K, V)> = Vec::new();
            for (k, v) in entries.drain(..) {
                if let Err(pair) = new_map.try_insert_new_entry_unchecked(k, v) {
                    overflow.push(pair);
                }
            }
            if overflow.is_empty() {
                *self = new_map;
                return Ok(());
            }
            new_map.drain_entries_into(&mut overflow);
            entries = overflow;
            target = target
                .checked_mul(2)
                .ok_or(TryReserveError::CapacityOverflow)?;
            new_map = Self::try_with_slots_and_reserve_fraction_and_hasher_in(
                target,
                self.reserve_fraction,
                self.hash_builder.clone(),
                self.alloc.clone(),
            )?;
        }
    }

    /// Internal fallible ctor for `try_resize`. `slots` is raw slot count
    /// (already inflated by the caller); public ctors take an insertion
    /// budget and inflate via `capacity_for` — this one skips that.
    fn try_with_slots_and_reserve_fraction_and_hasher_in(
        slots: usize,
        reserve_fraction: f64,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let capacity = slots;
        let reserve_fraction =
            capacity::sanitize_reserve_fraction(reserve_fraction).min(MAX_FUNNEL_RESERVE_FRACTION);
        let max_insertions = capacity::max_insertions(capacity, reserve_fraction);

        let level_count = compute_level_count(reserve_fraction);
        let bucket_width = align::round_up_to_group(compute_bucket_width(reserve_fraction));
        let primary_probe_limit = probe::log_log_probe_limit(capacity).max(1);

        let mut special_capacity =
            choose_special_capacity(capacity, reserve_fraction, bucket_width);
        let mut main_capacity = capacity.saturating_sub(special_capacity);
        let main_remainder = main_capacity % bucket_width.max(1);
        if main_remainder != 0 {
            main_capacity = main_capacity.saturating_sub(main_remainder);
            special_capacity = capacity.saturating_sub(main_capacity);
        }

        let total_main_buckets = main_capacity.checked_div(bucket_width).unwrap_or(0);
        let level_bucket_counts = partition_funnel_buckets(total_main_buckets, level_count);
        let mut levels: Vec<BucketLevel<K, V, A>> = Vec::new();
        levels
            .try_reserve_exact(level_bucket_counts.len())
            .map_err(|_| TryReserveError::AllocError)?;
        for (level_idx, bucket_count) in level_bucket_counts.into_iter().enumerate() {
            levels.push(BucketLevel::try_with_bucket_count_in(
                bucket_count,
                bucket_width,
                math::level_salt(level_idx),
                alloc.clone(),
            )?);
        }
        let levels = levels.into_boxed_slice();

        let special = SpecialArray::try_with_capacity_in(
            special_capacity,
            primary_probe_limit,
            alloc.clone(),
        )?;

        Ok(Self {
            levels,
            special,
            len: 0,
            capacity,
            max_insertions,
            reserve_fraction,
            primary_probe_limit,
            max_populated_level: 0,
            hash_builder,
            alloc,
        })
    }

    /// Rebuild in-place at `new_capacity`. Doubles `new_capacity` on
    /// insert overflow (funnel's structural failure mode under adversarial
    /// hashing) until every entry places.
    fn resize(&mut self, mut new_capacity: usize) {
        let mut entries: Vec<(K, V)> = Vec::with_capacity(self.len);
        self.drain_entries_into(&mut entries);
        loop {
            self.install_fresh_storage(new_capacity);
            let mut overflow: Vec<(K, V)> = Vec::new();
            for (k, v) in entries.drain(..) {
                if let Err(pair) = self.try_insert_new_entry_unchecked(k, v) {
                    overflow.push(pair);
                }
            }
            if overflow.is_empty() {
                return;
            }
            entries = overflow;
            self.drain_entries_into(&mut entries);
            new_capacity = new_capacity
                .checked_mul(2)
                .expect("capacity overflow during funnel resize retry");
        }
    }

    /// Move every live entry into `out`; storage stays allocated but empty.
    fn drain_entries_into(&mut self, out: &mut Vec<(K, V)>) {
        for level in &mut self.levels {
            level.table.for_each_occupied_mut(|table, idx| {
                let entry = unsafe { table.take(idx) };
                out.push((entry.key, entry.value));
            });
            level.table.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        self.special
            .primary
            .table
            .for_each_occupied_mut(|table, idx| {
                let entry = unsafe { table.take(idx) };
                out.push((entry.key, entry.value));
            });
        self.special.primary.table.clear_all_controls();
        self.special.primary.len = 0;
        self.special.primary.tombstones = 0;
        self.special
            .fallback
            .table
            .for_each_occupied_mut(|table, idx| {
                let entry = unsafe { table.take(idx) };
                out.push((entry.key, entry.value));
            });
        self.special.fallback.table.clear_all_controls();
        self.special.fallback.len = 0;
        self.special.fallback.tombstones = 0;
        self.special.total_len = 0;
        self.len = 0;
        self.max_populated_level = 0;
    }

    /// Replace `self`'s tables with empty storage sized for `new_capacity`.
    fn install_fresh_storage(&mut self, new_capacity: usize) {
        let level_count = compute_level_count(self.reserve_fraction);
        let bucket_width = align::round_up_to_group(compute_bucket_width(self.reserve_fraction));
        let mut special_capacity =
            choose_special_capacity(new_capacity, self.reserve_fraction, bucket_width);
        let mut main_capacity = new_capacity.saturating_sub(special_capacity);
        let main_remainder = main_capacity % bucket_width.max(1);
        if main_remainder != 0 {
            main_capacity = main_capacity.saturating_sub(main_remainder);
            special_capacity = new_capacity.saturating_sub(main_capacity);
        }
        let total_main_buckets = main_capacity.checked_div(bucket_width).unwrap_or(0);
        let level_bucket_counts = partition_funnel_buckets(total_main_buckets, level_count);
        let new_levels: Box<[BucketLevel<K, V, A>]> = level_bucket_counts
            .into_iter()
            .enumerate()
            .map(|(level_idx, bucket_count)| {
                BucketLevel::with_bucket_count_in(
                    bucket_count,
                    bucket_width,
                    math::level_salt(level_idx),
                    self.alloc.clone(),
                )
            })
            .collect();
        let new_primary_probe_limit = probe::log_log_probe_limit(new_capacity).max(1);
        let new_special = SpecialArray::with_capacity_in(
            special_capacity,
            new_primary_probe_limit,
            self.alloc.clone(),
        );
        self.levels = new_levels;
        self.special = new_special;
        self.capacity = new_capacity;
        self.max_insertions = capacity::max_insertions(new_capacity, self.reserve_fraction);
        self.primary_probe_limit = new_primary_probe_limit;
        self.max_populated_level = 0;
    }

    #[inline]
    fn hash_key<Q>(&self, key: &Q) -> u64
    where
        Q: Hash + ?Sized,
    {
        self.hash_builder.hash_one(key)
    }

    /// Paper §5 insertion chain: attempt `L_1`, `L_2`, …, `L_α` in order,
    /// stopping on the first level whose hashed bucket has a free slot;
    /// spill to `A_{α+1}`.
    #[inline]
    fn choose_slot_for_new_key(&self, key_hash: u64) -> Option<SlotLocation> {
        for (level_idx, level) in self.levels.iter().enumerate() {
            if let Some(slot_idx) = level.first_free_in_bucket(key_hash) {
                return Some(SlotLocation::Level {
                    level_idx,
                    slot_idx,
                });
            }
        }

        if let Some(slot_idx) = self.first_free_in_special_primary(key_hash) {
            return Some(SlotLocation::SpecialPrimary { slot_idx });
        }

        self.first_free_in_special_fallback(key_hash)
            .map(|slot_idx| SlotLocation::SpecialFallback { slot_idx })
    }

    /// Paper §5: walk `A_1..A_α` in order, stopping on the first `StopSearch`.
    /// `Candidate::Track` records the earliest level's free slot so inserts
    /// spill into deeper bucket levels before reaching the special array.
    /// Returns `(match, chain_clean)` where `chain_clean = true` means the
    /// probe chain terminated via a clean EMPTY byte — the key cannot exist
    /// in the special array.
    #[inline]
    fn find_in_levels<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
        candidate: Candidate<'_, SlotLocation>,
    ) -> (Option<SlotLocation>, bool)
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let wants_free = candidate.wants_free();
        let mut local: Option<SlotLocation> = None;
        let mut chain_clean = false;

        for (level_idx, level) in self.levels.iter().enumerate() {
            // Per-level slot tracking, only while we still want a candidate.
            let mut slot_candidate: Option<usize> = None;
            let level_mode = if wants_free && local.is_none() {
                Candidate::Track(&mut slot_candidate)
            } else {
                Candidate::Lookup
            };
            let lookup_step = level.find_in_bucket(key_hash, key_fingerprint, key, level_mode);
            if let Some(slot_idx) = slot_candidate {
                local = Some(SlotLocation::Level {
                    level_idx,
                    slot_idx,
                });
            }
            match lookup_step {
                LookupStep::Found(slot_idx) => {
                    return (
                        Some(SlotLocation::Level {
                            level_idx,
                            slot_idx,
                        }),
                        false,
                    );
                }
                LookupStep::Continue => {}
                LookupStep::StopSearch => {
                    chain_clean = true;
                    break;
                }
            }
        }

        candidate.record(local);
        (None, chain_clean)
    }

    /// Scan special primary then fallback for `key`. Updates `candidate` with
    /// the first free slot seen. Returns `Some(location)` if the key is found.
    ///
    /// Marked `#[cold]` + `#[inline(never)]` to keep this out of the hot
    /// insert path and give the branch predictor a miss-rate hint.
    #[cold]
    #[inline(never)]
    fn scan_special_for_key<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
        candidate: &mut Option<SlotLocation>,
    ) -> Option<SlotLocation>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        match self.find_in_special_primary(
            key_hash,
            key_fingerprint,
            key,
            Candidate::Track(candidate),
        ) {
            LookupStep::Found(slot_idx) => {
                return Some(SlotLocation::SpecialPrimary { slot_idx });
            }
            LookupStep::StopSearch => {}
            LookupStep::Continue => {
                if let Some(slot_idx) = self.find_in_special_fallback(
                    key_hash,
                    key_fingerprint,
                    key,
                    Candidate::Track(candidate),
                ) {
                    return Some(SlotLocation::SpecialFallback { slot_idx });
                }
            }
        }
        None
    }

    #[inline]
    fn replace_existing_value(&mut self, location: SlotLocation, value: V) -> V {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let entry = unsafe { self.levels[level_idx].table.get_mut(slot_idx) };
                mem::replace(&mut entry.value, value)
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let entry = unsafe { self.special.primary.table.get_mut(slot_idx) };
                mem::replace(&mut entry.value, value)
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let entry = unsafe { self.special.fallback.table.get_mut(slot_idx) };
                mem::replace(&mut entry.value, value)
            }
        }
    }

    /// Place a known-novel `key`/`value`. Returns `Err((key, value))` if no
    /// slot is available; the resize loop reclaims and retries at 2x.
    #[inline]
    fn try_insert_new_entry_unchecked(&mut self, key: K, value: V) -> Result<(), (K, V)> {
        let key_hash = self.hash_key(&key);
        let key_fingerprint = control::control_fingerprint(key_hash);
        let Some(location) = self.choose_slot_for_new_key(key_hash) else {
            return Err((key, value));
        };
        self.place_new_entry(location, key, value, key_fingerprint);
        Ok(())
    }

    #[inline]
    /// Insert `key`/`value` into a candidate slot, growing first via
    /// `resize` if `len >= max_insertions`. After resize, the candidate
    /// becomes stale, so this re-locates the slot from scratch.
    fn insert_at_location_after_resize_check(
        &mut self,
        location: Option<SlotLocation>,
        key_hash: u64,
        key: K,
        value: V,
        key_fingerprint: u8,
    ) -> Option<V> {
        let final_location = if self.len >= self.max_insertions || location.is_none() {
            let new_capacity = if self.capacity == 0 {
                INITIAL_CAPACITY
            } else {
                self.capacity.saturating_mul(2)
            };
            self.resize(new_capacity);
            self.choose_slot_for_new_key(key_hash)
                .expect("no free slot found after resize")
        } else {
            match location {
                Some(location) => location,
                None => unreachable!("checked for resize above"),
            }
        };

        self.place_new_entry(final_location, key, value, key_fingerprint);
        None
    }

    #[inline]
    fn place_new_entry(&mut self, location: SlotLocation, key: K, value: V, key_fingerprint: u8) {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let level = &mut self.levels[level_idx];
                level
                    .table
                    .write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
                level.len += 1;
                if level_idx > self.max_populated_level {
                    self.max_populated_level = level_idx;
                }
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let primary = &mut self.special.primary;
                // Reusing a tombstone slot must decrement the counter;
                // otherwise resize triggers on stale-since-resize counts.
                let was_tombstone = primary.table.control_at(slot_idx) == CTRL_TOMBSTONE;
                primary.table.write_with_control(
                    slot_idx,
                    SlotEntry { key, value },
                    key_fingerprint,
                );
                primary.len += 1;
                if was_tombstone {
                    primary.tombstones -= 1;
                }
                self.special.total_len += 1;
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let fallback = &mut self.special.fallback;
                fallback.table.write_with_control(
                    slot_idx,
                    SlotEntry { key, value },
                    key_fingerprint,
                );
                fallback.len += 1;
                self.special.total_len += 1;
            }
        }
        self.len += 1;
    }

    fn first_free_in_special_primary(&self, key_hash: u64) -> Option<usize> {
        let primary = &self.special.primary;
        if primary.len >= primary.table.capacity() {
            return None;
        }

        let group_count = primary.table.group_count();
        let group_limit = self.primary_probe_limit.min(group_count.max(1));
        let mask = primary.group_count_mask;
        let mut probe = ProbeSeq::new(primary.group_start(key_hash), primary.group_step(key_hash));
        for _ in 0..group_limit {
            if let Some(slot_idx) = primary.first_free_in_group(probe.group) {
                return Some(slot_idx);
            }
            probe.advance(mask);
        }
        None
    }

    fn first_free_in_special_fallback(&self, key_hash: u64) -> Option<usize> {
        let fallback = &self.special.fallback;
        if fallback.len >= fallback.capacity() {
            return None;
        }

        let bucket_a = fallback.bucket_a(key_hash);
        let bucket_b = fallback.bucket_b(key_hash);

        for &bucket_idx in &[bucket_a, bucket_b] {
            let range = fallback.bucket_range(bucket_idx);
            for slot_idx in range {
                if fallback.table.control_at(slot_idx).is_free() {
                    return Some(slot_idx);
                }
            }
        }

        None
    }

    /// Probe special primary for `key`. Bounded by `primary_probe_limit`
    /// groups; if reached without a match and no tombstones seen, returns
    /// `StopSearch` so the caller skips fallback. See [`Candidate`] for
    /// tracking modes.
    #[inline]
    fn find_in_special_primary<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        candidate: Candidate<'_, SlotLocation>,
    ) -> LookupStep
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let wants_free = candidate.wants_free();
        let primary = &self.special.primary;

        if primary.table.capacity() == 0 || primary.len == 0 {
            if wants_free {
                let slot = self
                    .first_free_in_special_primary(key_hash)
                    .map(|slot_idx| SlotLocation::SpecialPrimary { slot_idx });
                candidate.record(slot);
            }
            return LookupStep::Continue;
        }

        let group_count = primary.table.group_count();
        let group_limit = self.primary_probe_limit.min(group_count.max(1));
        let mask = primary.group_count_mask;
        let mut local: Option<usize> = None;
        let mut probe = ProbeSeq::new(primary.group_start(key_hash), primary.group_step(key_hash));

        let outcome: LookupStep = 'probe: {
            for _ in 0..group_limit {
                // Track free slots only when asked AND we don't already have
                // one. `first_free_in_group` doubles as the "any free?" check;
                // when not tracking we use the cheaper EMPTY-only mask.
                let has_free = if wants_free && local.is_none() {
                    let slot = primary.table.first_free_in_group(probe.group);
                    if let Some(s) = slot {
                        local = Some(s);
                    }
                    slot.is_some()
                } else {
                    primary
                        .table
                        .group_match_mask(probe.group, CTRL_EMPTY)
                        .any()
                };
                for relative_idx in primary.table.group_match_mask(probe.group, key_fingerprint) {
                    let slot_idx = probe.group * GROUP_SIZE + relative_idx;
                    let entry = unsafe { primary.table.get_ref(slot_idx) };
                    if entry.key.borrow() == key {
                        break 'probe LookupStep::Found(slot_idx);
                    }
                }
                // StopSearch: probe chain terminated naturally — an EMPTY
                // slot in the group, with no TOMBSTONE that might be hiding
                // an overflow we'd need to chase.
                if has_free
                    && !primary
                        .table
                        .group_match_mask(probe.group, CTRL_TOMBSTONE)
                        .any()
                {
                    break 'probe LookupStep::StopSearch;
                }
                probe.advance(mask);
            }
            LookupStep::Continue
        };

        if wants_free {
            candidate.record(local.map(|slot_idx| SlotLocation::SpecialPrimary { slot_idx }));
        }
        outcome
    }

    /// Probe special fallback for `key` across its two candidate buckets.
    /// See [`Candidate`] for tracking modes.
    #[inline]
    fn find_in_special_fallback<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        candidate: Candidate<'_, SlotLocation>,
    ) -> Option<usize>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let wants_free = candidate.wants_free();
        let fallback = &self.special.fallback;

        if fallback.table.capacity() == 0 || fallback.len == 0 {
            if wants_free {
                let slot = self
                    .first_free_in_special_fallback(key_hash)
                    .map(|slot_idx| SlotLocation::SpecialFallback { slot_idx });
                candidate.record(slot);
            }
            return None;
        }

        let bucket_a = fallback.bucket_a(key_hash);
        let bucket_b = fallback.bucket_b(key_hash);

        let mut local: Option<usize> = None;
        let mut found: Option<usize> = None;
        for bucket_idx in [bucket_a, bucket_b] {
            let need_match = found.is_none();
            let need_candidate = wants_free && local.is_none();
            if !need_match && !need_candidate {
                break;
            }
            let range = fallback.bucket_range(bucket_idx);
            if need_candidate {
                for slot_idx in range.clone() {
                    if fallback.table.control_at(slot_idx).is_free() {
                        local = Some(slot_idx);
                        break;
                    }
                }
            }
            if need_match {
                let controls = unsafe {
                    std::slice::from_raw_parts(
                        fallback.table.group_data_ptr(0).add(range.start),
                        range.len(),
                    )
                };
                let mut match_offset = 0;
                while let Some(relative_idx) = control::find_next_fingerprint_in_controls(
                    controls,
                    key_fingerprint,
                    match_offset,
                ) {
                    let slot_idx = range.start + relative_idx;
                    let entry = unsafe { fallback.table.get_ref(slot_idx) };
                    if entry.key.borrow() == key {
                        found = Some(slot_idx);
                        break;
                    }
                    match_offset = relative_idx + 1;
                }
            }
        }

        if wants_free {
            candidate.record(local.map(|slot_idx| SlotLocation::SpecialFallback { slot_idx }));
        }
        found
    }

    #[inline]
    fn find_slot_location_with_hash<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> Option<SlotLocation>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        match self.levels[0].find_in_bucket(key_hash, key_fingerprint, key, Candidate::Lookup) {
            LookupStep::Found(slot_idx) => {
                return Some(SlotLocation::Level {
                    level_idx: 0,
                    slot_idx,
                });
            }
            LookupStep::Continue => {}
            LookupStep::StopSearch => return None,
        }

        // L1+ is empty in steady state at default load; outline only when populated.
        if self.max_populated_level > 0
            && let ControlFlow::Break(result) =
                self.find_in_higher_levels(key, key_hash, key_fingerprint)
        {
            return result;
        }

        // Special tables — only populated under overflow.
        if self.special.total_len == 0 {
            return None;
        }

        self.find_in_special_outline(key_hash, key_fingerprint, key)
    }

    #[cold]
    #[inline(never)]
    fn find_in_higher_levels<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> ControlFlow<Option<SlotLocation>>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let search_limit = (self.max_populated_level + 1).min(self.levels.len());
        for (offset, level) in self.levels[1..search_limit].iter().enumerate() {
            match level.find_in_bucket(key_hash, key_fingerprint, key, Candidate::Lookup) {
                LookupStep::Found(slot_idx) => {
                    return ControlFlow::Break(Some(SlotLocation::Level {
                        level_idx: offset + 1,
                        slot_idx,
                    }));
                }
                LookupStep::Continue => {}
                LookupStep::StopSearch => return ControlFlow::Break(None),
            }
        }
        ControlFlow::Continue(())
    }

    #[cold]
    #[inline(never)]
    fn find_in_special_outline<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
    ) -> Option<SlotLocation>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        match self.find_in_special_primary(key_hash, key_fingerprint, key, Candidate::Lookup) {
            LookupStep::Found(slot_idx) => return Some(SlotLocation::SpecialPrimary { slot_idx }),
            LookupStep::Continue => {}
            LookupStep::StopSearch => return None,
        }

        self.find_in_special_fallback(key_hash, key_fingerprint, key, Candidate::Lookup)
            .map(|slot_idx| SlotLocation::SpecialFallback { slot_idx })
    }

    fn shrink_max_populated_level(&mut self) {
        while self.max_populated_level > 0 && self.levels[self.max_populated_level].len == 0 {
            self.max_populated_level -= 1;
        }
    }
}

/// A view into a single entry in a [`FunnelHashMap`], which may be either
/// vacant or occupied. Constructed via [`FunnelHashMap::entry`].
pub enum Entry<'a, K: 'a, V: 'a, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    /// Slot is occupied; key already lives in the map.
    Occupied(OccupiedEntry<'a, K, V, S, A>),
    /// Slot is vacant; the supplied key does not exist in the map yet.
    Vacant(VacantEntry<'a, K, V, S, A>),
}

/// View of an occupied entry in a [`FunnelHashMap`].
pub struct OccupiedEntry<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: &'a mut FunnelHashMap<K, V, S, A>,
    location: SlotLocation,
}

impl<'a, K, V, S, A> OccupiedEntry<'a, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Returns a reference to the entry's key.
    #[must_use]
    pub fn key(&self) -> &K {
        match self.location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { &self.map.levels[level_idx].table.get_ref(slot_idx).key },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                &self.map.special.primary.table.get_ref(slot_idx).key
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                &self.map.special.fallback.table.get_ref(slot_idx).key
            },
        }
    }

    /// Returns a reference to the entry's value.
    #[must_use]
    pub fn get(&self) -> &V {
        match self.location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { &self.map.levels[level_idx].table.get_ref(slot_idx).value },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                &self.map.special.primary.table.get_ref(slot_idx).value
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                &self.map.special.fallback.table.get_ref(slot_idx).value
            },
        }
    }

    /// Returns `&mut V`. Borrow is tied to `self`; for the map's lifetime
    /// use [`OccupiedEntry::into_mut`].
    pub fn get_mut(&mut self) -> &mut V {
        match self.location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { &mut self.map.levels[level_idx].table.get_mut(slot_idx).value },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                &mut self.map.special.primary.table.get_mut(slot_idx).value
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                &mut self.map.special.fallback.table.get_mut(slot_idx).value
            },
        }
    }

    /// Consumes the entry and returns `&mut V` borrowed from the map.
    #[must_use]
    pub fn into_mut(self) -> &'a mut V {
        match self.location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { &mut self.map.levels[level_idx].table.get_mut(slot_idx).value },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                &mut self.map.special.primary.table.get_mut(slot_idx).value
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                &mut self.map.special.fallback.table.get_mut(slot_idx).value
            },
        }
    }

    /// Replaces the entry's value and returns the old one.
    pub fn insert(&mut self, value: V) -> V {
        self.map.replace_existing_value(self.location, value)
    }

    /// Removes the entry and returns its value.
    #[must_use]
    pub fn remove(self) -> V {
        self.remove_entry().1
    }

    /// Removes the entry and returns the `(key, value)` pair.
    #[must_use]
    pub fn remove_entry(self) -> (K, V) {
        let (removed_entry, needs_resize) = match self.location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let level = &mut self.map.levels[level_idx];
                let removed = unsafe { level.table.take(slot_idx) };
                if level.table.erase(slot_idx) {
                    level.tombstones += 1;
                }
                level.len -= 1;
                let needs_resize = level.tombstones > level.capacity() / 2;
                (removed, needs_resize)
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                let special = &mut self.map.special;
                let primary = &mut special.primary;
                let removed = unsafe { primary.table.take(slot_idx) };
                if primary.table.erase(slot_idx) {
                    primary.tombstones += 1;
                }
                primary.len -= 1;
                special.total_len -= 1;
                let needs_resize = primary.tombstones > primary.table.capacity() / 2;
                (removed, needs_resize)
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                let special = &mut self.map.special;
                let fallback = &mut special.fallback;
                let removed = unsafe { fallback.table.take(slot_idx) };
                if fallback.table.erase(slot_idx) {
                    fallback.tombstones += 1;
                }
                fallback.len -= 1;
                special.total_len -= 1;
                let needs_resize = fallback.tombstones > fallback.capacity() / 2;
                (removed, needs_resize)
            }
        };

        self.map.len -= 1;
        self.map.shrink_max_populated_level();
        if needs_resize {
            let capacity = self.map.capacity;
            self.map.resize(capacity);
        }
        (removed_entry.key, removed_entry.value)
    }
}

/// View of a vacant entry in a [`FunnelHashMap`].
pub struct VacantEntry<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: &'a mut FunnelHashMap<K, V, S, A>,
    key: K,
    key_hash: u64,
}

impl<'a, K, V, S, A> VacantEntry<'a, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Returns a reference to the key that would be inserted.
    pub fn key(&self) -> &K {
        &self.key
    }

    /// Consumes the entry and returns the key without inserting.
    #[must_use]
    pub fn into_key(self) -> K {
        self.key
    }

    /// Inserts `value` for the entry's key, returning `&mut V`.
    pub fn insert(self, value: V) -> &'a mut V {
        let location = self
            .map
            .insert_for_vacant_entry(self.key, value, self.key_hash);
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { &mut self.map.levels[level_idx].table.get_mut(slot_idx).value },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                &mut self.map.special.primary.table.get_mut(slot_idx).value
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                &mut self.map.special.fallback.table.get_mut(slot_idx).value
            },
        }
    }
}

impl<'a, K, V, S, A> Entry<'a, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Returns a mutable reference to the entry's value, inserting `default`
    /// first if vacant.
    pub fn or_insert(self, default: V) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default),
        }
    }

    /// Like [`Entry::or_insert`] but the default is computed lazily.
    pub fn or_insert_with<F: FnOnce() -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(default()),
        }
    }

    /// Like [`Entry::or_insert_with`] but the default closure receives a
    /// reference to the key.
    pub fn or_insert_with_key<F: FnOnce(&K) -> V>(self, default: F) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let value = default(entry.key());
                entry.insert(value)
            }
        }
    }

    /// Returns a reference to this entry's key.
    pub fn key(&self) -> &K {
        match self {
            Entry::Occupied(entry) => entry.key(),
            Entry::Vacant(entry) => entry.key(),
        }
    }

    /// Runs `f` against the value if the entry is occupied, then returns
    /// the entry for further chaining.
    #[must_use]
    pub fn and_modify<F: FnOnce(&mut V)>(self, f: F) -> Self {
        match self {
            Entry::Occupied(mut entry) => {
                f(entry.get_mut());
                Entry::Occupied(entry)
            }
            Entry::Vacant(entry) => Entry::Vacant(entry),
        }
    }
}

impl<'a, K, V, S, A> Entry<'a, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
    V: Default,
{
    /// Returns a mutable reference to the value, inserting `V::default()`
    /// first if vacant.
    pub fn or_default(self) -> &'a mut V {
        match self {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry.insert(V::default()),
        }
    }
}

/// Error returned by [`FunnelHashMap::try_insert`] on key collision.
pub type OccupiedError<'a, K, V, S = DefaultHashBuilder, A = Global> =
    CommonOccupiedError<OccupiedEntry<'a, K, V, S, A>, V>;

impl<K, V, S, A> EntryView for OccupiedEntry<'_, K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Key = K;
    type Value = V;
    fn view_key(&self) -> &K {
        self.key()
    }
    fn view_value(&self) -> &V {
        self.get()
    }
}

/// Three-phase iterator state: walk all bucket levels, then the special
/// primary, then the special fallback.
#[derive(Debug)]
enum FunnelIterPhase {
    Levels,
    Primary,
    Fallback,
    Done,
}

/// Iterator over the funnel's tables: each level, then primary, then fallback.
#[derive(Clone)]
struct FunnelTables<'a, K, V, A: Allocator + Clone> {
    levels: std::slice::Iter<'a, BucketLevel<K, V, A>>,
    primary: Option<&'a RawTable<SlotEntry<K, V>, A>>,
    fallback: Option<&'a RawTable<SlotEntry<K, V>, A>>,
}

impl<'a, K, V, A: Allocator + Clone> Iterator for FunnelTables<'a, K, V, A> {
    type Item = &'a RawTable<SlotEntry<K, V>, A>;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(level) = self.levels.next() {
            return Some(&level.table);
        }
        if let Some(t) = self.primary.take() {
            return Some(t);
        }
        self.fallback.take()
    }
}

impl<K, V, A: Allocator + Clone> fmt::Debug for FunnelTables<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunnelTables").finish_non_exhaustive()
    }
}

/// Borrowing iterator over occupied entries. Visits bucket levels → special
/// primary → special fallback. SIMD-scans one group at a time via
/// [`OccupiedCursor`], yielding bits from a cached mask before refilling.
#[derive(Clone)]
pub struct FunnelIter<'a, K, V, A: Allocator + Clone = Global> {
    tables: FunnelTables<'a, K, V, A>,
    current: Option<&'a RawTable<SlotEntry<K, V>, A>>,
    cursor: OccupiedCursor,
    remaining: usize,
}

impl<K, V, A: Allocator + Clone> fmt::Debug for FunnelIter<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunnelIter").finish_non_exhaustive()
    }
}

impl<'a, K, V, A: Allocator + Clone> Iterator for FunnelIter<'a, K, V, A> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let Some(table) = self.current else {
                self.current = Some(self.tables.next()?);
                self.cursor = OccupiedCursor::new();
                continue;
            };
            if let Some(slot_idx) = table.scan_next(&mut self.cursor) {
                let entry = unsafe { table.get_ref(slot_idx) };
                self.remaining -= 1;
                return Some((&entry.key, &entry.value));
            }
            self.current = None;
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, A: Allocator + Clone> ExactSizeIterator for FunnelIter<'_, K, V, A> {}
impl<K, V, A: Allocator + Clone> FusedIterator for FunnelIter<'_, K, V, A> {}

impl<'a, K, V, S, A> IntoIterator for &'a FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Item = (&'a K, &'a V);
    type IntoIter = FunnelIter<'a, K, V, A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Walk phase shared by `Drain` and `ExtractIf`: levels first, then the
/// special primary, then the special fallback.
enum DrainPhase {
    Levels,
    Primary,
    Fallback,
    Done,
}

/// Draining iterator. Yields and removes every `(K, V)` entry; the map is
/// empty once the iterator is consumed or dropped. Returned by
/// [`FunnelHashMap::drain`].
pub struct Drain<'a, K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: &'a mut FunnelHashMap<K, V, S, A>,
    phase: DrainPhase,
    level_idx: usize,
    cursor: OccupiedCursor,
}

impl<K: fmt::Debug, V: fmt::Debug, S, A: Allocator + Clone> fmt::Debug for Drain<'_, K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Drain").finish_non_exhaustive()
    }
}

impl<K, V, S, A: Allocator + Clone> Iterator for Drain<'_, K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        // Per-yield ctrl byte update is skipped: Drain::drop wipes all ctrls
        // via `clear_all_controls` regardless, and the scan only advances
        // forward so yielded slots are never re-read.
        loop {
            match self.phase {
                DrainPhase::Levels => {
                    while self.level_idx < self.map.levels.len() {
                        let level = &mut self.map.levels[self.level_idx];
                        if let Some(idx) = level.table.scan_next(&mut self.cursor) {
                            let entry = unsafe { level.table.take(idx) };
                            self.map.len -= 1;
                            return Some((entry.key, entry.value));
                        }
                        self.level_idx += 1;
                        self.cursor = OccupiedCursor::new();
                    }
                    self.phase = DrainPhase::Primary;
                    self.cursor = OccupiedCursor::new();
                }
                DrainPhase::Primary => {
                    let primary = &mut self.map.special.primary;
                    if let Some(idx) = primary.table.scan_next(&mut self.cursor) {
                        let entry = unsafe { primary.table.take(idx) };
                        self.map.len -= 1;
                        return Some((entry.key, entry.value));
                    }
                    self.phase = DrainPhase::Fallback;
                    self.cursor = OccupiedCursor::new();
                }
                DrainPhase::Fallback => {
                    let fallback = &mut self.map.special.fallback;
                    if let Some(idx) = fallback.table.scan_next(&mut self.cursor) {
                        let entry = unsafe { fallback.table.take(idx) };
                        self.map.len -= 1;
                        return Some((entry.key, entry.value));
                    }
                    self.phase = DrainPhase::Done;
                }
                DrainPhase::Done => return None,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.map.len, Some(self.map.len))
    }
}

impl<K, V, S, A: Allocator + Clone> ExactSizeIterator for Drain<'_, K, V, S, A> {}
impl<K, V, S, A: Allocator + Clone> FusedIterator for Drain<'_, K, V, S, A> {}

impl<K, V, S, A: Allocator + Clone> Drop for Drain<'_, K, V, S, A> {
    fn drop(&mut self) {
        // Drain any unyielded entries so values run their `Drop`.
        for _ in &mut *self {}
        // All entries moved out via `next()`; wipe ctrl bytes + counters en bloc.
        for level in &mut self.map.levels {
            level.table.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        self.map.special.primary.table.clear_all_controls();
        self.map.special.primary.len = 0;
        self.map.special.primary.tombstones = 0;
        self.map.special.fallback.table.clear_all_controls();
        self.map.special.fallback.len = 0;
        self.map.special.fallback.tombstones = 0;
        self.map.special.total_len = 0;
        self.map.len = 0;
        self.map.max_populated_level = 0;
    }
}

/// Filtering drain. Yields and removes entries for which the predicate
/// returns `true`; the rest stay in the map. Returned by
/// [`FunnelHashMap::extract_if`].
pub struct ExtractIf<'a, K, V, F, S = DefaultHashBuilder, A: Allocator + Clone = Global>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    map: &'a mut FunnelHashMap<K, V, S, A>,
    pred: F,
    phase: DrainPhase,
    level_idx: usize,
    cursor: OccupiedCursor,
}

impl<K, V, F, S, A: Allocator + Clone> fmt::Debug for ExtractIf<'_, K, V, F, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExtractIf").finish_non_exhaustive()
    }
}

impl<K, V, F, S, A: Allocator + Clone> Iterator for ExtractIf<'_, K, V, F, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.phase {
                DrainPhase::Levels => {
                    while self.level_idx < self.map.levels.len() {
                        let level = &mut self.map.levels[self.level_idx];
                        while let Some(idx) = level.table.scan_next(&mut self.cursor) {
                            // SAFETY: scan only yields occupied slots.
                            let entry = unsafe { level.table.get_mut(idx) };
                            if (self.pred)(&entry.key, &mut entry.value) {
                                let removed = unsafe { level.table.take(idx) };
                                if level.table.erase(idx) {
                                    level.tombstones += 1;
                                }
                                level.len -= 1;
                                self.map.len -= 1;
                                return Some((removed.key, removed.value));
                            }
                        }
                        self.level_idx += 1;
                        self.cursor = OccupiedCursor::new();
                    }
                    self.phase = DrainPhase::Primary;
                    self.cursor = OccupiedCursor::new();
                }
                DrainPhase::Primary => {
                    let primary = &mut self.map.special.primary;
                    while let Some(idx) = primary.table.scan_next(&mut self.cursor) {
                        let entry = unsafe { primary.table.get_mut(idx) };
                        if (self.pred)(&entry.key, &mut entry.value) {
                            let removed = unsafe { primary.table.take(idx) };
                            if primary.table.erase(idx) {
                                primary.tombstones += 1;
                            }
                            primary.len -= 1;
                            self.map.special.total_len -= 1;
                            self.map.len -= 1;
                            return Some((removed.key, removed.value));
                        }
                    }
                    self.phase = DrainPhase::Fallback;
                    self.cursor = OccupiedCursor::new();
                }
                DrainPhase::Fallback => {
                    let fallback = &mut self.map.special.fallback;
                    while let Some(idx) = fallback.table.scan_next(&mut self.cursor) {
                        let entry = unsafe { fallback.table.get_mut(idx) };
                        if (self.pred)(&entry.key, &mut entry.value) {
                            let removed = unsafe { fallback.table.take(idx) };
                            if fallback.table.erase(idx) {
                                fallback.tombstones += 1;
                            }
                            fallback.len -= 1;
                            self.map.special.total_len -= 1;
                            self.map.len -= 1;
                            return Some((removed.key, removed.value));
                        }
                    }
                    self.phase = DrainPhase::Done;
                }
                DrainPhase::Done => return None,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.map.len))
    }
}

impl<K, V, F, S, A: Allocator + Clone> Drop for ExtractIf<'_, K, V, F, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    F: FnMut(&K, &mut V) -> bool,
{
    fn drop(&mut self) {
        // Tombstones from extracted entries are left in place; subsequent
        // `remove` calls trigger consolidation when their threshold is crossed.
    }
}

/// `&K` iterator returned by [`FunnelHashMap::keys`].
pub type Keys<'a, K, V, A = Global> = CommonKeys<FunnelIter<'a, K, V, A>>;
/// `&V` iterator returned by [`FunnelHashMap::values`].
pub type Values<'a, K, V, A = Global> = CommonValues<FunnelIter<'a, K, V, A>>;

/// `(&K, &mut V)` iterator. Visits bucket levels → special primary →
/// special fallback. Skips FREE / TOMBSTONE.
///
/// SAFETY: raw pointers to each region + `PhantomData<&'a mut FunnelHashMap>`
/// tie the iterator to the map's exclusive borrow. Each `next()` returns a
/// borrow of a strictly newer slot ⇒ disjoint.
pub struct FunnelIterMut<'a, K, V, A: Allocator + Clone = Global> {
    levels: *mut BucketLevel<K, V, A>,
    levels_len: usize,
    primary: *mut SpecialPrimary<K, V, A>,
    fallback: *mut SpecialFallback<K, V, A>,
    phase: FunnelIterPhase,
    level_idx: usize,
    cursor: OccupiedCursor,
    remaining: usize,
    _marker: PhantomData<&'a mut SpecialArray<K, V, A>>,
}

// SAFETY: `FunnelIterMut` acts as an exclusive borrow of the underlying
// map regions for its lifetime, matching `&mut FunnelHashMap<K, V, S, A>`.
unsafe impl<K: Send, V: Send, A: Allocator + Clone + Send> Send for FunnelIterMut<'_, K, V, A> {}
unsafe impl<K: Sync, V: Sync, A: Allocator + Clone + Sync> Sync for FunnelIterMut<'_, K, V, A> {}

impl<'a, K, V, A: Allocator + Clone> Iterator for FunnelIterMut<'a, K, V, A> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.phase {
                FunnelIterPhase::Levels => {
                    while self.level_idx < self.levels_len {
                        // SAFETY: `level_idx < levels_len`, and `self.levels`
                        // points at a slice of `levels_len` initialized
                        // `BucketLevel`s owned by the borrowed map. We hold
                        // an exclusive borrow for `'a` (via PhantomData).
                        let level = unsafe { &mut *self.levels.add(self.level_idx) };
                        if let Some(idx) = level.table.scan_next(&mut self.cursor) {
                            // SAFETY: scan only yields occupied slots; each
                            // call yields a strictly newer slot, so borrows
                            // returned across calls are disjoint.
                            let entry = unsafe { level.table.get_mut(idx) };
                            let key: &'a K = unsafe { &*ptr::from_ref(&entry.key) };
                            let val: &'a mut V = unsafe { &mut *ptr::from_mut(&mut entry.value) };
                            self.remaining -= 1;
                            return Some((key, val));
                        }
                        self.level_idx += 1;
                        self.cursor = OccupiedCursor::new();
                    }
                    self.phase = FunnelIterPhase::Primary;
                    self.cursor = OccupiedCursor::new();
                }
                FunnelIterPhase::Primary => {
                    // SAFETY: `self.primary` points at the borrowed map's
                    // `SpecialPrimary` for `'a`.
                    let primary = unsafe { &mut *self.primary };
                    if let Some(idx) = primary.table.scan_next(&mut self.cursor) {
                        let entry = unsafe { primary.table.get_mut(idx) };
                        let key: &'a K = unsafe { &*ptr::from_ref(&entry.key) };
                        let val: &'a mut V = unsafe { &mut *ptr::from_mut(&mut entry.value) };
                        self.remaining -= 1;
                        return Some((key, val));
                    }
                    self.phase = FunnelIterPhase::Fallback;
                    self.cursor = OccupiedCursor::new();
                }
                FunnelIterPhase::Fallback => {
                    // SAFETY: same as the Primary arm, for `self.fallback`.
                    let fallback = unsafe { &mut *self.fallback };
                    if let Some(idx) = fallback.table.scan_next(&mut self.cursor) {
                        let entry = unsafe { fallback.table.get_mut(idx) };
                        let key: &'a K = unsafe { &*ptr::from_ref(&entry.key) };
                        let val: &'a mut V = unsafe { &mut *ptr::from_mut(&mut entry.value) };
                        self.remaining -= 1;
                        return Some((key, val));
                    }
                    self.phase = FunnelIterPhase::Done;
                }
                FunnelIterPhase::Done => return None,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl<K, V, A: Allocator + Clone> ExactSizeIterator for FunnelIterMut<'_, K, V, A> {}
impl<K, V, A: Allocator + Clone> FusedIterator for FunnelIterMut<'_, K, V, A> {}

impl<K, V, A: Allocator + Clone> fmt::Debug for FunnelIterMut<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunnelIterMut")
            .field("level_idx", &self.level_idx)
            .finish_non_exhaustive()
    }
}

impl<'a, K, V, S, A> IntoIterator for &'a mut FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Item = (&'a K, &'a mut V);
    type IntoIter = FunnelIterMut<'a, K, V, A>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

/// `&mut V` iterator returned by [`FunnelHashMap::values_mut`].
pub struct FunnelValuesMut<'a, K, V, A: Allocator + Clone = Global> {
    inner: FunnelIterMut<'a, K, V, A>,
}

impl<'a, K, V, A: Allocator + Clone> Iterator for FunnelValuesMut<'a, K, V, A> {
    type Item = &'a mut V;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|(_, v)| v)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
}

impl<K, V, A: Allocator + Clone> ExactSizeIterator for FunnelValuesMut<'_, K, V, A> {}
impl<K, V, A: Allocator + Clone> FusedIterator for FunnelValuesMut<'_, K, V, A> {}

impl<K, V, A: Allocator + Clone> fmt::Debug for FunnelValuesMut<'_, K, V, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunnelValuesMut")
            .field("level_idx", &self.inner.level_idx)
            .finish_non_exhaustive()
    }
}

/// Owned `(K, V)` iterator returned by `FunnelHashMap::into_iter`.
///
/// SAFETY: each yielded slot is immediately tombstoned, so the map's
/// `Drop` never revisits it. `Drop` drains the remainder per std semantics.
pub struct FunnelIntoIter<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    map: FunnelHashMap<K, V, S, A>,
    phase: FunnelIterPhase,
    level_idx: usize,
    cursor: OccupiedCursor,
}

impl<K, V, S, A: Allocator + Clone> Iterator for FunnelIntoIter<K, V, S, A> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.phase {
                FunnelIterPhase::Levels => {
                    while self.level_idx < self.map.levels.len() {
                        let table = &mut self.map.levels[self.level_idx].table;
                        if let Some(idx) = table.scan_next(&mut self.cursor) {
                            // SAFETY: scan only yields occupied indices.
                            // Tombstone-mark so the map's `Drop` skips it.
                            let entry = unsafe { table.take(idx) };
                            table.mark_tombstone(idx);
                            self.map.len -= 1;
                            return Some((entry.key, entry.value));
                        }
                        self.level_idx += 1;
                        self.cursor = OccupiedCursor::new();
                    }
                    self.phase = FunnelIterPhase::Primary;
                    self.cursor = OccupiedCursor::new();
                }
                FunnelIterPhase::Primary => {
                    let table = &mut self.map.special.primary.table;
                    if let Some(idx) = table.scan_next(&mut self.cursor) {
                        let entry = unsafe { table.take(idx) };
                        table.mark_tombstone(idx);
                        self.map.len -= 1;
                        return Some((entry.key, entry.value));
                    }
                    self.phase = FunnelIterPhase::Fallback;
                    self.cursor = OccupiedCursor::new();
                }
                FunnelIterPhase::Fallback => {
                    let table = &mut self.map.special.fallback.table;
                    if let Some(idx) = table.scan_next(&mut self.cursor) {
                        let entry = unsafe { table.take(idx) };
                        table.mark_tombstone(idx);
                        self.map.len -= 1;
                        return Some((entry.key, entry.value));
                    }
                    self.phase = FunnelIterPhase::Done;
                }
                FunnelIterPhase::Done => return None,
            }
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.map.len, Some(self.map.len))
    }
}

impl<K, V, S, A: Allocator + Clone> ExactSizeIterator for FunnelIntoIter<K, V, S, A> {}
impl<K, V, S, A: Allocator + Clone> FusedIterator for FunnelIntoIter<K, V, S, A> {}

impl<K, V, S, A: Allocator + Clone> Drop for FunnelIntoIter<K, V, S, A> {
    fn drop(&mut self) {
        // Drain the remainder so each owned `(K, V)` runs its `Drop`. After
        // this, the map's own `Drop` finds only tombstones and is a no-op
        // over the entries.
        for _ in self.by_ref() {}
    }
}

impl<K, V, S, A: Allocator + Clone> fmt::Debug for FunnelIntoIter<K, V, S, A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FunnelIntoIter")
            .field("phase", &self.phase)
            .field("level_idx", &self.level_idx)
            .finish_non_exhaustive()
    }
}

impl<K, V, S, A> IntoIterator for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Item = (K, V);
    type IntoIter = FunnelIntoIter<K, V, S, A>;

    fn into_iter(self) -> Self::IntoIter {
        FunnelIntoIter {
            map: self,
            phase: FunnelIterPhase::Levels,
            level_idx: 0,
            cursor: OccupiedCursor::new(),
        }
    }
}

/// Owned `K` iterator returned by [`FunnelHashMap::into_keys`].
pub type FunnelIntoKeys<K, V, S = DefaultHashBuilder, A = Global> =
    CommonIntoKeys<FunnelIntoIter<K, V, S, A>>;
/// Owned `V` iterator returned by [`FunnelHashMap::into_values`].
pub type FunnelIntoValues<K, V, S = DefaultHashBuilder, A = Global> =
    CommonIntoValues<FunnelIntoIter<K, V, S, A>>;

/// Raw-pointer projection from a `SlotLocation` to its value, without forming
/// any intermediate `&mut BucketLevel` / `&mut SpecialPrimary` /
/// `&mut SpecialFallback`. Used by `get_disjoint_mut*` to hand out disjoint
/// `&mut V` even when multiple keys live in the same sub-table.
///
/// # Safety
///
/// - `levels_ptr` must point to a live `[BucketLevel<K, V, A>]` whose `level_idx`
///   slot exists; same for `primary_ptr` / `fallback_ptr`.
/// - The `slot_idx` carried by `loc` must reference an occupied slot.
#[inline]
unsafe fn funnel_slot_value_ptr<K, V, A: Allocator + Clone>(
    levels_ptr: *mut BucketLevel<K, V, A>,
    primary_ptr: *mut SpecialPrimary<K, V, A>,
    fallback_ptr: *mut SpecialFallback<K, V, A>,
    loc: SlotLocation,
) -> *mut V {
    let (table_ptr, slot_idx) = match loc {
        SlotLocation::Level {
            level_idx,
            slot_idx,
        } => unsafe {
            let lvl_ptr = levels_ptr.add(level_idx);
            (&raw mut (*lvl_ptr).table, slot_idx)
        },
        SlotLocation::SpecialPrimary { slot_idx } => {
            (unsafe { &raw mut (*primary_ptr).table }, slot_idx)
        }
        SlotLocation::SpecialFallback { slot_idx } => {
            (unsafe { &raw mut (*fallback_ptr).table }, slot_idx)
        }
    };
    let entry_ptr: *mut SlotEntry<K, V> = unsafe { RawTable::slot_ptr_raw(table_ptr, slot_idx) };
    unsafe { &raw mut (*entry_ptr).value }
}

/// As [`funnel_slot_value_ptr`] but returns key + value pointers together.
#[inline]
unsafe fn funnel_slot_kv_ptrs<K, V, A: Allocator + Clone>(
    levels_ptr: *mut BucketLevel<K, V, A>,
    primary_ptr: *mut SpecialPrimary<K, V, A>,
    fallback_ptr: *mut SpecialFallback<K, V, A>,
    loc: SlotLocation,
) -> (*const K, *mut V) {
    let (table_ptr, slot_idx) = match loc {
        SlotLocation::Level {
            level_idx,
            slot_idx,
        } => unsafe {
            let lvl_ptr = levels_ptr.add(level_idx);
            (&raw mut (*lvl_ptr).table, slot_idx)
        },
        SlotLocation::SpecialPrimary { slot_idx } => {
            (unsafe { &raw mut (*primary_ptr).table }, slot_idx)
        }
        SlotLocation::SpecialFallback { slot_idx } => {
            (unsafe { &raw mut (*fallback_ptr).table }, slot_idx)
        }
    };
    let entry_ptr: *mut SlotEntry<K, V> = unsafe { RawTable::slot_ptr_raw(table_ptr, slot_idx) };
    let k_ptr: *const K = unsafe { &raw const (*entry_ptr).key };
    let v_ptr: *mut V = unsafe { &raw mut (*entry_ptr).value };
    (k_ptr, v_ptr)
}

/// O(N^2) alias check shared by `get_disjoint_mut` and
/// `get_disjoint_key_value_mut`. Panics if two `Some` locations collide.
#[inline]
fn check_disjoint_aliasing_funnel<const N: usize>(locations: &[Option<SlotLocation>; N]) {
    for (i, li) in locations.iter().enumerate() {
        let Some(li) = li else { continue };
        for other in &locations[i + 1..] {
            assert!(
                other.as_ref() != Some(li),
                "get_disjoint_mut: duplicate keys resolve to the same entry",
            );
        }
    }
}

/// Paper §5: `α = ⌈4 log δ⁻¹ + 10⌉` levels (excluding the special array).
fn compute_level_count(reserve_fraction: f64) -> usize {
    cast::ceil_to_usize((4.0 * (1.0 / reserve_fraction).log2() + 10.0).max(1.0))
}

/// Paper §5: `β = ⌈2 log δ⁻¹⌉` slots per bucket A_{i,j}.
fn compute_bucket_width(reserve_fraction: f64) -> usize {
    cast::ceil_to_usize((2.0 * (1.0 / reserve_fraction).log2()).max(1.0))
}

/// Paper §5: `⌈δn/2⌉ ≤ |A_{α+1}| ≤ ⌊3δn/4⌋`, with the main capacity
/// constrained to a multiple of `β` so each level is `β·a_i` slots.
fn choose_special_capacity(
    total_capacity: usize,
    reserve_fraction: f64,
    bucket_size: usize,
) -> usize {
    if total_capacity == 0 {
        return 0;
    }

    let total_capacity_f64 = cast::usize_to_f64(total_capacity);
    let lower_bound = cast::ceil_to_usize((reserve_fraction * total_capacity_f64) / 2.0);
    let upper_bound = cast::floor_to_usize((3.0 * reserve_fraction * total_capacity_f64) / 4.0);
    let lower_bound = lower_bound.min(total_capacity);
    let upper_bound = upper_bound.min(total_capacity);

    if lower_bound <= upper_bound {
        for special_capacity in (lower_bound..=upper_bound).rev() {
            if (total_capacity - special_capacity).is_multiple_of(bucket_size.max(1)) {
                return special_capacity;
            }
        }
    }

    let target = cast::round_to_usize(
        ((5.0 * reserve_fraction * total_capacity_f64) / 8.0).clamp(0.0, total_capacity_f64),
    );

    let mut best_special_capacity = total_capacity % bucket_size.max(1);
    let mut best_distance = usize::MAX;

    for main_capacity in (0..=total_capacity).step_by(bucket_size.max(1)) {
        let special_capacity = total_capacity - main_capacity;
        let distance = special_capacity.abs_diff(target);
        if distance < best_distance {
            best_distance = distance;
            best_special_capacity = special_capacity;
        }
    }

    // Paper §5: A_{α+1} must be non-empty. Floor at one bucket so the
    // cascade always has a final landing spot.
    if best_special_capacity == 0 {
        best_special_capacity = bucket_size.min(total_capacity);
    }
    best_special_capacity
}

/// Paper §5: split `α` levels with `a_{i+1} = 3a_i/4 ± 1`, geometrically decreasing.
/// Output is monotone non-increasing so `L0` is always the largest.
fn partition_funnel_buckets(total_buckets: usize, level_count: usize) -> Vec<usize> {
    if level_count == 0 {
        return Vec::new();
    }

    if total_buckets == 0 {
        return vec![0; level_count];
    }

    let first_level_guess = {
        let ratio = 0.75f64;
        let denom = 1.0 - ratio.powi(i32::try_from(level_count).expect("level count fits in i32"));
        if denom <= 0.0 {
            total_buckets.max(1)
        } else {
            cast::round_to_usize(
                (((cast::usize_to_f64(total_buckets)) * (1.0 - ratio)) / denom).max(0.0),
            )
        }
    };

    for radius in 0..=total_buckets {
        let lower = first_level_guess.saturating_sub(radius);
        if let Some(bucket_counts) = build_funnel_bucket_sequence(total_buckets, level_count, lower)
        {
            return bucket_counts;
        }

        let upper = first_level_guess.saturating_add(radius).min(total_buckets);
        if upper != lower
            && let Some(bucket_counts) =
                build_funnel_bucket_sequence(total_buckets, level_count, upper)
        {
            return bucket_counts;
        }
    }

    let mut fallback_counts = vec![0; level_count];
    fallback_counts[0] = total_buckets;
    fallback_counts
}

fn build_funnel_bucket_sequence(
    total_buckets: usize,
    level_count: usize,
    first_level_bucket_count: usize,
) -> Option<Vec<usize>> {
    if level_count == 0 || first_level_bucket_count > total_buckets {
        return None;
    }

    let mut bucket_counts = Vec::with_capacity(level_count);
    bucket_counts.push(first_level_bucket_count);
    let mut remaining = total_buckets.saturating_sub(first_level_bucket_count);
    let mut previous_bucket_count = first_level_bucket_count;

    for level_idx in 1..level_count {
        let levels_after = level_count - level_idx - 1;
        let (min_next_bucket_count, max_next_bucket_count) =
            next_bucket_count_bounds(previous_bucket_count);
        let ideal_next_bucket_count = ((3 * previous_bucket_count + 2) / 4)
            .clamp(min_next_bucket_count, max_next_bucket_count);

        let mut chosen_bucket_count = None;
        let mut best_distance = usize::MAX;
        let candidate_upper_bound = max_next_bucket_count.min(remaining);
        for candidate_bucket_count in min_next_bucket_count..=candidate_upper_bound {
            let remaining_after_candidate = remaining - candidate_bucket_count;
            let (tail_min_sum, tail_max_sum) =
                possible_tail_sum_range(candidate_bucket_count, levels_after);
            if remaining_after_candidate < tail_min_sum || remaining_after_candidate > tail_max_sum
            {
                continue;
            }

            let distance = candidate_bucket_count.abs_diff(ideal_next_bucket_count);
            if distance < best_distance {
                best_distance = distance;
                chosen_bucket_count = Some(candidate_bucket_count);
                if distance == 0 {
                    break;
                }
            }
        }
        let chosen_bucket_count = chosen_bucket_count?;

        bucket_counts.push(chosen_bucket_count);
        remaining -= chosen_bucket_count;
        previous_bucket_count = chosen_bucket_count;
    }

    if remaining == 0 {
        Some(bucket_counts)
    } else {
        None
    }
}

fn next_bucket_count_bounds(current_bucket_count: usize) -> (usize, usize) {
    let scaled = current_bucket_count.saturating_mul(3);
    let min_next_bucket_count = scaled.saturating_sub(4).div_ceil(4);
    let max_next_bucket_count = (scaled.saturating_add(4) / 4).min(current_bucket_count);
    (
        min_next_bucket_count,
        max_next_bucket_count.max(min_next_bucket_count),
    )
}

fn possible_tail_sum_range(start_bucket_count: usize, levels_after: usize) -> (usize, usize) {
    let mut min_sum = 0;
    let mut max_sum = 0;
    let mut min_previous = start_bucket_count;
    let mut max_previous = start_bucket_count;

    for _ in 0..levels_after {
        let (next_min, _) = next_bucket_count_bounds(min_previous);
        let (_, next_max) = next_bucket_count_bounds(max_previous);
        min_sum += next_min;
        max_sum += next_max;
        min_previous = next_min;
        max_previous = next_max;
    }

    (min_sum, max_sum)
}

impl<K, V, S, A> Clone for FunnelHashMap<K, V, S, A>
where
    K: Clone,
    V: Clone,
    S: Clone,
    A: Allocator + Clone,
{
    fn clone(&self) -> Self {
        Self {
            levels: self.levels.clone(),
            special: self.special.clone(),
            len: self.len,
            capacity: self.capacity,
            max_insertions: self.max_insertions,
            reserve_fraction: self.reserve_fraction,
            primary_probe_limit: self.primary_probe_limit,
            max_populated_level: self.max_populated_level,
            hash_builder: self.hash_builder.clone(),
            alloc: self.alloc.clone(),
        }
    }

    fn clone_from(&mut self, source: &Self) {
        // Fast path: reuse every per-level + special allocation when shapes match.
        let shape_matches = self.capacity == source.capacity
            && self.levels.len() == source.levels.len()
            && self
                .levels
                .iter()
                .zip(source.levels.iter())
                .all(|(a, b)| a.table.capacity() == b.table.capacity())
            && self.special.primary.table.capacity() == source.special.primary.table.capacity()
            && self.special.fallback.table.capacity() == source.special.fallback.table.capacity();
        if !shape_matches {
            *self = source.clone();
            return;
        }
        for (dst, src) in self.levels.iter_mut().zip(source.levels.iter()) {
            dst.clone_from(src);
        }
        self.special.clone_from(&source.special);
        self.len = source.len;
        self.max_insertions = source.max_insertions;
        self.reserve_fraction = source.reserve_fraction;
        self.primary_probe_limit = source.primary_probe_limit;
        self.max_populated_level = source.max_populated_level;
        self.hash_builder.clone_from(&source.hash_builder);
    }
}

impl<K, V, S, A> PartialEq for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    V: PartialEq,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn eq(&self, other: &Self) -> bool {
        if self.len() != other.len() {
            return false;
        }
        self.iter()
            .all(|(k, v)| other.get(k).is_some_and(|ov| *v == *ov))
    }
}

impl<K, V, S, A> Eq for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    V: Eq,
    S: BuildHasher,
    A: Allocator + Clone,
{
}

impl<K, Q, V, S, A> std::ops::Index<&Q> for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash + Borrow<Q>,
    Q: Eq + Hash + ?Sized,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Output = V;

    #[inline]
    fn index(&self, key: &Q) -> &V {
        self.get(key).expect("no entry found for key")
    }
}

impl<K, V, S, A> Extend<(K, V)> for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn extend<I: IntoIterator<Item = (K, V)>>(&mut self, iter: I) {
        let iter = iter.into_iter();
        let (lo, _) = iter.size_hint();
        if lo > 0 {
            self.reserve(lo);
        }
        for (k, v) in iter {
            self.insert(k, v);
        }
    }
}

impl<'a, K, V, S, A> Extend<(&'a K, &'a V)> for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash + Copy,
    V: Copy,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn extend<I: IntoIterator<Item = (&'a K, &'a V)>>(&mut self, iter: I) {
        self.extend(iter.into_iter().map(|(k, v)| (*k, *v)));
    }
}

impl<'a, K, V, S, A> Extend<&'a (K, V)> for FunnelHashMap<K, V, S, A>
where
    K: Eq + Hash + Copy,
    V: Copy,
    S: BuildHasher,
    A: Allocator + Clone,
{
    fn extend<I: IntoIterator<Item = &'a (K, V)>>(&mut self, iter: I) {
        self.extend(iter.into_iter().copied());
    }
}

impl<K, V, S> FromIterator<(K, V)> for FunnelHashMap<K, V, S, Global>
where
    K: Eq + Hash,
    S: BuildHasher + Default,
{
    fn from_iter<I: IntoIterator<Item = (K, V)>>(iter: I) -> Self {
        let iter = iter.into_iter();
        let (lo, _) = iter.size_hint();
        let mut map = Self::with_capacity_and_hasher(lo, S::default());
        map.extend(iter);
        map
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn funnel_layout_covers_capacity() {
        // `with_capacity(n)` interprets `n` as the insertion budget. Internal
        // slot allocation rounds up so `capacity() >= n` and total slots
        // (level + special) cover that budget.
        let requested = 257;
        let map: FunnelHashMap<i32, i32> = FunnelHashMap::with_capacity(requested);
        assert!(
            map.capacity() >= requested,
            "capacity={} below requested={requested}",
            map.capacity()
        );
        let level_capacity: usize = map.levels.iter().map(BucketLevel::capacity).sum();
        let special_capacity =
            map.special.primary.table.capacity() + map.special.fallback.table.capacity();
        let total = level_capacity + special_capacity;
        assert!(
            total >= requested,
            "total={total} below requested={requested}"
        );
    }

    #[test]
    fn partition_buckets_monotone_paper_invariant() {
        // Paper: A_i are "geometrically decreasing in size" (a_{i+1} = 3a_i/4 ± 1).
        // Concretely, partition output must be monotone non-increasing so that
        // L0 is always largest (highest hit rate, shortest insert chain).
        for total in 0usize..=64 {
            for levels in 1usize..=24 {
                let p = partition_funnel_buckets(total, levels);
                assert_eq!(p.len(), levels, "len mismatch for ({total}, {levels})");
                assert_eq!(
                    p.iter().sum::<usize>(),
                    total,
                    "sum for ({total}, {levels})"
                );
                for w in p.windows(2) {
                    assert!(w[1] <= w[0], "non-monotone for ({total}, {levels}): {p:?}");
                }
            }
        }
    }

    #[test]
    fn special_primary_single_group_edge_case() {
        // Smallest capacity exercises the SpecialPrimary path with
        // `group_count == 1` (`mask == 0`). The odd-step probe must still
        // make forward progress (loop terminates via `group_limit`).
        let mut map: FunnelHashMap<u64, u64> = FunnelHashMap::with_capacity(1);
        assert_eq!(
            map.special.primary.group_count_mask, 0,
            "regression assumes a single-group special primary"
        );
        for i in 0..16 {
            map.insert(i, i * 3);
        }
        for i in 0..16 {
            assert_eq!(map.get(&i), Some(&(i * 3)));
        }
        for i in 0..8 {
            assert_eq!(map.remove(&i), Some(i * 3));
        }
        for i in 0..8 {
            assert_eq!(map.get(&i), None);
        }
        for i in 8..16 {
            assert_eq!(map.get(&i), Some(&(i * 3)));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // FIXME: takes too long
    fn delete_insert_cycles_trigger_rebuild() {
        // Exercises the tombstone cleanup path: 6000 remove+insert cycles
        // on a 12K map forces level.tombstones > capacity/2.
        let n = 12_000;
        let mut map = FunnelHashMap::with_capacity(n * 2);
        for i in 0..n {
            map.insert(i, i);
        }

        for i in 0..6000 {
            assert!(map.remove(&i).is_some(), "remove {i} failed");
            map.insert(i + n, i + n);
        }

        assert_eq!(map.len(), n);
        // Verify all remaining keys are findable.
        for i in 6000..n {
            assert_eq!(map.get(&i), Some(&i), "original key {i} missing");
        }
        for i in 0..6000 {
            assert_eq!(
                map.get(&(i + n)),
                Some(&(i + n)),
                "new key {} missing",
                i + n
            );
        }
    }

    #[test]
    fn retain_does_not_trigger_mid_iter_resize_with_clustered_tombstones() {
        // `retain` cleans up only on iterator Drop, at the same capacity —
        // slot count must not change.
        let mut map: FunnelHashMap<i32, i32> = FunnelHashMap::with_capacity(1024);
        let max = i32::try_from(capacity::max_insertions(
            map.capacity(),
            DEFAULT_RESERVE_FRACTION,
        ))
        .expect("test capacity fits i32");
        for i in 0..max {
            map.insert(i, i);
        }
        let initial_capacity = map.capacity();
        map.retain(|k, _| k % 2 == 0);

        let expected_count = (0..max).filter(|i| i % 2 == 0).count();
        assert_eq!(map.len(), expected_count);
        for i in 0..max {
            if i % 2 == 0 {
                assert_eq!(map.get(&i), Some(&i), "kept key {i} missing");
            } else {
                assert!(map.get(&i).is_none(), "dropped key {i} survived");
            }
        }
        assert_eq!(
            map.capacity(),
            initial_capacity,
            "retain must not change the slot count, only rehash in place"
        );
    }

    #[test]
    fn bucket_overflow_promotes_max_populated_level() {
        // Paper §5: A_{i,j} overflow must spill into A_{i+1}, not skip to the
        // special array. Constant hasher pins every key to the same L0 bucket.
        struct ConstHasher;
        impl std::hash::Hasher for ConstHasher {
            fn finish(&self) -> u64 {
                0
            }
            fn write(&mut self, _: &[u8]) {}
        }
        struct ConstHashBuilder;
        impl std::hash::BuildHasher for ConstHashBuilder {
            type Hasher = ConstHasher;
            fn build_hasher(&self) -> Self::Hasher {
                ConstHasher
            }
        }

        let mut map: FunnelHashMap<i32, i32, ConstHashBuilder> =
            FunnelHashMap::with_capacity_and_hasher(2048, ConstHashBuilder);
        assert!(map.levels.len() > 1, "test requires multi-level layout");
        let l0_bucket_size = i32::try_from(1usize << map.levels[0].bucket_size_log2).unwrap();
        // bucket holds at most l0_bucket_size; one more forces a spill.
        for i in 0..=l0_bucket_size {
            map.insert(i, i);
        }
        assert_eq!(
            map.max_populated_level, 1,
            "first bucket overflow should land in A_1, not the special array"
        );
        for i in 0..=l0_bucket_size {
            assert_eq!(map.get(&i), Some(&i));
        }
    }

    #[test]
    fn reserve_fraction_clamped_to_funnel_max() {
        // Funnel's correctness proof requires reserve_fraction <= 1/8.
        let map: FunnelHashMap<i32, i32> =
            FunnelHashMap::with_capacity_and_reserve_fraction(256, 0.5);
        assert!(
            map.reserve_fraction <= MAX_FUNNEL_RESERVE_FRACTION,
            "reserve_fraction={} not clamped to {MAX_FUNNEL_RESERVE_FRACTION}",
            map.reserve_fraction
        );
    }
}
