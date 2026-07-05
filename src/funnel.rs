use core::hash::{BuildHasher, Hash};
use core::mem::{self, MaybeUninit};
use core::ops::Range;
use core::slice;

use alloc::{boxed::Box, vec, vec::Vec};
use allocator_api2::alloc::{Allocator, Global, Layout};
use equivalent::Equivalent;

use crate::common::DefaultHashBuilder;
use crate::common::arena::{self, Arena, ArenaSlots, SlotEntry};
use crate::common::config::{GROUP_SIZE, INITIAL_CAPACITY};
use crate::common::control::{self, CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use crate::common::error::TryReserveError;
#[cfg(not(feature = "std"))]
use crate::common::float::FloatExt as _;
use crate::common::iter::RegionCursor;
use crate::common::math::{self, align, capacity, cast, probe};
use crate::macros;
use crate::map;

/// Upper bound on `reserve_fraction`;
/// level capacities become unstable beyond this load factor.
pub(crate) const MAX_FUNNEL_RESERVE_FRACTION: f64 = 1.0 / 8.0;

/// Levels `[0, FUNNEL_POW2_LEVELS)` use pow2 bucket counts + `& mask` routing
/// (hot path); deeper levels store exact paper counts + `% count`, avoiding pow2
/// inflation on cold levels.
pub(crate) const FUNNEL_POW2_LEVELS: usize = 8;

/// Pow2 (`& mask`) vs exact (`% count`) routing for a level. `total_ctrl` and
/// `build_regions` MUST agree per level or the arena mis-allocates (UB), so both
/// route through this one predicate.
#[inline]
const fn funnel_level_is_pow2(level_idx: usize) -> bool {
    level_idx < FUNNEL_POW2_LEVELS
}

/// One funnel level `A_i` (paper §5). Fixed grid of `β`-sized buckets `A_{i,j}`;
/// inserts hash to one bucket and probe within it. Overflow spills to `A_{i+1}`
/// (or the special array `A_{α+1}`).
struct BucketLevel<T> {
    /// Cached `arena.as_ptr() + ctrl_offset`, stamped at construction.
    ctrl_ptr: *mut u8,
    /// Cached `arena.as_ptr() + data_offset`, stamped at construction.
    data_ptr: *mut MaybeUninit<T>,
    /// Bucket-routing mask. Pow2 levels: `bucket_count - 1`, so routing is
    /// `& mask`. Cold (exact) levels: `u32::MAX` sentinel selecting the
    /// `% bucket_count` path. Empty levels carry `0` to avoid `% 0`.
    bucket_count_mask: u32,
    /// Exact bucket count. Pow2 levels: `bucket_count_mask + 1`. Cold levels:
    /// `bucket_count_mask == u32::MAX` (sentinel) → `% bucket_count` routing.
    bucket_count: u32,
    /// `log2(bucket width β)`. A bucket spans `1 << bucket_size_log2` slots
    /// starting at `bucket_idx << bucket_size_log2` (always `GROUP_SIZE`-aligned).
    bucket_size_log2: u32,
    /// Per-level salt mixed into the low 32 bits of the key hash before routing,
    /// decorrelating bucket choice across levels.
    salt: u32,
    /// Slot capacity (`bucket_count * bucket_width`). Bounds `len`/`tombstones`
    /// so both fit in `u32`.
    capacity: u32,
    /// Live entry count in this level.
    len: u32,
    /// Deleted-slot (tombstone) count in this level.
    tombstones: u32,
}

unsafe impl<T: Send> Send for BucketLevel<T> {}
unsafe impl<T: Sync> Sync for BucketLevel<T> {}

impl<T> ArenaSlots<T> for BucketLevel<T> {
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

impl<T> BucketLevel<T> {
    /// Stamps a fresh descriptor at the given arena ptrs.
    /// Caller advances the offset cursor.
    fn new_at(
        level_idx: usize,
        bucket_count: u32,
        bucket_width: u32,
        pow2: bool,
        ctrl_ptr: *mut u8,
        data_ptr: *mut MaybeUninit<T>,
    ) -> Self {
        let cap = bucket_count.saturating_mul(bucket_width);
        let bucket_count_mask = if bucket_count == 0 {
            // Empty level: route to the `& 0` path, never `% 0`.
            0
        } else if pow2 {
            bucket_count.saturating_sub(1)
        } else {
            u32::MAX
        };
        Self {
            ctrl_ptr,
            data_ptr,
            bucket_count_mask,
            bucket_count,
            bucket_size_log2: bucket_width.trailing_zeros(),
            salt: math::level_salt(level_idx),
            capacity: cap,
            len: 0,
            tombstones: 0,
        }
    }

    #[inline]
    #[allow(clippy::cast_possible_truncation)]
    fn bucket_index(&self, key_hash: u64) -> usize {
        let h = (key_hash as u32) ^ self.salt;
        if self.bucket_count_mask == u32::MAX {
            // Cold exact level. Empty levels carry mask 0 (see `new_at`), so a
            // level reaching the modulo path always has bucket_count != 0.
            debug_assert!(self.bucket_count != 0);
            (h % self.bucket_count) as usize
        } else {
            (h as usize) & self.bucket_count_mask as usize
        }
    }

    /// Slot index range covering all entries in `bucket_idx`.
    #[inline]
    fn bucket_range(&self, bucket_idx: usize) -> Range<usize> {
        let start = bucket_idx << self.bucket_size_log2;
        let size = 1usize << self.bucket_size_log2;
        start..start + size
    }

    /// Paper §5 attempted insertion: hash `key_hash` to one bucket `A_{i,j}`,
    /// return the first empty slot in that bucket (or `None` if full).
    fn first_free_in_bucket(&self, key_hash: u64) -> Option<usize> {
        if self.len >= self.capacity {
            return None;
        }
        let bucket_idx = self.bucket_index(key_hash);
        let bucket_range = self.bucket_range(bucket_idx);
        debug_assert_eq!(bucket_range.start % GROUP_SIZE, 0);
        if !bucket_range.start.is_multiple_of(GROUP_SIZE) {
            unsafe { core::hint::unreachable_unchecked() };
        }
        let group_idx = bucket_range.start / GROUP_SIZE;
        self.group(group_idx)
            .free_mask()
            .lowest()
            .map(|offset| bucket_range.start + offset)
    }
}

impl<K, V> BucketLevel<SlotEntry<K, V>> {
    /// Probe one bucket for `key`. `StopSearch` on EMPTY: bucket never
    /// overflowed, so the key isn't at a deeper level. Pass `Some(out)`
    /// to record the first free slot; `None` for lookup.
    #[inline]
    fn find_in_bucket<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        slot_out: Option<&mut Option<usize>>,
    ) -> LookupStep
    where
        Q: Equivalent<K> + ?Sized,
    {
        let wants_free = matches!(&slot_out, Some(out) if out.is_none());
        if self.len == 0 {
            if self.capacity == 0 {
                return LookupStep::Continue;
            }
            if wants_free {
                let bucket_idx = self.bucket_index(key_hash);
                let slot_idx = bucket_idx << self.bucket_size_log2;
                if let Some(out) = slot_out {
                    *out = Some(slot_idx);
                }
            }
            if self.tombstones == 0 {
                return LookupStep::StopSearch;
            }
            return LookupStep::Continue;
        }
        let bucket_idx = self.bucket_index(key_hash);
        let bucket_range = self.bucket_range(bucket_idx);
        debug_assert_eq!(bucket_range.start % GROUP_SIZE, 0);
        if !bucket_range.start.is_multiple_of(GROUP_SIZE) {
            unsafe { core::hint::unreachable_unchecked() };
        }
        let group = self.group(bucket_range.start / GROUP_SIZE);
        for relative_idx in group.match_mask(key_fingerprint) {
            let slot_idx = bucket_range.start + relative_idx;
            let entry = unsafe { self.get_ref(slot_idx) };
            if key.equivalent(&entry.key) {
                return LookupStep::Found(slot_idx);
            }
        }
        if wants_free
            && let Some(o) = group.free_mask().lowest()
            && let Some(out) = slot_out
        {
            *out = Some(bucket_range.start + o);
        }
        if group.has_empty() {
            LookupStep::StopSearch
        } else {
            LookupStep::Continue
        }
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
struct SpecialPrimary<T> {
    /// Cached `arena.as_ptr() + ctrl_offset`, stamped at construction.
    ctrl_ptr: *mut u8,
    /// Cached `arena.as_ptr() + data_offset`, stamped at construction.
    data_ptr: *mut MaybeUninit<T>,
    /// Slot capacity (`group_count * GROUP_SIZE`). Bounds `len`/`tombstones`.
    capacity: u32,
    /// `group_count - 1`; pow2 so per-key odd-step probes wrap with `& mask`.
    group_count_mask: u32,
    /// Live entry count.
    len: u32,
    /// Deleted-slot (tombstone) count.
    tombstones: u32,
}

unsafe impl<T: Send> Send for SpecialPrimary<T> {}
unsafe impl<T: Sync> Sync for SpecialPrimary<T> {}

impl<T> ArenaSlots<T> for SpecialPrimary<T> {
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

impl<T> SpecialPrimary<T> {
    /// Stamps a fresh primary descriptor.
    /// `group_count_mask` = `group_count - 1` (pow2-1) so probes wrap `& mask`.
    fn new_at(
        cap: u32,
        group_count_mask: u32,
        ctrl_ptr: *mut u8,
        data_ptr: *mut MaybeUninit<T>,
    ) -> Self {
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap,
            group_count_mask,
            len: 0,
            tombstones: 0,
        }
    }

    #[inline]
    fn group_count(&self) -> usize {
        if self.capacity == 0 {
            0
        } else {
            self.capacity as usize / GROUP_SIZE
        }
    }
    #[inline]
    fn group_start(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash.rotate_left(11)) & self.group_count_mask as usize
    }
    /// Per-key odd step over the pow2 `group_count`. The `| 1` forces odd ⇒
    /// coprime to pow2 ⇒ `(group_idx + step) & mask` visits every group
    /// within `group_count` iterations.
    #[inline]
    fn group_step(&self, key_hash: u64) -> usize {
        (probe::hash_to_usize(key_hash.rotate_left(43)) | 1) & self.group_count_mask as usize
    }
}

/// Half `C` of the special array `A_{α+1}` (paper §5):
/// two-choice table with buckets of size `2 * primary_probe_limit` ≈ 2 log log n.
/// Reached only when a key exhausts the primary's probe budget.
struct SpecialFallback<T> {
    /// Cached `arena.as_ptr() + ctrl_offset`, stamped at construction.
    ctrl_ptr: *mut u8,
    /// Cached `arena.as_ptr() + data_offset`, stamped at construction.
    data_ptr: *mut MaybeUninit<T>,
    /// Slot capacity (`bucket_count * bucket_width`). Bounds `len`/`tombstones`.
    capacity: u32,
    /// Number of two-choice buckets; a key probes exactly `bucket_a`/`bucket_b`.
    bucket_count: u32,
    /// `log2(bucket width)`; a bucket spans `1 << bucket_size_log2` slots
    /// (`≈ 2 * primary_probe_limit`, rounded to a power of two).
    bucket_size_log2: u32,
    /// Live entry count.
    len: u32,
    /// Deleted-slot (tombstone) count.
    tombstones: u32,
}

unsafe impl<T: Send> Send for SpecialFallback<T> {}
unsafe impl<T: Sync> Sync for SpecialFallback<T> {}

impl<T> ArenaSlots<T> for SpecialFallback<T> {
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

impl<T> SpecialFallback<T> {
    /// Stamps a fresh fallback descriptor with two-choice bucket geometry.
    fn new_at(
        cap: u32,
        bucket_count: u32,
        bucket_size_log2: u32,
        ctrl_ptr: *mut u8,
        data_ptr: *mut MaybeUninit<T>,
    ) -> Self {
        Self {
            ctrl_ptr,
            data_ptr,
            capacity: cap,
            bucket_count,
            bucket_size_log2,
            len: 0,
            tombstones: 0,
        }
    }

    #[inline]
    fn bucket_range(&self, bucket_idx: usize) -> Range<usize> {
        let start = bucket_idx << self.bucket_size_log2;
        let size = 1usize << self.bucket_size_log2;
        let end = (start + size).min(self.capacity as usize);
        start..end
    }
    #[inline]
    fn bucket_a(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash.rotate_left(19)) % self.bucket_count as usize
    }
    #[inline]
    fn bucket_b(&self, key_hash: u64) -> usize {
        probe::hash_to_usize(key_hash.rotate_left(37)) % self.bucket_count as usize
    }

    #[inline]
    fn bucket_info(&self, bucket_idx: usize) -> (Option<usize>, usize) {
        let mut first_free = None;
        let mut occupied_count = 0;
        for slot_idx in self.bucket_range(bucket_idx) {
            if self.control_at(slot_idx).is_free() {
                first_free.get_or_insert(slot_idx);
            } else {
                occupied_count += 1;
            }
        }
        (first_free, occupied_count)
    }
}

/// Combines the special primary (probed first) and the special fallback
/// (when primary hits its probe limit). Together they catch keys that
/// overflowed every bucket level.
struct SpecialArray<T> {
    primary: SpecialPrimary<T>,
    fallback: SpecialFallback<T>,
    total_len: usize,
}

impl<T> SpecialArray<T> {
    /// Drain primary + fallback, calling `f` on each entry. Each slot's
    /// ctrl is cleared *before* the move so an `f` panic leaves no
    /// OCCUPIED ctrl for the map's drop to double-drop.
    fn drain_occupied_with<F: FnMut(T)>(&mut self, mut f: F) {
        self.primary.drain_values_and_clear(&mut f);
        self.fallback.drain_values_and_clear(f);
    }
}

/// Handle primary and fallback overflow regions.
struct OverflowHandler<K, V> {
    special: SpecialArray<SlotEntry<K, V>>,
    primary_probe_limit: usize,
}

impl<K, V> OverflowHandler<K, V> {
    fn new(special: SpecialArray<SlotEntry<K, V>>, primary_probe_limit: usize) -> Self {
        Self {
            special,
            primary_probe_limit,
        }
    }

    // ---- Lookup / probe ----

    /// Probe primary then fallback, optionally recording a free slot.
    #[cold]
    #[inline(never)]
    fn find_in_special<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
        mut free_slot: FreeSlot<'_>,
    ) -> Option<SlotLocation>
    where
        Q: Equivalent<K> + ?Sized,
    {
        match self.find_in_special_primary(key_hash, key_fingerprint, key, free_slot.as_deref_mut())
        {
            LookupStep::Found(slot_idx) => {
                return Some(SlotLocation::SpecialPrimary { slot_idx });
            }
            LookupStep::StopSearch => return None,
            LookupStep::Continue => {}
        }
        self.find_in_special_fallback(key_hash, key_fingerprint, key, free_slot)
            .map(|slot_idx| SlotLocation::SpecialFallback { slot_idx })
    }

    /// Probe at most `primary_probe_limit` primary groups. Return `StopSearch`
    /// when an empty group proves fallback cannot contain the key. Pass
    /// `Some(out)` to record the first free `SlotLocation`; use `None` for
    /// lookup-only probes.
    #[inline]
    fn find_in_special_primary<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        free_slot: FreeSlot<'_>,
    ) -> LookupStep
    where
        Q: Equivalent<K> + ?Sized,
    {
        let wants_free = matches!(&free_slot, Some(out) if out.is_none());
        let primary = &self.special.primary;

        if primary.capacity() == 0 || primary.len == 0 {
            if wants_free && let Some(out) = free_slot {
                *out = self
                    .first_free_in_special_primary(key_hash)
                    .map(|slot_idx| SlotLocation::SpecialPrimary { slot_idx });
            }
            return LookupStep::Continue;
        }

        let group_count = primary.group_count();
        let group_limit = self.primary_probe_limit.min(group_count.max(1));
        let mask = primary.group_count_mask as usize;
        let mut local: Option<usize> = None;
        let mut probe = ProbeSeq::new(primary.group_start(key_hash), primary.group_step(key_hash));

        let outcome: LookupStep = 'probe: {
            for _ in 0..group_limit {
                let has_free = if wants_free && local.is_none() {
                    let slot = primary.first_free_in_group(probe.group);
                    if let Some(s) = slot {
                        local = Some(s);
                    }
                    slot.is_some()
                } else {
                    primary.group_match_mask(probe.group, CTRL_EMPTY).any()
                };
                for relative_idx in primary.group_match_mask(probe.group, key_fingerprint) {
                    let slot_idx = probe.group * GROUP_SIZE + relative_idx;
                    let entry = unsafe { primary.get_ref(slot_idx) };
                    if key.equivalent(&entry.key) {
                        break 'probe LookupStep::Found(slot_idx);
                    }
                }
                if has_free && !primary.group_match_mask(probe.group, CTRL_TOMBSTONE).any() {
                    break 'probe LookupStep::StopSearch;
                }
                probe.advance(mask);
            }
            LookupStep::Continue
        };

        if wants_free && let Some(out) = free_slot {
            *out = local.map(|slot_idx| SlotLocation::SpecialPrimary { slot_idx });
        }
        outcome
    }

    #[inline]
    fn find_in_special_fallback<Q>(
        &self,
        key_hash: u64,
        key_fingerprint: u8,
        key: &Q,
        free_slot: FreeSlot<'_>,
    ) -> Option<usize>
    where
        Q: Equivalent<K> + ?Sized,
    {
        let wants_free = matches!(&free_slot, Some(out) if out.is_none());
        let fallback = &self.special.fallback;

        if fallback.capacity() == 0 || fallback.len == 0 {
            if wants_free && let Some(out) = free_slot {
                *out = self
                    .first_free_in_special_fallback(key_hash)
                    .map(|slot_idx| SlotLocation::SpecialFallback { slot_idx });
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
                    if fallback.control_at(slot_idx).is_free() {
                        local = Some(slot_idx);
                        break;
                    }
                }
            }
            if need_match {
                let controls = unsafe {
                    slice::from_raw_parts(fallback.ctrl_ptr().add(range.start), range.len())
                };
                let mut match_offset = 0;
                while let Some(relative_idx) = control::find_next_fingerprint_in_controls(
                    controls,
                    key_fingerprint,
                    match_offset,
                ) {
                    let slot_idx = range.start + relative_idx;
                    let entry = unsafe { fallback.get_ref(slot_idx) };
                    if key.equivalent(&entry.key) {
                        found = Some(slot_idx);
                        break;
                    }
                    match_offset = relative_idx + 1;
                }
            }
        }

        if wants_free && let Some(out) = free_slot {
            *out = local.map(|slot_idx| SlotLocation::SpecialFallback { slot_idx });
        }
        found
    }

    // ---- Free-slot search ----

    fn first_free_in_special_primary(&self, key_hash: u64) -> Option<usize> {
        let primary = &self.special.primary;
        if primary.len as usize >= primary.capacity() {
            return None;
        }

        let group_count = primary.group_count();
        let group_limit = self.primary_probe_limit.min(group_count.max(1));
        let mask = primary.group_count_mask as usize;
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
        if fallback.len as usize >= fallback.capacity() {
            return None;
        }

        let bucket_a = fallback.bucket_a(key_hash);
        let bucket_b = fallback.bucket_b(key_hash);
        let (free_a, occupied_a) = fallback.bucket_info(bucket_a);
        if bucket_a == bucket_b {
            return free_a;
        }

        let (free_b, occupied_b) = fallback.bucket_info(bucket_b);

        match (free_a, free_b) {
            (Some(slot_a), Some(slot_b)) => {
                if occupied_a <= occupied_b {
                    Some(slot_a)
                } else {
                    Some(slot_b)
                }
            }
            (free_a, free_b) => free_a.or(free_b),
        }
    }

    // ---- Insertion ----

    fn place_new_special_primary_entry(
        &mut self,
        slot_idx: usize,
        key: K,
        value: V,
        key_fingerprint: u8,
    ) {
        let primary = &mut self.special.primary;
        let was_tombstone = primary.control_at(slot_idx) == CTRL_TOMBSTONE;
        primary.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
        primary.len += 1;
        if was_tombstone {
            primary.tombstones -= 1;
        }
        self.special.total_len += 1;
    }

    fn place_new_special_fallback_entry(
        &mut self,
        slot_idx: usize,
        key: K,
        value: V,
        key_fingerprint: u8,
    ) {
        let fallback = &mut self.special.fallback;
        let was_tombstone = fallback.control_at(slot_idx) == CTRL_TOMBSTONE;
        fallback.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
        fallback.len += 1;
        if was_tombstone {
            fallback.tombstones -= 1;
        }
        self.special.total_len += 1;
    }

    #[inline]
    fn replace_special_primary_value(&mut self, slot_idx: usize, value: V) -> V {
        let entry = unsafe { self.special.primary.get_mut(slot_idx) };
        mem::replace(&mut entry.value, value)
    }

    #[inline]
    fn replace_special_fallback_value(&mut self, slot_idx: usize, value: V) -> V {
        let entry = unsafe { self.special.fallback.get_mut(slot_idx) };
        mem::replace(&mut entry.value, value)
    }

    // ---- Erase / cleanup ----

    #[inline]
    fn erase_special_primary(&mut self, slot_idx: usize) -> bool {
        self.special.primary.erase(slot_idx)
    }

    #[inline]
    fn erase_special_fallback(&mut self, slot_idx: usize) -> bool {
        self.special.fallback.erase(slot_idx)
    }

    fn account_erased(&mut self, location: SlotLocation, wrote_tombstone: bool) {
        match location {
            SlotLocation::SpecialPrimary { .. } => {
                self.special.primary.tombstones += u32::from(wrote_tombstone);
                self.special.primary.len -= 1;
            }
            SlotLocation::SpecialFallback { .. } => {
                self.special.fallback.tombstones += u32::from(wrote_tombstone);
                self.special.fallback.len -= 1;
            }
            SlotLocation::Level { .. } => unreachable!("level location passed to overflow"),
        }
        self.special.total_len -= 1;
    }

    fn special_primary_needs_cleanup(&self) -> bool {
        let primary = &self.special.primary;
        primary.tombstones as usize > capacity::tombstone_cleanup_threshold(primary.capacity())
    }

    fn special_fallback_needs_cleanup(&self) -> bool {
        let fallback = &self.special.fallback;
        fallback.tombstones as usize > capacity::tombstone_cleanup_threshold(fallback.capacity())
    }

    fn region_needs_cleanup(&self, location: SlotLocation) -> bool {
        match location {
            SlotLocation::SpecialPrimary { .. } => self.special_primary_needs_cleanup(),
            SlotLocation::SpecialFallback { .. } => self.special_fallback_needs_cleanup(),
            SlotLocation::Level { .. } => unreachable!("level location passed to overflow"),
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.special.total_len
    }

    #[inline]
    fn primary(&self) -> &SpecialPrimary<SlotEntry<K, V>> {
        &self.special.primary
    }

    #[inline]
    fn fallback(&self) -> &SpecialFallback<SlotEntry<K, V>> {
        &self.special.fallback
    }

    // ---- Bulk operations ----

    fn drain_special_into<F: FnMut((K, V))>(&mut self, mut f: F) {
        self.special.drain_occupied_with(|entry| {
            f((entry.key, entry.value));
        });
    }

    fn wipe_special(&mut self) {
        self.special.primary.clear_all_controls();
        self.special.primary.len = 0;
        self.special.primary.tombstones = 0;
        self.special.fallback.clear_all_controls();
        self.special.fallback.len = 0;
        self.special.fallback.tombstones = 0;
        self.special.total_len = 0;
    }

    fn clear_special(&mut self) {
        self.special.primary.drop_values_and_clear();
        self.special.primary.len = 0;
        self.special.primary.tombstones = 0;
        self.special.fallback.drop_values_and_clear();
        self.special.fallback.len = 0;
        self.special.fallback.tombstones = 0;
        self.special.total_len = 0;
    }

    fn drop_values(&mut self) {
        self.special.primary.drop_values();
        self.special.fallback.drop_values();
    }

    /// Take a primary entry without updating counters.
    /// # Safety
    /// `slot_idx` must reference a live, initialized occupied slot.
    #[inline]
    unsafe fn take_special_primary_entry(&mut self, slot_idx: usize) -> SlotEntry<K, V> {
        unsafe { self.special.primary.take(slot_idx) }
    }

    /// Take a fallback entry without updating counters.
    /// # Safety
    /// `slot_idx` must reference a live, initialized occupied slot.
    #[inline]
    unsafe fn take_special_fallback_entry(&mut self, slot_idx: usize) -> SlotEntry<K, V> {
        unsafe { self.special.fallback.take(slot_idx) }
    }

    /// Borrow an occupied primary slot.
    /// # Safety
    /// `slot_idx` must reference an occupied slot.
    #[inline]
    unsafe fn special_primary_ref(&self, slot_idx: usize) -> &SlotEntry<K, V> {
        unsafe { self.special.primary.get_ref(slot_idx) }
    }

    /// Borrow an occupied fallback slot.
    /// # Safety
    /// `slot_idx` must reference an occupied slot.
    #[inline]
    unsafe fn special_fallback_ref(&self, slot_idx: usize) -> &SlotEntry<K, V> {
        unsafe { self.special.fallback.get_ref(slot_idx) }
    }

    /// Return a mutable pointer to a live primary slot.
    /// # Safety
    /// `slot_idx` must reference a live slot.
    #[inline]
    unsafe fn special_primary_ptr(&self, slot_idx: usize) -> *mut SlotEntry<K, V> {
        self.special.primary.slot_ptr(slot_idx)
    }

    /// Return a mutable pointer to a live fallback slot.
    /// # Safety
    /// `slot_idx` must reference a live slot.
    #[inline]
    unsafe fn special_fallback_ptr(&self, slot_idx: usize) -> *mut SlotEntry<K, V> {
        self.special.fallback.slot_ptr(slot_idx)
    }
}

/// Identify a slot without re-probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotLocation {
    Level { level_idx: usize, slot_idx: usize },
    SpecialPrimary { slot_idx: usize },
    SpecialFallback { slot_idx: usize },
}

/// Record the first free slot, or omit tracking for lookup-only probes.
type FreeSlot<'a> = Option<&'a mut Option<SlotLocation>>;

/// Direct lookup after probing one region.
/// - `Found(slot_idx)`: key matched at slot.
/// - `Continue`: bucket has tombstones; keep probing for the key elsewhere.
/// - `StopSearch`: bucket has free space and no tombstones — key cannot
///   exist further along this hash chain, abort the search.
enum LookupStep {
    Found(usize),
    Continue,
    StopSearch,
}

/// Decide whether a level miss can continue into overflow.
enum LevelMiss {
    /// Stop because an empty byte proves overflow cannot contain the key.
    ChainClean,
    /// Continue because exhausted levels do not rule out overflow.
    MayContinue,
}

/// Stage entries between Funnel rebuild attempts.
struct ResizeScheduler<K, V> {
    target: usize,
    pending: Vec<(K, V)>,
    overflow: Vec<(K, V)>,
}

impl<K, V> ResizeScheduler<K, V> {
    fn new(target: usize, pending: Vec<(K, V)>) -> Self {
        Self {
            target,
            pending,
            overflow: Vec::new(),
        }
    }

    fn try_empty(target: usize, entry_capacity: usize) -> Result<Self, TryReserveError> {
        let mut pending = Vec::new();
        pending
            .try_reserve(entry_capacity)
            .map_err(|_| TryReserveError::AllocError)?;
        Ok(Self::new(target, pending))
    }

    #[inline]
    fn target(&self) -> usize {
        self.target
    }

    fn advance_target(&mut self) -> Result<usize, TryReserveError> {
        self.target = self
            .target
            .checked_mul(2)
            .ok_or(TryReserveError::CapacityOverflow)?;
        Ok(self.target)
    }
}

/// Implement funnel hashing for [`map::HashMap`].
///
/// Capacity is split between a stack of bucket-grouped `levels` (each level
/// half the size of the previous) and an `overflow` handler catching overflow.
/// Inserts try level 0 first, then descend to deeper levels, then to
/// `overflow` (special primary → special fallback). Lookups follow the same
/// order. The funnel structure trades a small probe budget per level for
/// hard worst-case guarantees on lookup cost.
///
/// **Lower bound**: paper §4 proves any greedy open-addressing scheme needs
/// `Ω(log² δ⁻¹)` worst-case probes (`δ` = empty fraction). Funnel matches
/// this asymptotically — no constant-factor rewrite can do better.
pub struct FunnelTable<K, V, S = DefaultHashBuilder, A: Allocator + Clone = Global> {
    levels: BucketLevelSlice<K, V>,
    overflow: OverflowHandler<K, V>,
    len: usize,
    total_slots: usize,
    max_insertions: usize,
    reserve_fraction: f64,
    /// Bound lookups by the deepest populated level.
    max_populated_level: usize,
    hash_builder: S,
    alloc: A,
    /// [`ctrl_L0|...|ctrl_SP|ctrl_SF`][pad][`slots_L0|...|slots_SP|slots_SF`].
    arena: Arena,
}

impl<K, V> ResizeScheduler<K, V>
where
    K: Eq + Hash,
{
    fn collect_from<S, A>(target: usize, table: &mut FunnelTable<K, V, S, A>) -> Self
    where
        S: BuildHasher,
        A: Allocator + Clone,
    {
        let mut scheduler = Self::new(target, Vec::with_capacity(table.len));
        table.drain_entries_into(&mut scheduler.pending);
        scheduler
    }

    fn try_collect_from<S, A>(
        target: usize,
        table: &mut FunnelTable<K, V, S, A>,
    ) -> Result<Self, TryReserveError>
    where
        S: BuildHasher,
        A: Allocator + Clone,
    {
        let mut scheduler = Self::try_empty(target, table.len)?;
        table.drain_entries_into(&mut scheduler.pending);
        Ok(scheduler)
    }

    /// Reinsert staged entries, recovering all entries after a failed attempt.
    fn reinsert_into<S, A>(&mut self, table: &mut FunnelTable<K, V, S, A>) -> bool
    where
        S: BuildHasher,
        A: Allocator + Clone,
    {
        self.overflow.clear();
        for (key, value) in self.pending.drain(..) {
            if let Err(pair) = table.try_insert_new_entry_unchecked(key, value) {
                self.overflow.push(pair);
            }
        }
        if self.overflow.is_empty() {
            return true;
        }
        table.drain_entries_into(&mut self.overflow);
        mem::swap(&mut self.pending, &mut self.overflow);
        false
    }
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
        let levels = &mut self.levels;
        let overflow = &mut self.overflow;
        self.arena.drop_table(&self.alloc, || {
            for level in levels {
                level.drop_values();
            }
            overflow.drop_values();
        });
    }
}

// ---------------------------------------------------------------------------
// Public type aliases. The generic [`map::HashMap`] shell supplies the public
// API; these names keep `FunnelHashMap` and its iterator/entry types nameable
// (and re-exportable from `lib.rs` / `set.rs`). The generic-argument threading
// lives once in `declare_backend_aliases!`; each entry below is just `doc`,
// alias name, and the unprefixed shell type.
// ---------------------------------------------------------------------------

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

/// Boxed level descriptors for one funnel arena build.
type BucketLevelSlice<K, V> = Box<[BucketLevel<SlotEntry<K, V>>]>;

/// Full result of a funnel arena build: arena + level + special descriptors.
type FunnelArenaBuild<K, V> = (Arena, BucketLevelSlice<K, V>, SpecialArray<SlotEntry<K, V>>);

/// [`FunnelArenaBuild`] minus the arena, returned by
/// [`FunnelGeometry::build_regions`] so the caller deallocates on error.
type FunnelArenaInner<K, V> = (BucketLevelSlice<K, V>, SpecialArray<SlotEntry<K, V>>);

/// Power-of-two-rounded layout sizes for one funnel map: levels + the two
/// special arrays. Derives every rounded size once in [`new`](Self::new), then
/// owns the build/alloc steps so callers never re-thread or re-round them.
struct FunnelGeometry<'a> {
    level_bucket_counts: &'a [usize],
    /// `bucket_width` rounded up to a power of two.
    bucket_width: usize,
    primary_ctrl: usize,
    fallback_ctrl: usize,
    fallback_bucket_size: usize,
}

impl<'a> FunnelGeometry<'a> {
    /// Rounds the raw capacities to their final layout sizes once. `bucket_width`
    /// rounds up to a power of two; the special capacities to their ctrl-byte
    /// extents (idempotent if already rounded).
    fn new(
        level_bucket_counts: &'a [usize],
        bucket_width: usize,
        special_primary_capacity: usize,
        special_fallback_capacity: usize,
        fallback_bucket_size: usize,
    ) -> Self {
        Self {
            level_bucket_counts,
            bucket_width: bucket_width.next_power_of_two(),
            primary_ctrl: align::round_up_to_pow2_groups(special_primary_capacity),
            fallback_ctrl: align::round_up_to_group(special_fallback_capacity),
            fallback_bucket_size,
        }
    }

    /// Total control-byte count across levels + both special arrays. Checked
    /// throughout: a fallible caller (`try_resize`/`try_reserve`) gets
    /// `CapacityOverflow` rather than a wrapped under-count.
    fn total_ctrl(&self) -> Result<usize, TryReserveError> {
        let mut sum: usize = 0;
        for (level_idx, &bc) in self.level_bucket_counts.iter().enumerate() {
            let bc = if bc == 0 {
                0
            } else if funnel_level_is_pow2(level_idx) {
                bc.checked_next_power_of_two()
                    .ok_or(TryReserveError::CapacityOverflow)?
            } else {
                bc
            };
            let part = bc
                .checked_mul(self.bucket_width)
                .ok_or(TryReserveError::CapacityOverflow)?;
            sum = sum
                .checked_add(part)
                .ok_or(TryReserveError::CapacityOverflow)?;
        }
        sum.checked_add(self.primary_ctrl)
            .and_then(|s| s.checked_add(self.fallback_ctrl))
            .ok_or(TryReserveError::CapacityOverflow)
    }

    /// Stamps level + special descriptors from the arena base into a single
    /// contiguous allocation:
    /// `[ctrls_L0|...|sp_ctrl|sf_ctrl][pad][slots_L0|...|sf_slots]`.
    fn build_regions<K, V>(
        &self,
        arena_base: *mut u8,
        data_base_off: usize,
    ) -> Result<FunnelArenaInner<K, V>, TryReserveError> {
        let mut cursor = arena::LayoutCursor::<SlotEntry<K, V>>::new(arena_base, data_base_off)?;

        let mut levels: Vec<BucketLevel<SlotEntry<K, V>>> = Vec::new();
        levels
            .try_reserve_exact(self.level_bucket_counts.len())
            .map_err(|_| TryReserveError::AllocError)?;
        let bw32 =
            u32::try_from(self.bucket_width).map_err(|_| TryReserveError::CapacityOverflow)?;
        for (level_idx, &bc_raw) in self.level_bucket_counts.iter().enumerate() {
            let pow2 = funnel_level_is_pow2(level_idx);
            let bc = u32::try_from(if bc_raw == 0 {
                0
            } else if pow2 {
                bc_raw.next_power_of_two()
            } else {
                bc_raw
            })
            .map_err(|_| TryReserveError::CapacityOverflow)?;
            let cap = bc.saturating_mul(bw32);
            // SAFETY: the arena was allocated for the layout these region caps sum to.
            let (ctrl_ptr, data_ptr) = unsafe { cursor.reserve(cap)? };
            levels.push(BucketLevel::new_at(
                level_idx, bc, bw32, pow2, ctrl_ptr, data_ptr,
            ));
        }

        let primary_cap =
            u32::try_from(self.primary_ctrl).map_err(|_| TryReserveError::CapacityOverflow)?;
        let primary_gc_mask = u32::try_from(self.primary_ctrl / GROUP_SIZE)
            .map_err(|_| TryReserveError::CapacityOverflow)?
            .wrapping_sub(1);
        // SAFETY: as above.
        let (primary_ctrl_ptr, primary_data_ptr) = unsafe { cursor.reserve(primary_cap)? };
        let primary = SpecialPrimary::new_at(
            primary_cap,
            primary_gc_mask,
            primary_ctrl_ptr,
            primary_data_ptr,
        );

        let fallback_cap =
            u32::try_from(self.fallback_ctrl).map_err(|_| TryReserveError::CapacityOverflow)?;
        let fb_size = self.fallback_bucket_size.next_power_of_two();
        let fb_count = u32::try_from(if fb_size == 0 {
            0
        } else {
            self.fallback_ctrl.div_ceil(fb_size)
        })
        .map_err(|_| TryReserveError::CapacityOverflow)?;
        let fb_log2 = u32::try_from(fb_size)
            .map_err(|_| TryReserveError::CapacityOverflow)?
            .trailing_zeros();
        // SAFETY: as above.
        let (fallback_ctrl_ptr, fallback_data_ptr) = unsafe { cursor.reserve(fallback_cap)? };
        let fallback = SpecialFallback::new_at(
            fallback_cap,
            fb_count,
            fb_log2,
            fallback_ctrl_ptr,
            fallback_data_ptr,
        );

        Ok((
            levels.into_boxed_slice(),
            SpecialArray {
                primary,
                fallback,
                total_len: 0,
            },
        ))
    }

    /// Fallible single-arena builder: allocates, stamps regions, deallocates on
    /// error (`Arena` has no `Drop`, so a bare `?` would leak).
    fn try_alloc<K, V, A: Allocator + Clone>(
        &self,
        alloc: &A,
    ) -> Result<FunnelArenaBuild<K, V>, TryReserveError> {
        let total_ctrl = self.total_ctrl()?;
        let (arena_layout, data_base_off) = arena::layout_for::<K, V>(total_ctrl)?;
        let arena = Arena::try_allocate_with_ctrl_zeroed(arena_layout, total_ctrl, alloc)?;
        match self.build_regions::<K, V>(arena.as_ptr(), data_base_off) {
            Ok((levels, special)) => Ok((arena, levels, special)),
            Err(e) => {
                arena.deallocate(alloc);
                Err(e)
            }
        }
    }

    /// Infallible [`try_alloc`](Self::try_alloc); aborts via `handle_alloc_error`.
    fn alloc<K, V, A: Allocator + Clone>(&self, alloc: &A) -> FunnelArenaBuild<K, V> {
        self.try_alloc(alloc).unwrap_or_else(|_| {
            let layout = match self
                .total_ctrl()
                .and_then(|tc| arena::layout_for::<K, V>(tc).map(|(layout, _)| layout))
            {
                Ok(layout) => layout,
                Err(_) => Layout::from_size_align(1, 1).unwrap(),
            };
            allocator_api2::alloc::handle_alloc_error(layout)
        })
    }
}

/// Split a raw slot budget into funnel regions: main bucket levels plus the
/// special primary/fallback arrays (paper §5). The single home for the split, so
/// every fresh-allocation constructor derives one consistent layout.
struct FunnelSplit {
    level_bucket_counts: Vec<usize>,
    bucket_width: usize,
    primary_ctrl: usize,
    fallback_ctrl: usize,
    fallback_bucket_size: usize,
    /// Special-primary probe budget; also feeds [`OverflowHandler::new`].
    primary_probe_limit: usize,
}

impl FunnelSplit {
    /// Partition `total_slots` at an already-sanitized `reserve_fraction`: trim
    /// the main capacity to a `β` multiple, fold the remainder into the special
    /// arrays, then split the leftover evenly across primary and fallback.
    fn for_slots(total_slots: usize, reserve_fraction: f64) -> Self {
        let level_count = compute_level_count(reserve_fraction);
        let bucket_width = align::round_up_to_group(compute_bucket_width(reserve_fraction));
        let primary_probe_limit = probe::log_log_probe_limit(total_slots).max(1);

        let mut special_capacity =
            choose_special_capacity(total_slots, reserve_fraction, bucket_width);
        let mut main_capacity = total_slots.saturating_sub(special_capacity);
        let main_remainder = main_capacity % bucket_width.max(1);
        if main_remainder != 0 {
            main_capacity = main_capacity.saturating_sub(main_remainder);
            special_capacity = total_slots.saturating_sub(main_capacity);
        }

        let total_main_buckets = main_capacity.checked_div(bucket_width).unwrap_or(0);
        let level_bucket_counts = partition_funnel_buckets(total_main_buckets, level_count);
        let fallback_bucket_size = (primary_probe_limit.saturating_mul(2)).max(2);
        let primary_ctrl = align::round_up_to_pow2_groups(special_capacity.div_ceil(2));
        let fallback_ctrl =
            align::round_up_to_group(special_capacity.saturating_sub(special_capacity.div_ceil(2)));

        Self {
            level_bucket_counts,
            bucket_width,
            primary_ctrl,
            fallback_ctrl,
            fallback_bucket_size,
            primary_probe_limit,
        }
    }

    /// Borrow the split as an arena layout; keep the split alive until it allocates.
    fn geometry(&self) -> FunnelGeometry<'_> {
        FunnelGeometry::new(
            &self.level_bucket_counts,
            self.bucket_width,
            self.primary_ctrl,
            self.fallback_ctrl,
            self.fallback_bucket_size,
        )
    }
}

/// A funnel map's regions (bucket levels + the special array), bundled so
/// [`arena::ArenaDropGuard`] can drop their values for panic-safe `clone`.
struct FunnelRegions<K, V> {
    levels: BucketLevelSlice<K, V>,
    special: SpecialArray<SlotEntry<K, V>>,
}

impl<K, V> arena::RegionSet for FunnelRegions<K, V> {
    fn drop_all_values(&mut self) {
        for level in &mut self.levels {
            level.drop_values();
        }
        self.special.primary.drop_values();
        self.special.fallback.drop_values();
    }
}

impl<K, V, S, A> FunnelTable<K, V, S, A>
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
        let total_slots = if capacity == 0 {
            0
        } else {
            capacity::capacity_for(INITIAL_CAPACITY, capacity, reserve_fraction)
                .expect("capacity overflow")
        };
        let max_insertions = capacity::max_insertions(total_slots, reserve_fraction);

        let split = FunnelSplit::for_slots(total_slots, reserve_fraction);
        let primary_probe_limit = split.primary_probe_limit;
        let (arena, levels, special) = split.geometry().alloc(&alloc);

        let overflow = OverflowHandler::new(special, primary_probe_limit);

        Self {
            levels,
            overflow,
            len: 0,
            total_slots,
            max_insertions,
            reserve_fraction,
            max_populated_level: 0,
            hash_builder,
            alloc,
            arena,
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
            let new_capacity = if self.total_slots == 0 {
                INITIAL_CAPACITY
            } else {
                self.total_slots.saturating_mul(2)
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

    /// Places a known-novel entry at `location`, resizing first if the table is
    /// full or no candidate was found. Single-pass insert's placement tail.
    fn insert_at_location_after_resize_check(
        &mut self,
        location: Option<SlotLocation>,
        key_hash: u64,
        key: K,
        value: V,
        key_fingerprint: u8,
    ) -> Option<V> {
        let final_location = match location {
            Some(loc) if self.len < self.max_insertions => loc,
            _ => {
                let new_capacity = if self.total_slots == 0 {
                    INITIAL_CAPACITY
                } else {
                    self.total_slots.saturating_mul(2)
                };
                self.resize(new_capacity);
                self.choose_slot_for_new_key(key_hash)
                    .expect("no free slot found after resize")
            }
        };

        self.place_new_entry(final_location, key, value, key_fingerprint);
        None
    }

    /// Raw pointer to the whole slot at `loc`. Projects through raw pointers
    /// from shared `&Region` (level / special primary / special fallback),
    /// forming no intermediate `&mut`, so distinct locations yield
    /// non-aliasing `*mut`.
    ///
    /// # Safety
    /// `loc` must reference a live slot in this table.
    #[inline]
    unsafe fn slot_ptr_at(&self, loc: SlotLocation) -> *mut SlotEntry<K, V> {
        match loc {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let levels_ptr: *const BucketLevel<SlotEntry<K, V>> = self.levels.as_ptr();
                // SAFETY: shared `&BucketLevel` only — never `&mut` — so no
                // aliasing tag.
                let level = unsafe { &*levels_ptr.add(level_idx) };
                level.slot_ptr(slot_idx)
            }
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                self.overflow.special_primary_ptr(slot_idx)
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                self.overflow.special_fallback_ptr(slot_idx)
            },
        }
    }

    /// Take the entry at `location` without updating counters or control bytes.
    ///
    /// # Safety
    /// `location` must reference a live, initialized occupied slot in this table.
    #[inline]
    unsafe fn take_entry_at(&mut self, location: SlotLocation) -> SlotEntry<K, V> {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { self.levels[level_idx].take(slot_idx) },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                self.overflow.take_special_primary_entry(slot_idx)
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                self.overflow.take_special_fallback_entry(slot_idx)
            },
        }
    }

    #[inline]
    fn erase_location(&mut self, location: SlotLocation) -> bool {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => self.levels[level_idx].erase(slot_idx),
            SlotLocation::SpecialPrimary { slot_idx } => {
                self.overflow.erase_special_primary(slot_idx)
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                self.overflow.erase_special_fallback(slot_idx)
            }
        }
    }

    #[inline]
    fn account_erased_location(&mut self, location: SlotLocation, wrote_tombstone: bool) {
        match location {
            SlotLocation::Level { level_idx, .. } => {
                let level = &mut self.levels[level_idx];
                if wrote_tombstone {
                    level.tombstones += 1;
                }
                level.len -= 1;
            }
            SlotLocation::SpecialPrimary { .. } | SlotLocation::SpecialFallback { .. } => {
                self.overflow.account_erased(location, wrote_tombstone);
            }
        }
        self.len -= 1;
    }

    #[inline]
    fn finish_counted_removal(&mut self, location: SlotLocation) {
        let wrote_tombstone = self.erase_location(location);
        self.account_erased_location(location, wrote_tombstone);
    }

    /// Take + erase + decrement counters for the slot at `loc`. Shared by
    /// [`map::TableBackend::remove`] and [`map::TableBackend::extract_finish`]; the former adds a
    /// resize pass, the latter consolidates tombstones lazily.
    fn take_and_tombstone(&mut self, location: SlotLocation) -> (K, V) {
        // SAFETY: caller passes a live location found in this table.
        let removed = unsafe { self.take_entry_at(location) };
        self.finish_counted_removal(location);
        (removed.key, removed.value)
    }

    /// `true` if the region holding `loc` has accumulated enough tombstones
    /// that [`map::TableBackend::remove`] should rehash in place.
    fn region_needs_cleanup(&self, location: SlotLocation) -> bool {
        let (tombstones, cap) = match location {
            SlotLocation::Level { level_idx, .. } => {
                let level = &self.levels[level_idx];
                (level.tombstones, level.capacity())
            }
            SlotLocation::SpecialPrimary { .. } | SlotLocation::SpecialFallback { .. } => {
                return self.overflow.region_needs_cleanup(location);
            }
        };
        tombstones as usize > capacity::tombstone_cleanup_threshold(cap)
    }

    /// Bulk-clears all control bytes and zeroes counters. Called by
    /// [`map::Drain::drop`] after the slots' values have been taken.
    fn wipe_all(&mut self) {
        for level in &mut self.levels {
            level.clear_all_controls();
            level.len = 0;
            level.tombstones = 0;
        }
        self.overflow.wipe_special();
        self.len = 0;
        self.max_populated_level = 0;
    }

    /// Removes all entries, keeping allocated capacity.
    fn clear(&mut self) {
        for level in &mut self.levels {
            level.drop_values_and_clear();
            level.len = 0;
            level.tombstones = 0;
        }
        self.overflow.clear_special();
        self.len = 0;
        self.max_populated_level = 0;
    }

    /// Fallible counterpart to [`Self::resize`]. Common path leaves `self`
    /// intact on `Err`; a failing 2x-retry allocation may empty `self`.
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        let mut new_map = Self::try_with_slots_and_reserve_fraction_and_hasher_in(
            new_capacity,
            self.reserve_fraction,
            self.hash_builder.clone(),
            self.alloc.clone(),
        )?;
        let mut scheduler = ResizeScheduler::try_collect_from(new_capacity, self)?;
        loop {
            if scheduler.reinsert_into(&mut new_map) {
                *self = new_map;
                return Ok(());
            }
            let target = scheduler.advance_target()?;
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
        total_slots: usize,
        reserve_fraction: f64,
        hash_builder: S,
        alloc: A,
    ) -> Result<Self, TryReserveError> {
        let reserve_fraction =
            capacity::sanitize_reserve_fraction(reserve_fraction).min(MAX_FUNNEL_RESERVE_FRACTION);
        let max_insertions = capacity::max_insertions(total_slots, reserve_fraction);

        let split = FunnelSplit::for_slots(total_slots, reserve_fraction);
        let primary_probe_limit = split.primary_probe_limit;
        let (arena, levels, special) = split.geometry().try_alloc(&alloc)?;

        let overflow = OverflowHandler::new(special, primary_probe_limit);

        Ok(Self {
            levels,
            overflow,
            len: 0,
            total_slots,
            max_insertions,
            reserve_fraction,
            max_populated_level: 0,
            hash_builder,
            alloc,
            arena,
        })
    }

    /// Rebuild in-place at `new_capacity`. Doubles `new_capacity` on
    /// insert overflow (funnel's structural failure mode under adversarial
    /// hashing) until every entry places.
    fn resize(&mut self, new_capacity: usize) {
        let mut scheduler = ResizeScheduler::collect_from(new_capacity, self);
        loop {
            self.install_fresh_storage(scheduler.target());
            if scheduler.reinsert_into(self) {
                return;
            }
            scheduler
                .advance_target()
                .expect("capacity overflow during funnel resize retry");
        }
    }

    /// Move every live entry into `out`; ctrl bytes cleared so `install_fresh_storage`
    /// can free the old arena safely. Each ctrl is cleared *before* the move so
    /// a `Vec::push` realloc panic leaves no OCCUPIED slot behind to double-drop.
    fn drain_entries_into(&mut self, out: &mut Vec<(K, V)>) {
        for level in &mut self.levels {
            level.drain_values_and_clear(|entry| {
                out.push((entry.key, entry.value));
            });
        }
        self.overflow.drain_special_into(|entry| {
            out.push(entry);
        });
        for level in &mut self.levels {
            level.len = 0;
            level.tombstones = 0;
        }
        self.overflow.wipe_special();
        self.len = 0;
        self.max_populated_level = 0;
    }

    /// Replace `self`'s tables with empty storage sized for `new_capacity`.
    fn install_fresh_storage(&mut self, new_capacity: usize) {
        let split = FunnelSplit::for_slots(new_capacity, self.reserve_fraction);
        let new_primary_probe_limit = split.primary_probe_limit;
        let alloc = &self.alloc;

        let (new_arena, new_levels, new_special) = split.geometry().alloc(alloc);

        let new_overflow = OverflowHandler::new(new_special, new_primary_probe_limit);

        // Drop old levels first (they read from old arena), then replace arena.
        let old_arena = mem::replace(&mut self.arena, new_arena);
        self.levels = new_levels;
        self.overflow = new_overflow;
        self.total_slots = new_capacity;
        self.max_insertions = capacity::max_insertions(new_capacity, self.reserve_fraction);
        self.max_populated_level = 0;

        // Free old arena (drain_entries_into already moved all values out).
        old_arena.deallocate(alloc);
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

        if let Some(slot_idx) = self.overflow.first_free_in_special_primary(key_hash) {
            return Some(SlotLocation::SpecialPrimary { slot_idx });
        }

        self.overflow
            .first_free_in_special_fallback(key_hash)
            .map(|slot_idx| SlotLocation::SpecialFallback { slot_idx })
    }

    /// Delegate to [`OverflowHandler::find_in_special`].
    #[cold]
    #[inline(never)]
    fn find_in_special<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
        free_slot: FreeSlot<'_>,
    ) -> Option<SlotLocation>
    where
        Q: Equivalent<K> + ?Sized,
    {
        self.overflow
            .find_in_special(key, key_hash, key_fingerprint, free_slot)
    }

    /// Single-pass level probe. Returns the match if any; with `Some(free_slot)`
    /// records the first free slot so an insert places there without re-probing.
    /// The [`LevelMiss`] reports whether the chain ended clean (no special overflow).
    fn find_in_levels<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
        free_slot: FreeSlot<'_>,
    ) -> (Option<SlotLocation>, LevelMiss)
    where
        Q: Equivalent<K> + ?Sized,
    {
        let wants_free = matches!(&free_slot, Some(out) if out.is_none());
        let mut local: Option<SlotLocation> = None;

        for (level_idx, level) in self.levels.iter().enumerate() {
            let mut slot_candidate: Option<usize> = None;
            let out = if wants_free && local.is_none() {
                Some(&mut slot_candidate)
            } else {
                None
            };
            let step = level.find_in_bucket(key_hash, key_fingerprint, key, out);
            if let Some(slot_idx) = slot_candidate {
                local = Some(SlotLocation::Level {
                    level_idx,
                    slot_idx,
                });
            }
            match step {
                LookupStep::Found(slot_idx) => {
                    return (
                        Some(SlotLocation::Level {
                            level_idx,
                            slot_idx,
                        }),
                        LevelMiss::MayContinue,
                    );
                }
                LookupStep::Continue => {}
                LookupStep::StopSearch => {
                    if let Some(out) = free_slot {
                        *out = local;
                    }
                    return (None, LevelMiss::ChainClean);
                }
            }
        }

        if wants_free && let Some(out) = free_slot {
            *out = local;
        }
        (None, LevelMiss::MayContinue)
    }

    #[inline]
    fn replace_existing_value(&mut self, location: SlotLocation, value: V) -> V {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let entry = unsafe { self.levels[level_idx].get_mut(slot_idx) };
                mem::replace(&mut entry.value, value)
            }
            SlotLocation::SpecialPrimary { slot_idx } => {
                self.overflow.replace_special_primary_value(slot_idx, value)
            }
            SlotLocation::SpecialFallback { slot_idx } => self
                .overflow
                .replace_special_fallback_value(slot_idx, value),
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
        if let SlotLocation::Level {
            level_idx,
            slot_idx,
        } = location
        {
            self.place_new_level_entry(level_idx, slot_idx, key, value, key_fingerprint);
        } else {
            self.place_new_entry(location, key, value, key_fingerprint);
        }
        Ok(())
    }

    #[inline]
    fn place_new_entry(&mut self, location: SlotLocation, key: K, value: V, key_fingerprint: u8) {
        match location {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => self.place_new_level_entry(level_idx, slot_idx, key, value, key_fingerprint),
            SlotLocation::SpecialPrimary { slot_idx } => {
                self.place_new_special_primary_entry(slot_idx, key, value, key_fingerprint);
            }
            SlotLocation::SpecialFallback { slot_idx } => {
                self.place_new_special_fallback_entry(slot_idx, key, value, key_fingerprint);
            }
        }
    }

    #[inline]
    fn place_new_level_entry(
        &mut self,
        level_idx: usize,
        slot_idx: usize,
        key: K,
        value: V,
        key_fingerprint: u8,
    ) {
        let level = &mut self.levels[level_idx];
        let was_tombstone = level.control_at(slot_idx) == CTRL_TOMBSTONE;
        level.write_with_control(slot_idx, SlotEntry { key, value }, key_fingerprint);
        level.len += 1;
        if was_tombstone {
            level.tombstones -= 1;
        }
        if level_idx > self.max_populated_level {
            self.max_populated_level = level_idx;
        }
        self.len += 1;
    }

    #[inline]
    fn place_new_special_primary_entry(
        &mut self,
        slot_idx: usize,
        key: K,
        value: V,
        key_fingerprint: u8,
    ) {
        self.overflow
            .place_new_special_primary_entry(slot_idx, key, value, key_fingerprint);
        self.len += 1;
    }

    #[inline]
    fn place_new_special_fallback_entry(
        &mut self,
        slot_idx: usize,
        key: K,
        value: V,
        key_fingerprint: u8,
    ) {
        self.overflow
            .place_new_special_fallback_entry(slot_idx, key, value, key_fingerprint);
        self.len += 1;
    }

    /// Dispatch `loc` to the right descriptor and return a shared reference
    /// to the slot. SAFETY: `loc` must reference an occupied slot.
    #[inline]
    unsafe fn slot_ref(&self, loc: SlotLocation) -> &SlotEntry<K, V> {
        match loc {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => unsafe { self.levels[level_idx].get_ref(slot_idx) },
            SlotLocation::SpecialPrimary { slot_idx } => unsafe {
                self.overflow.special_primary_ref(slot_idx)
            },
            SlotLocation::SpecialFallback { slot_idx } => unsafe {
                self.overflow.special_fallback_ref(slot_idx)
            },
        }
    }

    #[inline]
    fn find_slot_location_with_hash<Q>(
        &self,
        key: &Q,
        key_hash: u64,
        key_fingerprint: u8,
    ) -> Option<SlotLocation>
    where
        Q: Equivalent<K> + ?Sized,
    {
        // SAFETY: `levels.len() == level_count >= 1` (fixed at construction), so
        // index 0 is always valid. Elides the hot-path bounds check + panic pad.
        let level0 = unsafe { self.levels.get_unchecked(0) };
        match level0.find_in_bucket(key_hash, key_fingerprint, key, None) {
            LookupStep::Found(slot_idx) => {
                return Some(SlotLocation::Level {
                    level_idx: 0,
                    slot_idx,
                });
            }
            LookupStep::Continue => {}
            LookupStep::StopSearch => return None,
        }

        if self.max_populated_level > 0 {
            let search_limit = (self.max_populated_level + 1).min(self.levels.len());
            // SAFETY: `search_limit <= levels.len()` by the `min` above, and
            // `1 <= search_limit` whenever `max_populated_level > 0`, so the
            // range is in bounds. Elides the slice bounds check.
            let tail = unsafe { self.levels.get_unchecked(1..search_limit) };
            for (offset, level) in tail.iter().enumerate() {
                match level.find_in_bucket(key_hash, key_fingerprint, key, None) {
                    LookupStep::Found(slot_idx) => {
                        return Some(SlotLocation::Level {
                            level_idx: offset + 1,
                            slot_idx,
                        });
                    }
                    LookupStep::Continue => {}
                    LookupStep::StopSearch => return None,
                }
            }
        }

        // Special tables are only populated under overflow.
        if self.overflow.len() == 0 {
            return None;
        }
        self.find_in_special(key, key_hash, key_fingerprint, None)
    }

    fn shrink_max_populated_level(&mut self) {
        while self.max_populated_level > 0 && self.levels[self.max_populated_level].len == 0 {
            self.max_populated_level -= 1;
        }
    }
}

impl<K, V, S, A> FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    /// Prime the scan and cross region boundaries off the hot path.
    #[cold]
    fn scan_advance(&self, scan: &mut FunnelScan) -> Option<(*mut SlotEntry<K, V>, SlotLocation)> {
        if !scan.region.started() {
            // Prime the cursor on the first region. With no levels, jump
            // straight to the special primary.
            if self.levels.is_empty() {
                scan.phase = ScanPhase::Primary;
                scan.region.enter(self.overflow.primary());
            } else {
                scan.region.enter(&self.levels[0]);
            }
        }
        loop {
            if let Some((ptr, slot_idx)) = scan.region.step::<SlotEntry<K, V>>() {
                return Some((ptr, scan.location_at(slot_idx)));
            }
            // Current region exhausted: advance, re-deriving the region pointer
            // from `&self`.
            match scan.phase {
                ScanPhase::Levels => {
                    scan.level_idx += 1;
                    if scan.level_idx < self.levels.len() {
                        scan.region.enter(&self.levels[scan.level_idx]);
                    } else {
                        scan.phase = ScanPhase::Primary;
                        scan.region.enter(self.overflow.primary());
                    }
                }
                ScanPhase::Primary => {
                    scan.phase = ScanPhase::Fallback;
                    scan.region.enter(self.overflow.fallback());
                }
                ScanPhase::Fallback => {
                    scan.phase = ScanPhase::Done;
                    return None;
                }
                ScanPhase::Done => return None,
            }
        }
    }
}

#[allow(private_interfaces)]
impl<K, V, S, A> map::TableBackend<K, V> for FunnelTable<K, V, S, A>
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    type Location = SlotLocation;
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
        self.len
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
    fn reserve_fraction(&self) -> f64 {
        self.reserve_fraction
    }

    #[inline]
    unsafe fn slot_ref(&self, loc: SlotLocation) -> &SlotEntry<K, V> {
        unsafe { self.slot_ref(loc) }
    }

    #[inline]
    unsafe fn slot_ptr(&self, loc: SlotLocation) -> *mut SlotEntry<K, V> {
        unsafe { self.slot_ptr_at(loc) }
    }

    #[inline]
    fn replace_value(&mut self, loc: SlotLocation, value: V) -> V {
        self.replace_existing_value(loc, value)
    }

    // -- Lookup --

    #[inline]
    fn find<Q>(&self, key: &Q, hash: u64, fingerprint: u8) -> Option<SlotLocation>
    where
        Q: Hash + Equivalent<K> + ?Sized,
    {
        self.find_slot_location_with_hash(key, hash, fingerprint)
    }

    // -- Insert / remove --

    #[inline]
    fn insert_for_vacant(&mut self, key: K, value: V, hash: u64) -> SlotLocation {
        self.insert_for_vacant_entry(key, value, hash)
    }

    fn insert(&mut self, key: K, value: V, key_hash: u64) -> Option<V>
    where
        K: Hash + Eq,
    {
        let key_fingerprint = control::control_fingerprint(key_hash);

        // One pass over levels: on match replace; on miss keep the first free
        // slot as the insertion candidate.
        let mut candidate: Option<SlotLocation> = None;
        let (found, miss) =
            self.find_in_levels(&key, key_hash, key_fingerprint, Some(&mut candidate));
        if let Some(location) = found {
            return Some(self.replace_existing_value(location, value));
        }

        // Skip the special-array dedup when the chain ended clean (no overflow
        // possible) or special is empty — place at the level candidate.
        if (matches!(miss, LevelMiss::ChainClean) || self.overflow.len() == 0)
            && let Some(SlotLocation::Level {
                level_idx,
                slot_idx,
            }) = candidate
        {
            if self.len < self.max_insertions {
                self.place_new_level_entry(level_idx, slot_idx, key, value, key_fingerprint);
                return None;
            }
            return self.insert_at_location_after_resize_check(
                candidate,
                key_hash,
                key,
                value,
                key_fingerprint,
            );
        }

        // Cold: key may have overflowed to special; probe it for a match.
        if let Some(location) =
            self.find_in_special(&key, key_hash, key_fingerprint, Some(&mut candidate))
        {
            return Some(self.replace_existing_value(location, value));
        }

        self.insert_at_location_after_resize_check(candidate, key_hash, key, value, key_fingerprint)
    }

    fn remove(&mut self, loc: SlotLocation) -> (K, V) {
        // Common level case: take + erase + counters + cleanup decision behind
        // one level borrow, not four re-resolutions of `levels[level_idx]`.
        let (kv, needs_cleanup) = match loc {
            SlotLocation::Level {
                level_idx,
                slot_idx,
            } => {
                let level = &mut self.levels[level_idx];
                // SAFETY: caller passes a live location found in this table.
                let removed = unsafe { level.take(slot_idx) };
                if level.erase(slot_idx) {
                    level.tombstones += 1;
                }
                level.len -= 1;
                let needs_cleanup = level.tombstones as usize
                    > capacity::tombstone_cleanup_threshold(level.capacity());
                self.len -= 1;
                ((removed.key, removed.value), needs_cleanup)
            }
            special => (
                self.take_and_tombstone(special),
                self.region_needs_cleanup(special),
            ),
        };
        self.shrink_max_populated_level();
        if needs_cleanup {
            self.resize(self.total_slots);
        }
        kv
    }

    #[inline]
    fn tombstone_slot(&mut self, location: SlotLocation) {
        self.erase_location(location);
    }

    #[inline]
    fn extract_finish(&mut self, location: SlotLocation) {
        self.finish_counted_removal(location);
    }

    // -- Iterate --

    type Scan = FunnelScan;

    #[inline]
    fn scan(&self) -> FunnelScan {
        FunnelScan {
            phase: ScanPhase::Levels,
            level_idx: 0,
            region: RegionCursor::new(),
        }
    }

    #[inline]
    fn scan_next(&self, scan: &mut FunnelScan) -> Option<(*mut SlotEntry<K, V>, SlotLocation)> {
        // Hot path: another occupied slot in the region the cursor already holds.
        if scan.region.started()
            && let Some((ptr, slot_idx)) = scan.region.step::<SlotEntry<K, V>>()
        {
            return Some((ptr, scan.location_at(slot_idx)));
        }
        self.scan_advance(scan)
    }

    // -- Lifecycle --

    #[inline]
    fn with_capacity_and_reserve_fraction_and_hasher_in(
        capacity: usize,
        reserve_fraction: f64,
        hash_builder: S,
        alloc: A,
    ) -> Self {
        Self::with_capacity_and_reserve_fraction_and_hasher_in(
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
    fn try_resize(&mut self, new_capacity: usize) -> Result<(), TryReserveError>
    where
        S: Clone,
    {
        self.try_resize(new_capacity)
    }

    #[inline]
    fn clear(&mut self) {
        self.clear();
    }

    fn wipe_all(&mut self) {
        self.wipe_all();
    }

    fn clone_table(&self) -> Self
    where
        K: Clone,
        V: Clone,
        S: Clone,
    {
        self.clone_storage()
    }
}

/// Three-phase region of a [`FunnelScan`]: walk all bucket levels, then the
/// special primary, then the special fallback.
#[derive(Clone, Copy)]
enum ScanPhase {
    Levels,
    Primary,
    Fallback,
    Done,
}

/// Track [`map::TableBackend::scan`] across levels, primary, and fallback without
/// retaining pointers between calls.
#[derive(Clone)]
pub struct FunnelScan {
    phase: ScanPhase,
    level_idx: usize,
    region: RegionCursor,
}

impl FunnelScan {
    /// Maps `slot_idx` in the cursor's current region to its [`SlotLocation`].
    /// Shared by the hot and cold `scan_next` paths.
    #[inline]
    fn location_at(&self, slot_idx: usize) -> SlotLocation {
        match self.phase {
            ScanPhase::Levels => SlotLocation::Level {
                level_idx: self.level_idx,
                slot_idx,
            },
            ScanPhase::Primary => SlotLocation::SpecialPrimary { slot_idx },
            ScanPhase::Fallback => SlotLocation::SpecialFallback { slot_idx },
            // `step` returns `None` on an empty region, so the cursor never
            // yields once the phase machine reaches `Done`.
            ScanPhase::Done => unreachable!("cursor empty in Done phase"),
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

    // The closed-form guess may be off by a few buckets — its sum doesn't
    // always hit `total_buckets` exactly under integer rounding. Search
    // outward by `radius` until a valid sequence is found.
    //
    // Worst case `O(total_buckets · level_count)`; in practice `radius`
    // stays at a small constant.
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

impl<K, V, S, A> FunnelTable<K, V, S, A>
where
    K: Clone,
    V: Clone,
    S: Clone,
    A: Allocator + Clone,
{
    /// Deep-clones storage + hasher + allocator. Backs the
    /// [`map::TableBackend::clone_table`] impl; the [`map::HashMap`] shell provides the
    /// public [`Clone`].
    fn clone_storage(&self) -> Self {
        // Build level_bucket_counts from existing level descriptors.
        let bucket_width = align::round_up_to_group(compute_bucket_width(self.reserve_fraction));
        let primary_ctrl = self.overflow.primary().capacity as usize;
        let fallback_ctrl = self.overflow.fallback().capacity as usize;
        // Use stored `bucket_count`: pow2 for hot levels (idempotent under
        // `build_regions`), exact paper count for cold. `bucket_count_mask` would
        // read the `u32::MAX` sentinel.
        let level_bucket_counts: Vec<usize> = self
            .levels
            .iter()
            .map(|l| l.bucket_count as usize)
            .collect();
        let fallback_bucket_size = (self.overflow.primary_probe_limit.saturating_mul(2)).max(2);

        let (arena, levels, special) = FunnelGeometry::new(
            &level_bucket_counts,
            bucket_width,
            primary_ctrl,
            fallback_ctrl,
            fallback_bucket_size,
        )
        .alloc(&self.alloc);

        // Drop guard: if a user-provided `Clone` impl panics inside
        // [`clone_region_panic_safe`], walk every region's OCCUPIED ctrls to
        // drop already-cloned values, then deallocate the partially-built arena.
        // `Arena` has no `Drop`, so without this the entire arena
        // allocation would leak on unwind.
        let mut guard = arena::ArenaDropGuard::new(
            arena,
            FunnelRegions { levels, special },
            self.alloc.clone(),
        );
        // Panic-safe order: clone value, write slot, then ctrl byte. If a
        // clone panics, only initialized slots carry OCCUPIED ctrls — the
        // guard's `drop_values` walks exactly those.
        for (dst, src_lvl) in guard
            .regions_mut()
            .levels
            .iter_mut()
            .zip(self.levels.iter())
        {
            dst.clone_region_from(src_lvl);
            dst.len = src_lvl.len;
            dst.tombstones = src_lvl.tombstones;
        }

        let special_mut = &mut guard.regions_mut().special;
        {
            let s = self.overflow.primary();
            let d = &mut special_mut.primary;
            d.clone_region_from(s);
            d.len = s.len;
            d.tombstones = s.tombstones;
        }

        {
            let s = self.overflow.fallback();
            let d = &mut special_mut.fallback;
            d.clone_region_from(s);
            d.len = s.len;
            d.tombstones = s.tombstones;
        }

        special_mut.total_len = self.overflow.len();

        // Success: reclaim arena + regions so the guard's Drop no-ops.
        let (arena, FunnelRegions { levels, special }) = guard.disarm();

        let overflow = OverflowHandler::new(special, self.overflow.primary_probe_limit);

        Self {
            levels,
            overflow,
            len: self.len,
            total_slots: self.total_slots,
            max_insertions: self.max_insertions,
            reserve_fraction: self.reserve_fraction,
            max_populated_level: self.max_populated_level,
            hash_builder: self.hash_builder.clone(),
            alloc: self.alloc.clone(),
            arena,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::hash::{BuildHasher, Hasher};

    use crate::common::config::DEFAULT_RESERVE_FRACTION;

    /// Every key hashes to 0, so all collide into bucket 0 of each level and,
    /// once those fill, into the special array — deterministic, seed-free.
    struct ConstHasher;
    impl Hasher for ConstHasher {
        fn finish(&self) -> u64 {
            0
        }
        fn write(&mut self, _: &[u8]) {}
    }
    struct ConstHashBuilder;
    impl BuildHasher for ConstHashBuilder {
        type Hasher = ConstHasher;
        fn build_hasher(&self) -> Self::Hasher {
            ConstHasher
        }
    }

    #[test]
    fn resize_scheduler_owns_pending_entries_and_checked_growth() {
        let mut scheduler = ResizeScheduler::new(64, vec![(1, 10), (2, 20)]);
        assert_eq!(scheduler.target(), 64);
        assert_eq!(scheduler.pending.len(), 2);
        assert_eq!(scheduler.advance_target(), Ok(128));
        assert_eq!(scheduler.target(), 128);
    }

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
        let table = map.table();
        let level_capacity: usize = table.levels.iter().map(BucketLevel::capacity).sum();
        let special_capacity =
            table.overflow.special.primary.capacity() + table.overflow.special.fallback.capacity();
        let total = level_capacity + special_capacity;
        assert!(
            total >= requested,
            "total={total} below requested={requested}"
        );
    }

    /// Recompute `(bucket_width, paper_bucket_counts)` from a table's geometry,
    /// mirroring the constructor. Counts are the raw §5 partition, pre-rounding.
    fn paper_geometry(total_slots: usize, reserve_fraction: f64) -> (usize, Vec<usize>) {
        let level_count = compute_level_count(reserve_fraction);
        let bucket_width = align::round_up_to_group(compute_bucket_width(reserve_fraction));
        let special_capacity = choose_special_capacity(total_slots, reserve_fraction, bucket_width);
        let mut main_capacity = total_slots.saturating_sub(special_capacity);
        main_capacity -= main_capacity % bucket_width.max(1);
        let total_main_buckets = main_capacity.checked_div(bucket_width).unwrap_or(0);
        // Mirror `FunnelGeometry::new`: round `bucket_width` up to a power of two.
        let bucket_width = bucket_width.next_power_of_two();
        (
            bucket_width,
            partition_funnel_buckets(total_main_buckets, level_count),
        )
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Large geometry-only allocation is too slow under Miri.
    fn funnel_layout_keeps_exact_bucket_counts_for_cold_levels() {
        let map: FunnelHashMap<u64, u64> = FunnelHashMap::with_capacity(2_000_000);
        let table = map.table();
        let levels = &table.levels;
        assert!(
            levels.len() > FUNNEL_POW2_LEVELS,
            "need a cold level; got {}",
            levels.len()
        );

        let (_, paper_counts) = paper_geometry(table.total_slots, table.reserve_fraction);
        assert!(
            paper_counts[FUNNEL_POW2_LEVELS] > 0,
            "cold level under test must be non-empty: {paper_counts:?}"
        );

        let cold = &levels[FUNNEL_POW2_LEVELS];
        assert_eq!(
            cold.bucket_count_mask,
            u32::MAX,
            "cold level must use modulo routing"
        );
        // Exact paper count, not a pow2 round-up.
        assert_eq!(cold.bucket_count as usize, paper_counts[FUNNEL_POW2_LEVELS]);

        // Hot levels keep pow2 + `& mask` routing.
        for hot in &levels[..FUNNEL_POW2_LEVELS] {
            if hot.bucket_count != 0 {
                assert_ne!(
                    hot.bucket_count_mask,
                    u32::MAX,
                    "hot level must use mask routing"
                );
                assert_eq!(
                    hot.bucket_count_mask,
                    hot.bucket_count - 1,
                    "pow2 level: mask == count - 1"
                );
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Large geometry-only allocation is too slow under Miri.
    fn cold_exact_counts_shrink_the_arena() {
        let map: FunnelHashMap<u64, u64> = FunnelHashMap::with_capacity(2_000_000);
        let table = map.table();
        let (bw, paper_counts) = paper_geometry(table.total_slots, table.reserve_fraction);

        let pow2_ctrl: usize = paper_counts
            .iter()
            .map(|&bc| {
                if bc == 0 {
                    0
                } else {
                    bc.next_power_of_two() * bw
                }
            })
            .sum();
        let exact_ctrl: usize = paper_counts
            .iter()
            .enumerate()
            .map(|(i, &bc)| {
                if bc == 0 {
                    0
                } else if i < FUNNEL_POW2_LEVELS {
                    bc.next_power_of_two() * bw
                } else {
                    bc * bw
                }
            })
            .sum();
        assert!(
            exact_ctrl < pow2_ctrl,
            "cold-exact must cut ctrl bytes: {exact_ctrl} !< {pow2_ctrl}"
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
            map.table().overflow.primary().group_count_mask,
            0,
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
    fn clear_then_reinsert_preserves_entries() {
        // Assert preservation (len + retrievable), not placement: which entries
        // reach the special array is distribution-dependent, never zero-guaranteed.
        let mut map: FunnelHashMap<u64, u64> = FunnelHashMap::with_capacity(512);
        for i in 0..384 {
            map.insert(i, i ^ 0xa5a5);
        }
        map.clear();

        for i in 512..896 {
            map.insert(i, i ^ 0x5a5a);
        }

        assert_eq!(map.len(), 384);
        for i in 512..896 {
            assert_eq!(map.get(&i), Some(&(i ^ 0x5a5a)));
        }
    }

    #[test]
    fn clear_empties_the_special_array() {
        // All keys collide into the special array; clear must empty it, so
        // `overflow.len() == 0` after clear is a real invariant here.
        let mut map: FunnelHashMap<u64, u64, ConstHashBuilder> =
            FunnelHashMap::with_capacity_and_hasher(512, ConstHashBuilder);
        let budget = u64::try_from(map.capacity()).expect("capacity fits u64");
        let mut inserted = 0;
        while map.table().overflow.len() == 0 && inserted < budget {
            map.insert(inserted, inserted);
            inserted += 1;
        }
        assert!(
            map.table().overflow.len() > 0,
            "all-colliding keys should populate the special array"
        );

        map.clear();
        assert_eq!(map.len(), 0);
        assert_eq!(map.table().overflow.len(), 0);
    }

    #[test]
    fn level_tombstone_reuse_decrements_counter() {
        let mut map: FunnelHashMap<i32, i32, ConstHashBuilder> =
            FunnelHashMap::with_capacity_and_reserve_fraction_and_hasher_in(
                2048,
                DEFAULT_RESERVE_FRACTION,
                ConstHashBuilder,
                Global,
            );

        let l0_bucket_size = 1usize << map.table().levels[0].bucket_size_log2;
        for i in 0..i32::try_from(l0_bucket_size).unwrap() {
            map.insert(i, i);
        }
        assert_eq!(map.table().levels[0].tombstones, 0);

        assert_eq!(map.remove(&0), Some(0));
        assert_eq!(map.table().levels[0].tombstones, 1);

        map.insert(10_000, 10_000);
        assert_eq!(map.table().levels[0].tombstones, 0);
        assert_eq!(map.table().levels[0].len as usize, l0_bucket_size);
        assert_eq!(map.get(&10_000), Some(&10_000));
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
        let mut map: FunnelHashMap<i32, i32, ConstHashBuilder> =
            FunnelHashMap::with_capacity_and_reserve_fraction_and_hasher_in(
                2048,
                DEFAULT_RESERVE_FRACTION,
                ConstHashBuilder,
                Global,
            );
        assert!(
            map.table().levels.len() > 1,
            "test requires multi-level layout"
        );
        let l0_bucket_size =
            i32::try_from(1usize << map.table().levels[0].bucket_size_log2).unwrap();
        // bucket holds at most l0_bucket_size; one more forces a spill.
        for i in 0..=l0_bucket_size {
            map.insert(i, i);
        }
        assert_eq!(
            map.table().max_populated_level,
            1,
            "first bucket overflow should land in A_1, not the special array"
        );
        for i in 0..=l0_bucket_size {
            assert_eq!(map.get(&i), Some(&i));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // Constant-hash special-array search is slow under Miri.
    fn special_array_removal_updates_region_counts_once() {
        let mut map: FunnelHashMap<i32, i32, ConstHashBuilder> =
            FunnelHashMap::with_capacity_and_reserve_fraction_and_hasher_in(
                2048,
                DEFAULT_RESERVE_FRACTION,
                ConstHashBuilder,
                Global,
            );
        let mut inserted = 0i32;
        let max_insertions = i32::try_from(map.capacity()).expect("test capacity fits i32");
        while map.table().overflow.len() == 0 && inserted < max_insertions {
            map.insert(inserted, inserted);
            inserted += 1;
        }
        assert!(
            map.table().overflow.len() > 0,
            "test requires at least one special-array entry"
        );

        let fingerprint = control::control_fingerprint(0);
        let special_key = (0..inserted)
            .find(|key| {
                matches!(
                    map.table()
                        .find_slot_location_with_hash(key, 0, fingerprint),
                    Some(
                        SlotLocation::SpecialPrimary { .. } | SlotLocation::SpecialFallback { .. }
                    )
                )
            })
            .expect("inserted special entry must be findable");

        let before_special = map.table().overflow.len();
        let before_len = map.len();
        assert_eq!(map.remove(&special_key), Some(special_key));
        assert_eq!(map.table().overflow.len(), before_special - 1);
        assert_eq!(map.len(), before_len - 1);
    }

    #[test]
    fn special_fallback_insert_prefers_emptier_bucket() {
        let mut table: FunnelTable<u64, u64, DefaultHashBuilder, Global> =
            FunnelTable::with_capacity_and_reserve_fraction_and_hasher_in(
                2048,
                DEFAULT_RESERVE_FRACTION,
                DefaultHashBuilder::default(),
                Global,
            );
        let fallback = &mut table.overflow.special.fallback;
        assert!(
            fallback.bucket_count > 1,
            "test requires at least two fallback buckets"
        );

        let key_hash = (0u64..10_000)
            .map(|candidate| candidate.wrapping_mul(0x9E37_79B9_7F4A_7C15))
            .find(|&candidate| fallback.bucket_a(candidate) != fallback.bucket_b(candidate))
            .expect("must find two distinct fallback buckets");
        let bucket_a = fallback.bucket_a(key_hash);
        let bucket_b = fallback.bucket_b(key_hash);
        let range_a = fallback.bucket_range(bucket_a);
        let range_b = fallback.bucket_range(bucket_b);
        assert!(
            range_a.len() >= 3 && !range_b.is_empty(),
            "test requires non-empty candidate buckets"
        );

        let occupied = control::control_fingerprint(0xabc);
        fallback.set_control(range_a.start, occupied);
        fallback.set_control(range_a.start + 1, occupied);
        fallback.len = 2;

        assert_eq!(
            table.overflow.first_free_in_special_fallback(key_hash),
            Some(range_b.start),
            "fallback C should choose the emptier of the two paper buckets"
        );
    }

    #[test]
    fn fallback_tombstone_reuse_decrements_counter() {
        let mut table: FunnelTable<u64, u64, DefaultHashBuilder, Global> =
            FunnelTable::with_capacity_and_reserve_fraction_and_hasher_in(
                2048,
                DEFAULT_RESERVE_FRACTION,
                DefaultHashBuilder::default(),
                Global,
            );
        let slot_idx = 0;
        table
            .overflow
            .special
            .fallback
            .set_control(slot_idx, CTRL_TOMBSTONE);
        table.overflow.special.fallback.tombstones = 1;

        table.overflow.place_new_special_fallback_entry(
            slot_idx,
            7,
            11,
            control::control_fingerprint(7),
        );

        assert_eq!(table.overflow.special.fallback.tombstones, 0);
    }

    #[test]
    fn reserve_fraction_clamped_to_funnel_max() {
        // Funnel's correctness proof requires reserve_fraction <= 1/8.
        let map: FunnelHashMap<i32, i32> =
            FunnelHashMap::with_capacity_and_reserve_fraction(256, 0.5);
        assert!(
            map.table().reserve_fraction <= MAX_FUNNEL_RESERVE_FRACTION,
            "reserve_fraction={} not clamped to {MAX_FUNNEL_RESERVE_FRACTION}",
            map.table().reserve_fraction
        );
    }
}
