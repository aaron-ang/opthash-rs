use core::cell::Cell;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::sync::Arc;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::exact::probe::{self, ProbeDomain};
use crate::exact::reference::{ScalarFunnel, ScalarFunnelInsert, ScalarFunnelLocation};
use crate::map::TableBackend;
use crate::test_support::{
    self, CountDrop, HashedKey, IdentityBuildHasher, PanicHashKey, PanicOnFirstDrop,
    ToggleAllocator,
};

std::thread_local! {
    pub(super) static VACANCY_WALKS: Cell<usize> = const { Cell::new(0) };
}

#[derive(Clone, Debug)]
struct CountingKey {
    id: u64,
    comparisons: Arc<AtomicUsize>,
}

impl PartialEq for CountingKey {
    fn eq(&self, other: &Self) -> bool {
        self.comparisons.fetch_add(1, Ordering::Relaxed);
        self.id == other.id
    }
}

impl Eq for CountingKey {}

impl Hash for CountingKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        // Each even key has an absent odd partner with the same hash.
        (self.id / 2).hash(state);
    }
}

/// What the ordered walk reports for a key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Walked {
    Hit(usize),
    /// The first free slot of the walk, for a key it does not hold.
    Vacant(usize),
    Full,
}

/// The ordered walk one control at a time: the key's bucket in each ordinary
/// level, shallowest first, then the primary probes, then the two fallback
/// buckets a lane of each in turn. It ends at the key or at the first EMPTY,
/// and every lookup and placement path is held to it.
fn ordered_walk<K, V, S>(table: &FunnelTable<K, V, S>, key: &K, hash: u64) -> Walked
where
    K: Eq + Hash,
    S: BuildHasher,
{
    type Table<K, V, S> = FunnelTable<K, V, S>;
    let shape = &table.shape;
    let probe = table.prf.prepare(hash);
    let mut slots = Vec::new();
    let special = |slots: &mut Vec<usize>| {
        let primary = probe.prepare_counter_base(FUNNEL_SPECIAL_PRIMARY_BASE);
        for logical in 0..shape.loglog_ceiling {
            let code = shape.encode_logical_probe(logical);
            let local = Table::<K, V, S>::sample(&primary, code, shape.primary_range)?;
            slots.push(shape.primary_offset + local);
        }
        let first = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_A_BASE);
        let first = Table::<K, V, S>::sample(&first, 0, shape.fallback_bucket_range)?;
        let second = probe.prepare_counter_base(FUNNEL_SPECIAL_FALLBACK_B_BASE);
        let second = Table::<K, V, S>::sample(&second, 0, shape.fallback_bucket_range)?;
        for lane in 0..shape.fallback_bucket_width {
            for bucket in [first, second] {
                slots.push(shape.fallback_offset + bucket * shape.fallback_bucket_width + lane);
            }
        }
        Some(())
    };
    if shape.n != 0 {
        for level in &shape.levels {
            let bucket = Table::<K, V, S>::sample_ordinary(probe, level);
            slots.extend(bucket_slots(shape, level, bucket));
        }
        special(&mut slots);
    }

    let mut vacant = None;
    for slot in slots {
        // SAFETY: every slot of the walk is one of the storage's, and a
        // fingerprint control marks an initialized entry.
        match unsafe { table.storage.control_at(slot) } {
            CTRL_EMPTY => return Walked::Vacant(vacant.unwrap_or(slot)),
            CTRL_TOMBSTONE => {
                vacant.get_or_insert(slot);
            }
            control if control == probe.fingerprint() => {
                // SAFETY: as above.
                if unsafe { table.storage.get_ref(slot) }.key == *key {
                    return Walked::Hit(slot);
                }
            }
            _ => {}
        }
    }
    vacant.map_or(Walked::Full, Walked::Vacant)
}

#[derive(Clone, Copy, Debug)]
enum VacantPath {
    Entry,
    TryInsert,
    GetOrInsertKey,
}

#[test]
fn vacant_paths_place_without_a_walk_unless_the_table_grows() {
    use VacantPath::{Entry, GetOrInsertKey, TryInsert};

    for path in [Entry, TryInsert, GetOrInsertKey] {
        // (requested capacity, fill to growth, tombstone on the walk)
        for (requested, full, tombstone) in
            [(64, false, false), (64, false, true), (32, true, false)]
        {
            let comparisons = Arc::new(AtomicUsize::new(0));
            let key = |id| CountingKey {
                id,
                comparisons: comparisons.clone(),
            };
            let mut map =
                FunnelHashMap::with_capacity_and_hasher(requested, test_support::fixed_hasher());
            let capacity = map.capacity();
            let live = if full { capacity } else { 1 };
            for id in 0..live as u64 {
                map.insert(key(2 * id), id);
            }
            if tombstone {
                map.insert(key(1), 0);
                map.remove(&key(1));
                assert_eq!(tombstone_controls(map.table()), 1);
            }
            comparisons.store(0, Ordering::Relaxed);
            VACANCY_WALKS.with(|walks| walks.set(0));
            match path {
                Entry => assert_eq!(*map.entry(key(1)).or_insert(99), 99),
                TryInsert => assert_eq!(*map.try_insert(key(1), 99).unwrap(), 99),
                GetOrInsertKey => {
                    assert_eq!(map.get_or_insert_key_with(&key(1), 99, Clone::clone).id, 1);
                }
            }
            let walks = VACANCY_WALKS.with(Cell::get);
            let label = format!("{path:?} full={full} tombstone={tombstone}");
            if full {
                // Rebuild places each old key from the head walk; the new key
                // needs its own fresh walk.
                assert!(comparisons.load(Ordering::Relaxed) > 0, "{label}");
                assert_eq!(walks, 1, "{label}");
                assert!(map.capacity() > capacity, "{label}");
            } else {
                assert_eq!(comparisons.load(Ordering::Relaxed), 1, "{label}");
                assert_eq!(walks, 0, "{label}: the head takes the key");
                assert_eq!(map.capacity(), capacity, "{label}");
            }
            assert_eq!(map.len(), live + 1, "{label}");
            for id in 0..live as u64 {
                assert_eq!(map.get(&key(2 * id)), Some(&id), "{label}");
            }
            assert_eq!(map.get(&key(1)), Some(&99), "{label}");
        }
    }
}

#[test]
fn entry_search_checks_exceptional_hits_before_reporting_a_key_absent() {
    let mut table = raw_table(512, 3);
    let key = 42;
    let fingerprint = table.prf.prepare(key).fingerprint();
    let exact = ordered_walk(&table, &key, key);
    let slot = table.shape.slots - 1;
    assert_ne!(exact, Walked::Vacant(slot));
    table.place_new_entry(
        table.vacancy_at(slot),
        key,
        7,
        table.membership_slot(key),
        fingerprint,
        true,
    );
    assert_eq!(table.find_for_entry(&key, key).ok(), Some(slot));

    // A different key with the same hash must complete the exceptional
    // scan before it is reported absent.
    let vacant = table.find_for_entry(&99, key).err().unwrap();
    VACANCY_WALKS.with(|walks| walks.set(0));
    let inserted = table.insert_for_vacant(99, 8, vacant);
    assert_eq!(VACANCY_WALKS.with(Cell::get), 0);
    assert_eq!(exact, Walked::Vacant(inserted));
    assert_eq!(table.find(&99, key), Some(inserted));
    assert_eq!(table.find(&key, key), Some(slot));
}

/// A key the filter rejects reaches its vacant entry unsearched, and the
/// entry's insert then places it through the head walk: no comparison and
/// no general placement walk.
#[test]
fn vacant_entry_filter_rejection_places_through_the_head_walk() {
    let comparisons = Arc::new(AtomicUsize::new(0));
    let key = CountingKey {
        id: 1,
        comparisons: comparisons.clone(),
    };
    let mut map = FunnelHashMap::with_capacity_and_hasher(64, test_support::fixed_hasher());
    VACANCY_WALKS.with(|walks| walks.set(0));
    let open = map.table().head_left;
    assert_eq!(*map.entry(key.clone()).or_insert(10), 10);
    assert_eq!(comparisons.load(Ordering::Relaxed), 0);
    assert_eq!(VACANCY_WALKS.with(Cell::get), 0);
    assert_eq!(map.table().head_left, open - 1);
    assert_eq!(map.get(&key), Some(&10));
}

#[test]
fn exhausted_vacant_entry_rebuilds_and_walks_again_before_exceptional_placement() {
    let mut table = raw_table(512, 3);
    let hash = 42;
    let absent = u64::MAX;
    while let Walked::Vacant(_) = ordered_walk(&table, &absent, hash) {
        let key = table.entries() as u64;
        table.insert_for_vacant_by_walk(key, key, hash);
        assert!(table.entries() < table.shape.max_insertions);
    }
    assert_eq!(ordered_walk(&table, &absent, hash), Walked::Full);
    let vacant = table.find_for_entry(&absent, hash).err().unwrap();
    let old_len = table.entries();
    let old_seed = table.prf;
    VACANCY_WALKS.with(|walks| walks.set(0));
    let inserted = table.insert_for_vacant(absent, 99, vacant);

    // The colliding keys were placed under one forced hash; the rebuild
    // rehashes them, so the walk after it finds a vacancy in the funnel.
    assert_eq!(
        VACANCY_WALKS.with(Cell::get),
        2,
        "the walk that finds no vacancy, and the walk after the rebuild"
    );
    assert_eq!(table.entries(), old_len + 1);
    assert_ne!(table.prf, old_seed);
    assert!(!table.exceptional_placement);
    assert_eq!(
        table.epoch_snapshot().transition,
        EpochTransition::PlacementRecovery
    );
    assert_eq!(table.entries(), old_len + 1);
    assert_eq!(table.find(&absent, hash), Some(inserted));
}

/// The slots of bucket `bucket` of `level` in lane order: those of its head
/// group, then those of its tail.
fn bucket_slots(
    shape: &FunnelShape,
    level: &LevelShape,
    bucket: usize,
) -> impl Iterator<Item = usize> + use<> {
    let head = level.offset + bucket * GROUP_SIZE;
    let tail_width = shape.beta.saturating_sub(GROUP_SIZE);
    let tail = level.offset + level.buckets * GROUP_SIZE + bucket * tail_width;
    (head..head + shape.beta.min(GROUP_SIZE)).chain(tail..tail + tail_width)
}

/// The smallest reserve exponent whose buckets are wider than one control
/// group on this target, with its smallest shape.
fn smallest_wide_shape() -> (u32, FunnelShape) {
    (3..=16)
        .map(|d| {
            let reserve = ReserveFraction::from_exponent(d).unwrap();
            (d, FunnelShape::for_insert_budget(1, reserve).unwrap())
        })
        .find(|(_, shape)| shape.beta > GROUP_SIZE)
        .unwrap()
}

fn raw_table(n: usize, d: u32) -> FunnelTable<u64, u64, IdentityBuildHasher> {
    raw_table_of(n, d)
}

fn raw_table_of<V>(n: usize, d: u32) -> FunnelTable<u64, V, IdentityBuildHasher> {
    let reserve = ReserveFraction::from_exponent(d).unwrap();
    FunnelTable::try_from_shape(
        FunnelShape::from_slots(n, reserve).unwrap(),
        reserve,
        IdentityBuildHasher,
        Global,
    )
    .unwrap()
}

/// A table holding all its limit allows still shrinks when a smaller slot
/// count has the same limit.
#[test]
fn shrink_of_a_full_table_drops_the_slots_its_limit_does_not_need() {
    let reserve = ReserveFraction::from_exponent(3).unwrap();
    let (slack, smallest) = (64..4096)
        .find_map(|n| {
            let shape = FunnelShape::from_slots(n, reserve).ok()?;
            let smallest = FunnelShape::for_insert_budget(shape.max_insertions, reserve).ok()?;
            (smallest.n < shape.n).then_some((shape.n, smallest.n))
        })
        .expect("a slot count past the smallest for its limit");
    let mut table = raw_table(slack, 3);
    let limit = table.shape.max_insertions as u64;
    for key in 0..limit {
        assert_eq!(map::TableBackend::insert(&mut table, key, key, key), None);
    }
    map::TableBackend::shrink_to(&mut table, 0);
    assert_eq!(table.shape.n, smallest);
    assert_eq!(table.shape.max_insertions as u64, limit);
    for key in 0..limit {
        assert!(table.find(&key, key).is_some());
    }
}

/// Whether `slot` is a padding lane of an ordinary bucket, which no entry
/// may occupy.
fn is_padding<V>(table: &FunnelTable<u64, V, IdentityBuildHasher>, slot: usize) -> bool {
    slot < table.shape.primary_offset && slot % GROUP_SIZE >= table.shape.beta
}

#[test]
fn dense_scan_preserves_order_while_removals_make_the_table_sparse() {
    let mut table = raw_table(344, 4);
    let slots = (0..320)
        .filter(|&slot| slot % 11 != 0 && !is_padding(&table, slot))
        .collect::<Vec<_>>();
    for &slot in &slots {
        let key = slot as u64;
        let hash = table.hash_builder.hash_one(key);
        table.place_new_entry(
            table.vacancy_at(slot),
            key,
            key + 100,
            table.membership_slot(hash),
            table.prf.prepare(hash).fingerprint(),
            true,
        );
    }
    let mut scan = map::TableBackend::scan(&table);
    for slot in slots {
        let (ptr, found) = map::TableBackend::scan_next(&table, &mut scan).unwrap();
        assert_eq!(found, slot);
        // SAFETY: `scan_next` yields occupied slots; `extract_finish` tombstones
        // this one before it could be read again.
        let entry = unsafe { ptr.read() };
        assert_eq!((entry.key, entry.value), (slot as u64, slot as u64 + 100));
        map::TableBackend::extract_finish(&mut table, slot);
    }
    assert!(map::TableBackend::scan_next(&table, &mut scan).is_none());
    assert!(map::TableBackend::scan_next(&table, &mut scan).is_none());
    assert_eq!(table.entries(), 0);
}

/// A dense scan of a shape whose buckets are narrower than a group visits
/// every occupied slot once, in slot order, across the padding lanes of the
/// ordinary levels and on into the special arrays, and reads no padding
/// control: one planted to read as occupied is never reported.
#[test]
fn dense_scan_steps_over_bucket_padding_into_the_special_arrays() {
    let reserve = ReserveFraction::from_exponent(3).unwrap();
    let mut table = head_table(
        FunnelShape::for_insert_budget(4_096, reserve).unwrap(),
        reserve,
    );
    assert!(table.shape.beta < GROUP_SIZE);
    let limit = table.shape.max_insertions as u64;
    for key in 0..limit - 2 {
        assert_eq!(map::TableBackend::insert(&mut table, key, key, key), None);
    }
    let special = [table.shape.primary_offset, table.shape.slots - 1];
    for (key, slot) in (limit - 2..).zip(special) {
        // SAFETY: `slot < slots`, the storage capacity.
        assert!(control::is_free(unsafe { table.storage.control_at(slot) }));
        let hash = table.hash_builder.hash_one(key);
        table.place_new_entry(
            table.vacancy_at(slot),
            key,
            key,
            table.membership_slot(hash),
            table.prf.prepare(hash).fingerprint(),
            true,
        );
    }
    // SAFETY: `slot < slots`, the storage capacity.
    let occupied = (0..table.shape.slots)
        .filter(|&slot| control::is_occupied(unsafe { table.storage.control_at(slot) }))
        .collect::<Vec<_>>();
    let planted = (0..table.shape.slots)
        .filter(|&slot| is_padding(&table, slot))
        .step_by(7)
        .collect::<Vec<_>>();
    assert_ne!(planted, [] as [usize; 0]);
    let occupied_control = control::control_fingerprint_low(0);
    for &slot in &planted {
        // SAFETY: `slot < slots`, the storage capacity; the scan below reads
        // only the control, and the padding is restored after it.
        unsafe { table.storage.set_control(slot, occupied_control) };
    }
    assert_eq!(occupied.len(), table.entries());
    let mut scan = map::TableBackend::scan(&table);
    assert!(matches!(scan.mode, FunnelScanMode::Dense(_)));
    let mut scanned = Vec::new();
    while let Some((_, slot)) = map::TableBackend::scan_next(&table, &mut scan) {
        scanned.push(slot);
    }
    assert_eq!(scanned, occupied);
    assert!(map::TableBackend::scan_next(&table, &mut scan).is_none());
    for &slot in &planted {
        // SAFETY: `slot < slots`; this restores the padding control.
        unsafe { table.storage.set_control(slot, CTRL_PADDING) };
    }
}

#[test]
fn sparse_scan_visits_group_boundaries_and_tail_once_in_slot_order() {
    let mut table = raw_table(32_767, 3);
    // Group boundaries in the special arrays, where every lane can hold an
    // entry.
    let base = table.shape.primary_offset.next_multiple_of(GROUP_SIZE);
    let slots = [
        0,
        base + GROUP_SIZE - 1,
        base + GROUP_SIZE,
        base + 3 * GROUP_SIZE + 2,
        table.shape.slots - 1,
    ];
    assert!(slots.is_sorted() && slots[3] < slots[4]);
    for slot in slots {
        assert!(!is_padding(&table, slot), "slot {slot}");
        let key = slot as u64;
        let hash = table.hash_builder.hash_one(key);
        table.place_new_entry(
            table.vacancy_at(slot),
            key,
            key + 100,
            table.membership_slot(hash),
            table.prf.prepare(hash).fingerprint(),
            true,
        );
    }
    // Include a deleted slot next to a live slot in a cached group.
    // SAFETY: the slot lies between two placed slots.
    unsafe { table.storage.mark_tombstone(base + GROUP_SIZE + 1) };
    let mut scan = map::TableBackend::scan(&table);
    for slot in slots {
        let (ptr, found) = map::TableBackend::scan_next(&table, &mut scan).unwrap();
        assert_eq!(found, slot);
        // SAFETY: `scan_next` yields occupied slots.
        assert_eq!(unsafe { (*ptr).value }, slot as u64 + 100);
        // Draining changes control bytes while the cursor holds its mask.
        // SAFETY: as above; `extract_finish` tombstones the slot after the move.
        let entry = unsafe { ptr.read() };
        assert_eq!(entry.key, slot as u64);
        map::TableBackend::extract_finish(&mut table, slot);
    }
    assert!(map::TableBackend::scan_next(&table, &mut scan).is_none());
    assert!(map::TableBackend::scan_next(&table, &mut scan).is_none());
    assert_eq!(table.entries(), 0);
}

/// A refresh of a filter no key has left re-records it as the inserts
/// did, level bins included, in shapes whose entries reach from the first
/// level into the special arrays.
#[test]
#[cfg_attr(miri, ignore)]
fn refresh_membership_rebuilds_the_recorded_filter() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut bins = 0;
    for (n, d) in [(344, 4), (4096, 3), (32_767, 3)] {
        let mut table = raw_table(n, d);
        for index in 0..table.shape.max_insertions as u64 {
            let key = index.wrapping_mul(SPREAD);
            table.place_unique(SlotEntry { key, value: index }, key);
        }
        let recorded = filter_tail(&table);
        bins |= recorded
            .iter()
            .fold(0, |bins, unit| bins | unit_levels(*unit));
        table.clear_membership();
        table.refresh_membership();
        assert_eq!(filter_tail(&table), recorded, "n {n} d {d}");
    }
    assert_ne!(bins & OVERFLOW_LEVEL_BIT, 0);
    assert!((bins & !OVERFLOW_LEVEL_BIT).count_ones() > 4);
}

/// Every unit of `table`'s filter tail, level bin and membership alike.
fn filter_tail<V>(table: &FunnelTable<u64, V, IdentityBuildHasher>) -> Vec<FilterUnit> {
    let units = table.membership.region.words;
    // SAFETY: the tail holds `units` initialized units from its base on; a
    // table without any reads none.
    unsafe { core::slice::from_raw_parts(table.membership_ptr(), units).to_vec() }
}

/// Every control byte and filter word of `table`.
fn controls_and_filter<V>(
    table: &FunnelTable<u64, V, IdentityBuildHasher>,
) -> (Vec<u8>, Vec<FilterUnit>) {
    // SAFETY: `slot < slots`, the storage capacity.
    let controls = (0..table.shape.slots)
        .map(|slot| unsafe { table.storage.control_at(slot) })
        .collect();
    (controls, filter_tail(table))
}

/// Replacing a present key swaps it where it sits: every control, the
/// filter, each count and the epoch stay as they were, in a table without
/// tombstones and in one with them. An absent key is inserted.
#[test]
fn replace_key_leaves_the_table_of_a_present_key_as_it_was() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    const KEYS: u64 = 600;
    type Map = FunnelHashMap<u64, u64, IdentityBuildHasher>;

    fn state(map: &Map) -> impl PartialEq + use<> {
        let table = map.table();
        (
            controls_and_filter(table),
            [
                table.entries(),
                table.tombstone_bound(),
                table.stale_membership(),
                table.head_left,
            ],
            map::TableBackend::epoch_snapshot(table),
        )
    }

    let mut map =
        Map::with_capacity_and_hasher(usize::try_from(KEYS).unwrap(), IdentityBuildHasher);
    for index in 0..KEYS {
        map.insert(index.wrapping_mul(SPREAD), index);
    }
    for removed in [0, 3] {
        for index in (0..KEYS).step_by(removed.max(1)).take(removed * 50) {
            assert_eq!(map.remove(&index.wrapping_mul(SPREAD)), Some(index));
        }
        assert_eq!(tombstone_controls(map.table()) != 0, removed != 0);
        let before = state(&map);
        let present = map.len();
        for index in 0..KEYS {
            let key = index.wrapping_mul(SPREAD);
            if map.contains_key(&key) {
                assert_eq!(map.replace_key(key, u64::MAX), Some(key));
                assert_eq!(map.get(&key), Some(&index));
            }
        }
        assert_eq!(map.len(), present);
        assert!(state(&map) == before, "removed {removed}");
    }
    let absent = KEYS.wrapping_mul(SPREAD);
    let len = map.len();
    assert_eq!(map.replace_key(absent, 7), None);
    assert_eq!(map.get(&absent), Some(&7));
    assert_eq!(map.len(), len + 1);
}

/// The reference side inserts through the vacant-entry placement walk, which
/// shares no lookup or vacancy code with the frameless insert.
#[test]
#[cfg_attr(miri, ignore)]
fn frameless_insert_places_and_records_like_the_placement_walk() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let (wide, wide_shape) = smallest_wide_shape();
    for (n, d) in [
        (344, 4),
        (4096, 3),
        (1 << 14, 3),
        (wide_shape.n, wide),
        (21_856, 10),
    ] {
        let mut inline = raw_table(n, d);
        let mut walked = raw_table(n, d);
        let budget = inline.shape.max_insertions as u64;
        for index in 0..budget {
            let key = index.wrapping_mul(SPREAD);
            assert_eq!(
                map::TableBackend::insert(&mut inline, key, index, key),
                None
            );
            let slot = walked.insert_for_vacant_by_walk(key, index, key);
            assert_eq!(
                inline.find(&key, key),
                Some(slot),
                "n {n} d {d} index {index}"
            );
        }
        assert_eq!(inline.entries(), walked.entries());
        assert_eq!(controls_and_filter(&inline), controls_and_filter(&walked));
        for index in 0..budget {
            let key = index.wrapping_mul(SPREAD);
            assert_eq!(
                map::TableBackend::insert(&mut inline, key, index + 1, key),
                Some(index)
            );
            assert_eq!(
                map::TableBackend::find_entry(&inline, &key, key).map(|entry| entry.value),
                Some(index + 1)
            );
        }
        assert_eq!(inline.entries(), walked.entries());
        assert_eq!(controls_and_filter(&inline), controls_and_filter(&walked));
        // The budget is spent, so an unrecorded key grows the table first.
        let key = (budget..2 * budget)
            .map(|index| index.wrapping_mul(SPREAD))
            .find(|&key| !inline.membership_gate(key).passes())
            .unwrap();
        assert_eq!(inline.entries(), inline.shape.max_insertions);
        assert_eq!(map::TableBackend::insert(&mut inline, key, 0, key), None);
        assert!(inline.shape.n > n, "n {n} d {d}");
        assert!(inline.entries() <= inline.shape.max_insertions);
    }
}

/// A rebuild places each survivor where the placement walk would, in slot
/// order, and records it the same way.
#[test]
#[cfg_attr(miri, ignore)]
fn rebuild_places_and_records_like_the_placement_walk() {
    let (wide, wide_shape) = smallest_wide_shape();
    for (n, d) in [
        (344, 4),
        (4096, 3),
        (1 << 14, 3),
        (wide_shape.n, wide),
        (21_856, 10),
    ] {
        let rebuilt = assert_rebuild_matches_placement_walk(n, d, |index| index);
        assert!(!rebuild_prefetches(&rebuilt), "n {n} d {d}");
    }
}

/// [`rebuild_places_and_records_like_the_placement_walk`] over a table large
/// enough for the rebuild to hash ahead of its placements. Wide values reach
/// that size in few slots.
#[test]
fn prefetching_rebuild_places_and_records_like_the_placement_walk() {
    const BUDGET: usize = 300;
    type WideValue = [u64; 2047];
    let narrow = ReserveFraction::from_exponent(3).unwrap();
    let n = FunnelShape::for_insert_budget(BUDGET, narrow).unwrap().n;
    let rebuilt =
        assert_rebuild_matches_placement_walk(n, 3, |index| -> WideValue { [index; 2047] });
    assert!(rebuilt.shape.beta <= GROUP_SIZE, "no head placement");
    assert!(rebuild_prefetches(&rebuilt));

    if cfg!(miri) {
        return;
    }
    let (wide, _) = smallest_wide_shape();
    let reserve = ReserveFraction::from_exponent(wide).unwrap();
    let n = FunnelShape::for_insert_budget(BUDGET, reserve).unwrap().n;
    let rebuilt =
        assert_rebuild_matches_placement_walk(n, wide, |index| -> WideValue { [index; 2047] });
    assert!(rebuilt.shape.beta > GROUP_SIZE);
    assert!(rebuild_prefetches(&rebuilt));
}

/// Whether a rebuild out of `table` hashes ahead of its placements.
fn rebuild_prefetches<V>(table: &FunnelTable<u64, V, IdentityBuildHasher>) -> bool {
    table.shape.slots * size_of::<SlotEntry<u64, V>>() >= rebuild::PREFETCH_MIN_BYTES
}

/// Fills a table of `n` slots, tombstones a third of it, rebuilds it at the
/// same size and compares it with a table the survivors were inserted into
/// through the placement walk. Returns the rebuilt table.
fn assert_rebuild_matches_placement_walk<V>(
    n: usize,
    d: u32,
    value_of: impl Fn(u64) -> V,
) -> FunnelTable<u64, V, IdentityBuildHasher>
where
    V: Copy + PartialEq + core::fmt::Debug,
{
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut rebuilt = raw_table_of::<V>(n, d);
    let budget = rebuilt.shape.max_insertions as u64;
    let key_of = |index: u64| {
        let key = index.wrapping_mul(SPREAD);
        (key ^ (key >> 32)).wrapping_mul(SPREAD)
    };
    for index in 0..budget {
        let key = key_of(index);
        assert!(map::TableBackend::insert(&mut rebuilt, key, value_of(index), key).is_none());
    }
    // Tombstones, so the rebuild has slots to reclaim.
    for index in (0..budget).step_by(3) {
        let key = key_of(index);
        let slot = rebuilt.find(&key, key).unwrap();
        map::TableBackend::remove(&mut rebuilt, slot);
    }
    let mut survivors = Vec::new();
    let mut scan = OccupiedIndices::new();
    while let Some(slot) = scan.step(&rebuilt.storage) {
        // SAFETY: `step` yields occupied in-bounds slots.
        let entry = unsafe { rebuilt.storage.get_ref(slot) };
        survivors.push((entry.key, entry.value));
    }
    rebuilt.resize_with_transition(n, EpochTransition::ExplicitResize);

    let mut walked = raw_table_of::<V>(n, d);
    for &(key, value) in &survivors {
        walked.insert_for_vacant_by_walk(key, value, key);
    }
    assert_eq!(rebuilt.entries(), survivors.len(), "n {n} d {d}");
    assert_eq!(rebuilt.head_left, walked.head_left, "n {n} d {d}");
    assert_eq!(tombstone_controls(&rebuilt), 0);
    assert!(
        controls_and_filter(&rebuilt) == controls_and_filter(&walked),
        "n {n} d {d}"
    );
    for &(key, value) in &survivors {
        assert_eq!(
            map::TableBackend::find_entry(&rebuilt, &key, key).map(|entry| entry.value),
            Some(value)
        );
    }
    rebuilt
}

/// Removals and inserts in turn, through the calls a map makes: each insert
/// stores its key where the placement walk would put it, rebuilds nothing,
/// and leaves the table holding what a model map holds. The turns take back
/// the key just removed or a new one, alone or two at a time, at half the
/// insertion limit and at the limit, for long enough to refresh the filter
/// and to carry the tombstone bound past the cleanup threshold.
#[test]
#[cfg_attr(miri, ignore)]
fn churn_places_like_the_placement_walk_and_never_rebuilds() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;

    for (n, d, fill) in [(4096, 3, 2), (4096, 3, 1), (1 << 14, 3, 1)] {
        let mut table = raw_table(n, d);
        let budget = table.shape.max_insertions as u64;
        let mut model = alloc::collections::BTreeMap::new();
        let mut live = (0..budget / fill).collect::<Vec<_>>();
        for &index in &live {
            let key = index.wrapping_mul(SPREAD);
            map::TableBackend::insert(&mut table, key, index, key);
            model.insert(key, index);
        }
        let generation = table.epoch_snapshot().generation;
        let mut fresh = budget;
        let threshold = capacity::tombstone_cleanup_threshold(table.shape.n);
        let (mut taken_back, mut reopened, mut refreshed, mut past_threshold) = (0, 0, 0, 0);
        for turn in 0..3 * table.shape.max_insertions {
            let pairs = if turn % 7 == 6 { 2 } else { 1 };
            let mut removed = Vec::new();
            for pair in 0..pairs {
                let at = (turn * 31 + pair) % live.len();
                let index = live.swap_remove(at);
                let key = index.wrapping_mul(SPREAD);
                let stale = table.stale_membership();
                assert_eq!(
                    map::TableBackend::take(&mut table, &key, key),
                    model.remove(&key).map(|value| (key, value)),
                    "n {n} turn {turn}"
                );
                refreshed += usize::from(table.stale_membership() < stale);
                removed.push(index);
            }
            for index in removed {
                let index = if turn % 2 == 0 {
                    index
                } else {
                    fresh += 1;
                    fresh
                };
                let key = index.wrapping_mul(SPREAD);
                let probe = table.prf.prepare(key);
                let walk = table.search_vacancy(probe).unwrap();
                // A key with no free lane in the head goes by the walk.
                if let Some(head) = table.first_free_in_head(probe) {
                    assert_eq!(
                        walk.slot,
                        table.slot_of(NonNull::new(head.lane).unwrap()),
                        "n {n} turn {turn}"
                    );
                }
                // SAFETY: the walk's slot is below the storage capacity.
                let control = unsafe { table.storage.control_at(walk.slot) };
                taken_back += usize::from(control == CTRL_TOMBSTONE);
                reopened += usize::from(table.head_left == 0);
                past_threshold += usize::from(table.tombstone_bound() > threshold);
                assert_eq!(
                    map::TableBackend::insert(&mut table, key, index, key),
                    model.insert(key, index),
                    "n {n} turn {turn}"
                );
                assert_eq!(table.find(&key, key), Some(walk.slot), "n {n} turn {turn}");
                assert_ne!(
                    table.membership_gate(key).levels() & walk.level_bit,
                    0,
                    "n {n} turn {turn}"
                );
                assert_eq!(table.entries(), model.len(), "n {n} turn {turn}");
                live.push(index);
            }
            if turn % 257 == 0 {
                assert!(tombstone_controls(&table) <= table.tombstone_bound());
            }
        }
        assert_eq!(
            table.epoch_snapshot().generation,
            generation,
            "n {n} fill {fill}"
        );
        assert_ne!(taken_back, 0, "n {n} fill {fill}");
        assert_ne!(refreshed, 0, "n {n} fill {fill}");
        assert_ne!(past_threshold, 0, "n {n} fill {fill}");
        assert_ne!(reopened, 0, "n {n} fill {fill}");
        for (key, value) in &model {
            let slot = table.find(key, *key).unwrap();
            assert_eq!(table.find_entry(key, *key).unwrap().value, *value);
            assert_ne!(
                table.membership_gate(*key).levels() & table.level_bit(slot),
                0
            );
        }
        for index in 0..fresh {
            let key = index.wrapping_mul(SPREAD);
            assert_eq!(table.find(&key, key).is_some(), model.contains_key(&key));
        }
    }
}

/// A table at its insertion limit takes a new key for one it gave up, where
/// the placement walk would put it, and grows for the key after that.
#[test]
#[cfg_attr(miri, ignore)]
fn insert_at_the_limit_fills_the_room_a_delete_made_and_then_grows() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;

    let mut with_tombstones = 0;
    for turn in 0..32_u64 {
        let mut table = raw_table(4096, 3);
        let limit = table.shape.max_insertions;
        let budget = limit as u64;
        for index in 0..budget {
            let key = index.wrapping_mul(SPREAD);
            map::TableBackend::insert(&mut table, key, index, key);
        }
        let slots = table.shape.slots;
        let gone = (turn * 97).wrapping_mul(SPREAD);
        assert_eq!(
            map::TableBackend::take(&mut table, &gone, gone),
            Some((gone, turn * 97))
        );
        let key = (budget + turn).wrapping_mul(SPREAD);
        let walk = table.search_vacancy(table.prf.prepare(key)).unwrap();
        assert_eq!(map::TableBackend::insert(&mut table, key, turn, key), None);
        assert_eq!(table.find(&key, key), Some(walk.slot));
        assert_eq!(table.shape.slots, slots, "turn {turn}");
        assert_eq!(table.entries(), table.shape.max_insertions);
        with_tombstones += usize::from(tombstone_controls(&table) != 0);
        let next = (budget + 32 + turn).wrapping_mul(SPREAD);
        assert_eq!(
            map::TableBackend::insert(&mut table, next, turn, next),
            None
        );
        assert!(table.shape.slots > slots, "turn {turn}");
        assert_eq!(table.entries(), table.shape.max_insertions.min(limit + 1));
        for index in (0..budget).filter(|index| *index != turn * 97) {
            let key = index.wrapping_mul(SPREAD);
            assert_eq!(
                table.find_entry(&key, key).map(|entry| entry.value),
                Some(index)
            );
        }
        assert_eq!(table.find(&gone, gone), None);
    }
    assert_ne!(with_tombstones, 0);
}

/// An insert through a vacant entry lands where the placement walk lands
/// and leaves the same controls, filter and counts, in a table without
/// tombstones and in one with them, sized for its keys or grown from empty,
/// and the entry search then finds the key where the lookup does. Among
/// tombstones a shape with a head places some keys without the walk.
#[test]
#[cfg_attr(miri, ignore)]
fn vacant_entry_insert_places_like_the_placement_walk() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    type Table = FunnelTable<u64, u64, IdentityBuildHasher>;

    fn enter(table: &mut Table, key: u64, value: u64) -> usize {
        let vacant = table.find_for_entry(&key, key).err().unwrap();
        table.insert_for_vacant(key, value, vacant)
    }
    fn counts(table: &Table) -> [usize; 3] {
        [
            table.entries(),
            tombstone_controls(table),
            table.stale_membership(),
        ]
    }

    let (wide, wide_shape) = smallest_wide_shape();
    for (n, d) in [
        (0, 3),
        (344, 4),
        (4096, 3),
        (1 << 14, 3),
        (wide_shape.n, wide),
    ] {
        let mut entered = raw_table(n, d);
        let mut walked = raw_table(n, d);
        let budget = match entered.shape.max_insertions {
            0 => 3_000,
            sized => sized as u64,
        };
        for index in 0..budget {
            let key = index.wrapping_mul(SPREAD);
            let slot = enter(&mut entered, key, index);
            assert_eq!(
                slot,
                walked.insert_for_vacant_by_walk(key, index, key),
                "n {n} d {d} index {index}"
            );
            assert_eq!(entered.find_for_entry(&key, key).ok(), Some(slot));
        }
        assert_eq!(counts(&entered), counts(&walked), "n {n} d {d}");
        for index in (0..budget).step_by(4) {
            let key = index.wrapping_mul(SPREAD);
            for table in [&mut entered, &mut walked] {
                let slot = table.find(&key, key).unwrap();
                TableBackend::remove(table, slot);
            }
        }
        // Removed keys, which the filter still records, and new ones in turn.
        let mut without_walk = 0;
        for (turn, index) in (0..budget).step_by(4).enumerate() {
            let index = if turn % 2 == 0 { index } else { budget + index };
            let key = index.wrapping_mul(SPREAD);
            VACANCY_WALKS.with(|walks| walks.set(0));
            let slot = enter(&mut entered, key, index);
            without_walk += usize::from(VACANCY_WALKS.with(Cell::get) == 0);
            assert_eq!(
                slot,
                walked.insert_for_vacant_by_walk(key, index, key),
                "n {n} d {d} index {index}"
            );
            assert_eq!(entered.find_for_entry(&key, key).ok(), Some(slot));
            assert_eq!(counts(&entered), counts(&walked), "n {n} d {d}");
            assert_eq!(
                entered.epoch_snapshot(),
                walked.epoch_snapshot(),
                "n {n} d {d}"
            );
        }
        assert!(without_walk != 0 || entered.head_lanes == 0, "n {n} d {d}");
        assert_eq!(controls_and_filter(&entered), controls_and_filter(&walked));
    }
}

/// A key placed outside its funnel records the level it landed in, not the
/// overflow bit, so only the table's flag sends its lookup past the buckets
/// its probe selects.
#[test]
fn lookup_finds_a_key_placed_outside_its_funnel_in_a_recorded_level() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut table = raw_table(4096, 3);
    let level = table.shape.levels[0];
    for index in 1..=32_u64 {
        let key = index.wrapping_mul(SPREAD);
        let probe = table.prf.prepare(key);
        let own = probe::ordinary_funnel_bucket(probe, level.multiplier, level.buckets);
        // The first lane of an untouched level-zero bucket the probe does
        // not select.
        let (_, slot) = (0..level.buckets)
            .map(|bucket| (bucket, level.offset + bucket * GROUP_SIZE))
            .find(|&(bucket, slot)| {
                // SAFETY: a level-zero bucket starts inside the storage.
                own != bucket && control::is_free(unsafe { table.storage.control_at(slot) })
            })
            .unwrap();
        let vacancy = table.vacancy_at(slot);
        assert_eq!(vacancy.level_bit, level_bit_of(0));
        table.place_new_entry(
            vacancy,
            key,
            index,
            table.membership_slot(key),
            table.prf.prepare(key).fingerprint(),
            true,
        );
    }
    assert!(table.exceptional_placement);
    for index in 1..=32_u64 {
        let key = index.wrapping_mul(SPREAD);
        assert_eq!(table.membership_gate(key).levels() & OVERFLOW_LEVEL_BIT, 0);
        assert_eq!(
            map::TableBackend::find_entry(&table, &key, key).map(|entry| entry.value),
            Some(index),
            "index {index}"
        );
        let slot = table.find(&key, key);
        assert!(slot.is_some(), "index {index}");
        assert_eq!(
            map::TableBackend::find_for_entry(&table, &key, key).ok(),
            slot,
            "index {index}"
        );
    }
}

/// What a differential run met, so each fixture can prove its coverage.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
struct DifferentialCoverage {
    growths: usize,
    full_budget_inserts: usize,
    clears: usize,
    reseeds: usize,
    tombstone_cleanups: usize,
    past_cleanup_threshold: bool,
    exceptional: bool,
    overflow_entries: bool,
    /// A live key whose folded word is zero.
    zero_word_keys: bool,
    overwrites: usize,
    wide_buckets: bool,
    narrow_buckets: bool,
    /// Inserts of an absent key that the head walk placed.
    head_placements: usize,
    /// Head placements that took a tombstone.
    tombstone_placements: usize,
    /// Inserts of an absent key below the budget into a head that had no
    /// placement left until the insert counted the deletes before it.
    reopened_head_inserts: usize,
    /// Checks of a table holding deletes its counters had yet to see.
    uncounted_deletes: usize,
}

/// Lengths, in operations, of the stretches one differential cycle runs in
/// order, and how often the table is checked against the model.
#[derive(Clone, Copy)]
struct DifferentialStream {
    operations: usize,
    filling: usize,
    mixed: usize,
    draining: usize,
    clear_every: usize,
    check_every: usize,
}

impl DifferentialStream {
    const SMALL: Self = Self {
        operations: 60_000,
        filling: 4_096,
        mixed: 2_048,
        draining: 6_144,
        clear_every: 9_973,
        check_every: 251,
    };
}

type DifferentialTable = FunnelTable<HashedKey, u64, IdentityBuildHasher>;

/// Every model entry is found where the ordered walk finds it, with the
/// model's value, under a filter that records it; the table holds nothing
/// else.
fn assert_matches_model(
    table: &DifferentialTable,
    model: &alloc::collections::BTreeMap<HashedKey, u64>,
    absent: &[HashedKey],
    coverage: &mut DifferentialCoverage,
) {
    assert_eq!(table.entries(), model.len());
    assert!(table.entries() <= table.shape.max_insertions);
    // The head never has more placements left than the limit less the
    // entries.
    assert!(table.head_left <= table.shape.head_insertions().saturating_sub(model.len()));
    // The tombstone bound holds with the uncounted deletes added, and no
    // delete ran past the threshold it had to settle at.
    assert!(table.tombstone_bound() >= tombstone_controls(table));
    assert!(table.stale_membership() <= membership::refresh_deletes(table.shape.max_insertions));
    assert!(table.settle_left >= 1);
    coverage.uncounted_deletes += usize::from(table.uncounted_deletes() != 0);
    coverage.wide_buckets |= table.shape.beta > GROUP_SIZE;
    coverage.narrow_buckets |= table.shape.n != 0 && table.shape.beta <= GROUP_SIZE;
    let mut scan = OccupiedIndices::new();
    let mut occupied = 0;
    while scan.step(&table.storage).is_some() {
        occupied += 1;
    }
    assert_eq!(occupied, model.len());
    // The ordered walk over every level the shape has, and the special
    // arrays behind the overflow bit.
    let every_level = if table.shape.n == 0 {
        0
    } else {
        (0..table.shape.levels.len())
            .fold(OVERFLOW_LEVEL_BIT, |bits, level| bits | level_bit_of(level))
    };
    let overflow_start = table
        .shape
        .levels
        .get(OVERFLOW_LEVEL)
        .map_or(table.shape.primary_offset, |level| level.offset);
    if table.shape.beta < GROUP_SIZE {
        for slot in 0..table.shape.primary_offset {
            // SAFETY: `slot` is below the storage capacity.
            let control = unsafe { table.storage.control_at(slot) };
            assert_eq!(
                control == CTRL_PADDING,
                slot % GROUP_SIZE >= table.shape.beta,
                "slot {slot} holds {control:#x}"
            );
        }
    }
    for (key, value) in model {
        let slot = table
            .find(key, key.hash)
            .unwrap_or_else(|| panic!("lost {key:?}"));
        assert_eq!(
            table.find_location_by_walk(key, key.hash, every_level),
            Some(slot),
            "{key:?}"
        );
        assert_eq!(
            table.find_entry(key, key.hash).map(|entry| entry.value),
            Some(*value),
            "{key:?}"
        );
        assert_ne!(
            table.membership_gate(key.hash).levels() & table.level_bit(slot),
            0,
            "{key:?} lost its level bit"
        );
        assert!(
            slot >= table.shape.primary_offset || slot % GROUP_SIZE < table.shape.beta,
            "{key:?} sits in a padding lane"
        );
        coverage.overflow_entries |= slot >= overflow_start;
        coverage.zero_word_keys |= key.hash == table.prf.zero_word_hash();
    }
    for key in absent {
        if !model.contains_key(key) {
            assert_eq!(table.find(key, key.hash), None, "{key:?}");
            assert_eq!(
                table.find_location_by_walk(key, key.hash, every_level),
                None,
                "{key:?}"
            );
        }
    }
}

fn occupied_controls<K, V, S>(table: &FunnelTable<K, V, S>) -> usize {
    (0..table.shape.slots)
        .filter(|&slot| control::is_occupied(table.storage.checked_control(slot)))
        .count()
}

fn tombstone_controls<K, V, S>(table: &FunnelTable<K, V, S>) -> usize {
    // SAFETY: `slot < slots`, the storage capacity.
    (0..table.shape.slots)
        .filter(|&slot| unsafe { table.storage.control_at(slot) } == CTRL_TOMBSTONE)
        .count()
}

/// Inserts `key`, which the model held `previous` for. Where the placement
/// walk puts an absent key is read off the table before the insert runs,
/// and an insert that keeps the storage must have stored the key there:
/// through the head, whose first free lane is that slot whenever the head
/// has one, or by the walk itself. Returns whether the insert rebuilt the
/// table.
fn insert_checking_the_head_walk(
    table: &mut DifferentialTable,
    key: HashedKey,
    value: u64,
    previous: Option<u64>,
    coverage: &mut DifferentialCoverage,
) -> bool {
    let before = table.membership_gate(key.hash);
    let probe = table.prf.prepare(key.hash);
    let storage = table.storage.ctrl_ptr();
    let below_budget = table.entries() < table.shape.max_insertions;
    let walk = table.search_vacancy(probe);
    // The scalar walk decides both: the slot of a present key, and the
    // vacancy of an absent one. It misses only a key outside its funnel.
    match ordered_walk(table, &key, key.hash) {
        Walked::Hit(slot) => {
            assert!(previous.is_some(), "{key:?}");
            assert_eq!(table.find(&key, key.hash), Some(slot), "{key:?}");
        }
        missed => {
            assert!(previous.is_none() || table.exceptional_placement, "{key:?}");
            if previous.is_none() {
                let vacant = match missed {
                    Walked::Vacant(slot) => Some(slot),
                    _ => None,
                };
                assert_eq!(walk.map(|vacancy| vacancy.slot), vacant, "{key:?}");
            }
        }
    }
    // The head takes an absent key below the budget.
    let head = (previous.is_none() && below_budget && table.head_lanes != 0)
        .then(|| table.first_free_in_head(probe))
        .flatten();
    if let Some(head) = &head {
        let slot = table.slot_of(NonNull::new(head.lane).unwrap());
        assert_eq!(
            walk,
            Some(Vacancy {
                slot,
                level_bit: head.level_bit
            }),
            "{key:?}"
        );
        // SAFETY: `slot` is below the storage capacity.
        let control = unsafe { table.storage.control_at(slot) };
        coverage.tombstone_placements += usize::from(control == CTRL_TOMBSTONE);
        coverage.reopened_head_inserts += usize::from(table.head_left == 0);
        coverage.head_placements += 1;
    }
    assert_eq!(table.insert(key, value, key.hash), previous, "{key:?}");
    // A rebuild allocates the new storage before it frees the old.
    let rebuilt = table.storage.ctrl_ptr() != storage;
    if previous.is_none()
        && !rebuilt
        && let Some(vacancy) = walk
    {
        assert_eq!(table.find(&key, key.hash), Some(vacancy.slot), "{key:?}");
        assert_eq!(
            table.membership_gate(key.hash).levels(),
            before.levels() | vacancy.level_bit,
            "{key:?}"
        );
    }
    rebuilt
}

/// Ends a bulk delete, which cleans up when the bound is past the threshold
/// and the tombstones are within a group's share of the slots of it.
/// `true` if it cleaned up.
fn end_bulk_delete_checking_the_cleanup(table: &mut DifferentialTable) -> bool {
    let threshold = capacity::tombstone_cleanup_threshold(table.shape.n);
    let due = table.tombstone_bound() > threshold
        && tombstone_controls(table) + table.shape.slots / GROUP_SIZE > threshold;
    let (slots, prf) = (table.shape.n, table.prf);
    let generation = table.epoch_snapshot().generation;
    map::TableBackend::finish_deferred_removals(table);
    let cleaned = table.epoch_snapshot().generation != generation;
    assert_eq!(cleaned, due);
    if cleaned {
        assert_eq!((table.shape.n, table.prf), (slots, prf));
        assert_eq!(tombstone_controls(table), 0);
    }
    cleaned
}

/// Runs a fixed pseudo-random insert, overwrite, remove, lookup and clear
/// stream against a model map, starting from a table with no storage, and
/// checks a clone of the final table against the model too.
fn run_differential(
    d: u32,
    universe: &[HashedKey],
    stream: DifferentialStream,
    seed: u64,
) -> DifferentialCoverage {
    let reserve = ReserveFraction::from_exponent(d).unwrap();
    let mut table = DifferentialTable::with_capacity_and_reserve_and_hasher_in(
        0,
        reserve,
        IdentityBuildHasher,
        Global,
    );
    assert_eq!(table.shape.n, 0);
    let mut model = alloc::collections::BTreeMap::new();
    let mut coverage = DifferentialCoverage::default();
    let mut next = test_support::xorshift_stream(seed);
    assert_matches_model(&table, &model, universe, &mut coverage);
    let cycle = stream.filling + stream.mixed + stream.draining;
    for step in 0..stream.operations {
        // A filling stretch meets the insertion budget and growth, a mixed
        // one reuses tombstones, and a draining one removes only live keys,
        // so tombstones pass the cleanup threshold; its few inserts draw
        // from the whole universe, and none of them cleans up.
        let (insert_below, draining) = match step % cycle {
            at if at < stream.filling => (85, false),
            at if at < stream.filling + stream.mixed => (50, false),
            _ => (3, true),
        };
        let drawn = universe[usize::try_from(next() % universe.len() as u64).unwrap()];
        let roll = next() % 100;
        let key = if draining && roll >= insert_below {
            model.range(drawn..).next().map_or(drawn, |(key, _)| *key)
        } else {
            drawn
        };
        let slots = table.shape.n;
        let prf = table.prf;
        if roll < 2 {
            assert_eq!(
                table.find_entry(&key, key.hash).map(|entry| entry.value),
                model.get(&key).copied(),
                "step {step} get {key:?}"
            );
        } else if roll < insert_below {
            let value = next();
            // The first insert allocates; only a later one meets a spent budget.
            coverage.full_budget_inserts += usize::from(
                table.shape.max_insertions > 0
                    && table.entries() == table.shape.max_insertions
                    && !model.contains_key(&key),
            );
            let previous = model.insert(key, value);
            coverage.overwrites += usize::from(previous.is_some());
            // The count reads every control byte, so it runs on a sample of
            // the inserts, and only on a table with that many lanes free.
            let threshold = capacity::tombstone_cleanup_threshold(slots);
            let past_threshold = step % 16 == 0
                && slots != 0
                && table.shape.slots - table.entries() > threshold
                && tombstone_controls(&table) > threshold;
            let rebuilt =
                insert_checking_the_head_walk(&mut table, key, value, previous, &mut coverage);
            // Only an absent key's insert rebuilds, and never at the same
            // size under the same seed, which is a cleanup.
            assert!(!(rebuilt && previous.is_some()), "step {step}");
            assert!(
                !(rebuilt && table.shape.n == slots && table.prf == prf),
                "step {step}"
            );
            coverage.past_cleanup_threshold |= past_threshold && !rebuilt;
        } else if step % stream.clear_every == stream.clear_every - 1 {
            table.clear();
            model.clear();
            coverage.clears += 1;
        } else {
            let location = table.find(&key, key.hash);
            let generation = table.epoch_snapshot().generation;
            let removed = location.map(|location| table.remove(location));
            assert_eq!(
                removed,
                model.remove(&key).map(|value| (key, value)),
                "step {step} remove {key:?}"
            );
            // A remove of a live key leaves a tombstone in its lane and
            // never rebuilds.
            if let Some(slot) = location {
                // SAFETY: `find` returns a slot below the storage capacity.
                let control = unsafe { table.storage.control_at(slot) };
                assert_eq!(control, CTRL_TOMBSTONE, "step {step}");
            }
            assert_eq!(table.epoch_snapshot().generation, generation, "step {step}");
        }
        assert!(table.entries() <= table.shape.max_insertions, "step {step}");
        // The first allocation is not a growth.
        coverage.growths += usize::from(slots != 0 && table.shape.n > slots);
        coverage.reseeds += usize::from(table.prf != prf);
        coverage.exceptional |= table.exceptional_placement;
        if step % cycle == cycle - 1 {
            coverage.tombstone_cleanups +=
                usize::from(end_bulk_delete_checking_the_cleanup(&mut table));
        }
        if step % stream.check_every == 0 {
            assert_matches_model(&table, &model, universe, &mut coverage);
        }
    }
    assert_matches_model(&table, &model, universe, &mut coverage);
    assert_matches_model(&table.clone_table(), &model, universe, &mut coverage);
    coverage
}

fn spread_universe(len: u64) -> Vec<HashedKey> {
    // The first key's folded word is zero until a reseed, so it draws
    // bucket zero in every level.
    let zero_word = FunnelPrf::new(FUNNEL_PROBE_SEED).zero_word_hash();
    (0..len)
        .map(|id| HashedKey {
            id,
            hash: if id == 0 {
                zero_word
            } else {
                id.wrapping_mul(0x9E37_79B9_7F4A_7C15)
            },
        })
        .collect()
}

#[test]
#[cfg_attr(miri, ignore)]
fn operation_streams_agree_with_a_model_map_and_the_ordered_walk() {
    for d in [3, 4] {
        let coverage = run_differential(
            d,
            &spread_universe(6_000),
            DifferentialStream::SMALL,
            0x2545_F491_4F6C_DD1D,
        );
        assert!(
            coverage.narrow_buckets && !coverage.wide_buckets,
            "{coverage:?}"
        );
        assert!(coverage.growths >= 4, "{coverage:?}");
        assert!(coverage.full_budget_inserts > 0, "{coverage:?}");
        assert!(coverage.clears > 0, "{coverage:?}");
        assert!(coverage.overwrites > 0, "{coverage:?}");
        assert!(coverage.zero_word_keys, "{coverage:?}");
        assert!(!coverage.exceptional, "{coverage:?}");
        assert!(coverage.head_placements > 0, "{coverage:?}");
        assert!(coverage.tombstone_placements > 0, "{coverage:?}");
        assert!(coverage.reopened_head_inserts > 0, "{coverage:?}");
        assert!(coverage.uncounted_deletes > 0, "{coverage:?}");
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn operation_streams_agree_with_a_model_map_in_wide_buckets() {
    let large = DifferentialStream {
        operations: 200_000,
        filling: 60_000,
        mixed: 2_000,
        draining: 30_000,
        clear_every: 95_003,
        check_every: 4_099,
    };
    // The stream has to outgrow the smallest shape, which grows with the
    // group width.
    let (wide, wide_shape) = smallest_wide_shape();
    let smallest = if 4 * wide_shape.max_insertions <= 6_000 {
        (wide, 6_000, DifferentialStream::SMALL)
    } else {
        (wide, 80_000, large)
    };
    for (d, keys, stream) in [smallest, (10, 80_000, large)] {
        let coverage = run_differential(d, &spread_universe(keys), stream, 0x9E37_79B9_7F4A_7C15);
        assert!(
            coverage.wide_buckets && !coverage.narrow_buckets,
            "{coverage:?}"
        );
        assert!(coverage.growths > 0, "{coverage:?}");
        assert!(coverage.full_budget_inserts > 0, "{coverage:?}");
        assert!(coverage.past_cleanup_threshold, "{coverage:?}");
        assert!(coverage.tombstone_cleanups > 0, "{coverage:?}");
        assert!(coverage.overwrites > 0, "{coverage:?}");
    }
}

/// A few hashes shared by many keys overfill one probe path, which forces
/// the special arrays, a reseeding rebuild, and placements outside the
/// funnel.
#[test]
#[cfg_attr(miri, ignore)]
fn operation_streams_agree_with_a_model_map_under_colliding_hashes() {
    let universe: Vec<HashedKey> = (0..900_u64)
        .map(|id| HashedKey {
            id,
            hash: (id % 3 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15),
        })
        .collect();
    // Buckets narrower and wider than one control group.
    let (wide, wide_shape) = smallest_wide_shape();
    // The keys overfill a probe path only in a shape they outgrow, and the
    // smallest wide shape grows with the group width. The staged test below
    // reseeds that shape at any width.
    let outgrown = universe.len() > wide_shape.max_insertions;
    for d in [3, wide] {
        let coverage = run_differential(
            d,
            &universe,
            DifferentialStream::SMALL,
            0xD1B5_4A32_D192_ED03,
        );
        assert_eq!(coverage.wide_buckets, d == wide, "{coverage:?}");
        assert_eq!(coverage.narrow_buckets, d != wide, "{coverage:?}");
        assert!(coverage.overflow_entries, "{coverage:?}");
        if d != wide || outgrown {
            assert!(coverage.reseeds > 0, "{coverage:?}");
            assert!(coverage.exceptional, "{coverage:?}");
            assert!(coverage.past_cleanup_threshold, "{coverage:?}");
            assert!(coverage.tombstone_cleanups > 0, "{coverage:?}");
        }
    }
}

/// With a key outside its funnel, the entry search and the insert still
/// find every key of `model` where the lookup does, and a vacant entry
/// stores `absent`.
fn enter_with_a_key_outside_its_funnel(
    table: &mut DifferentialTable,
    model: &mut alloc::collections::BTreeMap<HashedKey, u64>,
    absent: HashedKey,
) {
    assert!(table.exceptional_placement);
    for (key, value) in model.iter_mut() {
        let slot = table.find(key, key.hash);
        assert!(slot.is_some(), "{key:?}");
        assert_eq!(table.find_for_entry(key, key.hash).ok(), slot, "{key:?}");
        assert_eq!(
            table.insert(*key, *value + 1, key.hash),
            Some(*value),
            "{key:?}"
        );
        *value += 1;
        assert_eq!(table.find(key, key.hash), slot, "{key:?}");
    }
    let vacant = table.find_for_entry(&absent, absent.hash).err().unwrap();
    let slot = table.insert_for_vacant(absent, absent.id, vacant);
    assert_eq!(table.find(&absent, absent.hash), Some(slot));
    model.insert(absent, absent.id);
}

/// The smallest shapes on both sides of the group width, from a table without
/// storage through a spent budget, tombstones, a growth, a clear and a
/// reseeding rebuild, with a clone checked at each stage. Miri runs the wide
/// shape only where its budget stays small.
#[test]
fn smallest_shapes_agree_with_a_model_map_through_every_transition() {
    /// Largest budget the staged run fills under Miri.
    const MIRI_BUDGET: usize = 1 << 10;

    let (wide, _) = smallest_wide_shape();
    for d in [3, wide] {
        let reserve = ReserveFraction::from_exponent(d).unwrap();
        let budget = FunnelShape::for_insert_budget(1, reserve)
            .unwrap()
            .max_insertions;
        if cfg!(miri) && budget > MIRI_BUDGET {
            continue;
        }
        let universe = spread_universe(budget as u64 + 8);
        let mut coverage = DifferentialCoverage::default();
        let mut model = alloc::collections::BTreeMap::new();
        let mut table = DifferentialTable::with_capacity_and_reserve_and_hasher_in(
            0,
            reserve,
            IdentityBuildHasher,
            Global,
        );
        let mut check =
            |table: &DifferentialTable, model: &alloc::collections::BTreeMap<HashedKey, u64>| {
                assert_matches_model(table, model, &universe, &mut coverage);
                assert_matches_model(&table.clone_table(), model, &universe, &mut coverage);
            };
        check(&table, &model);

        // The smallest shape, filled to its budget without a tombstone.
        for key in &universe[..budget] {
            assert_eq!(table.insert(*key, key.id, key.hash), None, "d {d} {key:?}");
            model.insert(*key, key.id);
        }
        assert_eq!(table.shape.max_insertions, budget, "d {d}");
        assert_eq!(
            (table.entries(), tombstone_controls(&table)),
            (budget, 0),
            "d {d}"
        );
        check(&table, &model);

        // Tombstones on the walks, then inserts that reuse some of them.
        for key in universe[..budget].iter().step_by(3) {
            let location = table.find(key, key.hash).unwrap();
            assert_eq!(table.remove(location), (*key, key.id), "d {d}");
            model.remove(key);
        }
        assert_ne!(tombstone_controls(&table), 0, "d {d}");
        check(&table, &model);
        for key in universe[..budget].iter().step_by(6) {
            assert_eq!(
                table.insert(*key, key.id + 1, key.hash),
                None,
                "d {d} {key:?}"
            );
            model.insert(*key, key.id + 1);
        }
        check(&table, &model);

        // Inserts past the budget grow the table.
        let slots = table.shape.n;
        for key in &universe {
            assert_eq!(
                table.insert(*key, key.id + 2, key.hash),
                model.insert(*key, key.id + 2),
                "d {d} {key:?}"
            );
        }
        assert!(table.shape.n > slots, "d {d}");
        check(&table, &model);

        table.clear();
        model.clear();
        check(&table, &model);

        // Keys sharing one hash overfill its probe path, which a rebuild
        // answers with a new seed.
        let prf = table.prf;
        let mut id = 1 << 32;
        while table.prf == prf {
            let key = HashedKey {
                id,
                hash: 0x9E37_79B9_7F4A_7C15,
            };
            assert_eq!(table.insert(key, id, key.hash), None, "d {d} {key:?}");
            model.insert(key, id);
            id += 1;
            assert!(model.len() <= table.shape.max_insertions, "d {d}");
        }
        assert!(table.exceptional_placement, "d {d}");
        check(&table, &model);

        let absent = HashedKey {
            id,
            hash: 0x9E37_79B9_7F4A_7C15,
        };
        enter_with_a_key_outside_its_funnel(&mut table, &mut model, absent);
        check(&table, &model);
    }
}

/// A recorded unit's leading zeros, as the first-match walk reads them, name
/// the head entry of its bin's shallowest level whatever its membership bits:
/// the level's own for a level with a bit, and the absent one after them for
/// the overflow bit. A unit that records no key is not walked, and one whose
/// bin is empty leads to an absent entry.
#[test]
fn a_wide_bin_leads_with_the_index_of_its_shallowest_level() {
    let lead = |levels: u16| {
        let leads = [1, 1 << (MEMBERSHIP_BITS - 1), (1 << MEMBERSHIP_BITS) - 1].map(|bits| {
            let unit = unit_of(bits, levels);
            assert_eq!(unit_levels(unit), levels);
            WideLevelBin::of_recording_unit(unit, bits)
                .unwrap()
                .get()
                .leading_zeros() as usize
        });
        assert!(leads.iter().all(|&lead| lead == leads[0]));
        leads[0]
    };
    for level in 0..OVERFLOW_LEVEL {
        assert_eq!(lead(level_bit_of(level)), level);
        assert_eq!(lead(level_bit_of(level) | OVERFLOW_LEVEL_BIT), level);
    }
    assert_eq!(lead(OVERFLOW_LEVEL_BIT), OVERFLOW_LEVEL);
    assert!(WideLevelBin::of_recording_unit(unit_of(0, u16::MAX), 1).is_none());
    assert!(WideLevelBin::of_recording_unit(unit_of(1, u16::MAX), 2).is_none());
    for bits in [1, (1 << MEMBERSHIP_BITS) - 1] {
        let lead = WideLevelBin::of_recording_unit(unit_of(bits, 0), bits)
            .unwrap()
            .get()
            .leading_zeros() as usize;
        assert!((OVERFLOW_LEVEL..HEAD_ENTRIES).contains(&lead));
    }
}

fn head_table(
    shape: FunnelShape,
    reserve: ReserveFraction,
) -> FunnelTable<u64, u64, IdentityBuildHasher> {
    FunnelTable::try_from_shape(shape, reserve, IdentityBuildHasher, Global).unwrap()
}

/// The head is the one [`head_levels`] derives from the table's own shape
/// and storage.
fn assert_head_addresses_storage<K, V, S>(table: &FunnelTable<K, V, S>) {
    let derived = head_levels(&table.shape, &table.storage);
    for (index, (head, derived)) in table.head.iter().zip(&derived).enumerate() {
        assert_eq!(head.multiplier, derived.multiplier, "entry {index}");
        assert_eq!(head.buckets, derived.buckets, "entry {index}");
        assert_eq!(head.ctrl, derived.ctrl, "entry {index}");
        assert_eq!(head.lead_origin, derived.lead_origin, "entry {index}");
    }
    assert_eq!(table.head_lanes, table.shape.head_lanes());
}

/// Absent keys inserted between the operations that write and clear
/// tombstones land where the placement walk would put them, and the map
/// keeps what a model map keeps: single removals, `retain`, `extract_if`
/// run to its end and dropped part way, a clone, a rebuild, `drain`,
/// `clear`, and churn through growth.
#[test]
#[allow(clippy::too_many_lines)]
fn inserts_place_like_the_placement_walk_around_every_removal() {
    use alloc::collections::BTreeMap;

    type Map = FunnelHashMap<u64, u64, crate::test_support::FixedHashBuilder>;
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;

    fn tombstone_lanes(map: &Map) -> usize {
        tombstone_controls(map.table())
    }
    fn check(map: &Map, model: &BTreeMap<u64, u64>) {
        let table = map.table();
        assert!(table.head_left <= table.shape.head_insertions() - map.len());
        assert!(table.tombstone_bound() >= tombstone_lanes(map));
        assert_eq!(map.len(), model.len());
        for (key, value) in model {
            assert_eq!(map.get(key), Some(value), "key {key}");
        }
    }
    // The scan of every lane after each single step, where it is cheap.
    fn check_step(map: &Map, model: &BTreeMap<u64, u64>) {
        if !cfg!(miri) {
            check(map, model);
        }
    }
    // Inserts `count` absent keys, checking each placement against the
    // placement walk's vacancy from before it.
    struct Stream {
        next: u64,
        through_head: usize,
        around_tombstones: usize,
    }
    impl Stream {
        fn insert(&mut self, map: &mut Map, model: &mut BTreeMap<u64, u64>, count: usize) {
            for _ in 0..count {
                let key = self.next.wrapping_mul(SPREAD);
                self.next += 1;
                let hash = map.hasher().hash_one(key);
                let table = map.table();
                let probe = table.prf.prepare(hash);
                let (storage, walk) = (table.storage.ctrl_ptr(), table.search_vacancy(probe));
                let through_head = table.entries() < table.shape.max_insertions
                    && table.first_free_in_head(probe).is_some();
                let tombstones = tombstone_lanes(map);
                assert_eq!(map.insert(key, self.next), None);
                model.insert(key, self.next);
                let table = map.table();
                if table.storage.ctrl_ptr() == storage {
                    let slot = walk.unwrap().slot;
                    assert_eq!(table.find(&key, hash), Some(slot), "key {key}");
                    self.through_head += usize::from(through_head);
                    self.around_tombstones += usize::from(tombstone_lanes(map) < tombstones);
                } else {
                    assert!(!through_head, "key {key}");
                }
                check_step(map, model);
            }
        }
    }

    let mut map: Map = FunnelHashMap::with_capacity_and_hasher(256, test_support::fixed_hasher());
    let mut model = BTreeMap::new();
    let mut stream = Stream {
        next: 0,
        through_head: 0,
        around_tombstones: 0,
    };
    stream.insert(&mut map, &mut model, 150);

    // Removals, then inserts among their tombstones.
    let removed: Vec<u64> = model.keys().copied().step_by(3).collect();
    for key in removed {
        assert_eq!(map.remove(&key), model.remove(&key));
        check_step(&map, &model);
    }
    check(&map, &model);
    stream.insert(&mut map, &mut model, 20);

    map.retain(|key, _| key % 5 != 0);
    model.retain(|key, _| key % 5 != 0);
    check(&map, &model);
    stream.insert(&mut map, &mut model, 20);

    // An extraction run to its end, and one dropped part way.
    for extracted in map.extract_if(|key, _| key % 7 == 0).collect::<Vec<_>>() {
        assert_eq!(model.remove(&extracted.0), Some(extracted.1));
    }
    check(&map, &model);
    stream.insert(&mut map, &mut model, 20);
    for extracted in map
        .extract_if(|key, _| key % 2 == 0)
        .take(9)
        .collect::<Vec<_>>()
    {
        assert_eq!(model.remove(&extracted.0), Some(extracted.1));
    }
    check(&map, &model);
    stream.insert(&mut map, &mut model, 20);

    // A clone carries the tombstones with it.
    let mut clone = map.clone();
    let mut clone_model = model.clone();
    check(&clone, &clone_model);
    let mut clone_stream = Stream {
        next: 1 << 40,
        through_head: 0,
        around_tombstones: 0,
    };
    clone_stream.insert(&mut clone, &mut clone_model, 20);

    // A rebuild leaves no tombstone.
    assert_ne!(tombstone_lanes(&map), 0);
    map.shrink_to_fit();
    check(&map, &model);
    assert_eq!(tombstone_lanes(&map), 0);
    assert_eq!(
        map.table().head_left,
        map.table().shape.head_insertions() - map.len()
    );
    stream.insert(&mut map, &mut model, 20);

    // A drain run to its end, a clear, and a clear after removals.
    for drained in map.drain().collect::<Vec<_>>() {
        assert_eq!(model.remove(&drained.0), Some(drained.1));
    }
    check(&map, &model);
    stream.insert(&mut map, &mut model, 40);
    map.clear();
    model.clear();
    check(&map, &model);
    stream.insert(&mut map, &mut model, 40);
    let removed: Vec<u64> = model.keys().copied().step_by(2).collect();
    for key in removed {
        assert_eq!(map.remove(&key), model.remove(&key));
    }
    map.clear();
    model.clear();
    check(&map, &model);
    assert_ne!(map.table().head_left, 0);

    // Churn through tombstone reuse and growth.
    stream.insert(&mut map, &mut model, 100);
    for _ in 0..if cfg!(miri) { 200 } else { 3_000 } {
        let key = *model.keys().next().unwrap();
        assert_eq!(map.remove(&key), model.remove(&key));
        check_step(&map, &model);
        stream.insert(&mut map, &mut model, 1);
    }
    stream.insert(&mut map, &mut model, 400);
    check(&map, &model);
    check(&clone, &clone_model);
    assert_ne!(stream.through_head, 0);
    assert_ne!(stream.around_tombstones, 0);
    assert_ne!(clone_stream.around_tombstones, 0);
}

/// The head placement copies an absent key and its value into the table,
/// and the insert then gives both up without dropping them: each drops
/// once, with the table.
#[test]
fn head_placement_takes_key_and_value_without_dropping_either() {
    // Counted in a static, not behind a pointer the key or value owns, so
    // a second drop is a wrong count and not a use after free.
    static DROPS: AtomicUsize = AtomicUsize::new(0);
    struct Tracked {
        id: u64,
    }
    impl Drop for Tracked {
        fn drop(&mut self) {
            DROPS.fetch_add(1, Ordering::Relaxed);
        }
    }
    impl PartialEq for Tracked {
        fn eq(&self, other: &Self) -> bool {
            self.id == other.id
        }
    }
    impl Eq for Tracked {}
    impl Hash for Tracked {
        fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
            self.id.hash(state);
        }
    }

    const ENTRIES: usize = 100;
    let tracked = |id| Tracked { id };
    let mut map = FunnelHashMap::with_capacity_and_hasher(128, test_support::fixed_hasher());
    let open = map.table().head_left;
    for id in 0..ENTRIES as u64 {
        assert!(map.insert(tracked(id), tracked(id)).is_none());
    }
    // Every insert went through the head.
    assert_eq!(map.table().head_left, open - ENTRIES);
    assert_eq!(DROPS.load(Ordering::Relaxed), 0);
    drop(map);
    assert_eq!(DROPS.load(Ordering::Relaxed), 2 * ENTRIES);
}

/// The head placement walks the levels that own a level-bin bit without
/// asking whether each exists, so every shape must have them all, and each
/// head entry the walk reads must address groups of the storage.
#[test]
#[cfg_attr(miri, ignore = "builds a table for each of thousands of shapes")]
fn every_shape_has_the_levels_the_head_placement_walks() {
    for d in geometry::MIN_FUNNEL_RESERVE_EXPONENT..=8 {
        let reserve = ReserveFraction::from_exponent(d).unwrap();
        let levels = 4 * d as usize + 10;
        assert!(levels >= geometry::MIN_FUNNEL_LEVELS);
        let mut shapes = 0;
        for n in (2..4_000).chain((1 << 16)..(1 << 16) + 200) {
            let Ok(shape) = FunnelShape::from_slots(n, reserve) else {
                continue;
            };
            shapes += 1;
            assert_eq!(shape.levels.len(), levels, "d={d} n={n}");
            let table = raw_table(n, d);
            let controls = table.storage.ctrl_ptr() as usize;
            for (index, level) in table.head[..OVERFLOW_LEVEL].iter().enumerate() {
                assert_ne!(level.buckets, 0, "d={d} n={n} entry {index}");
                let first = level.ctrl as usize;
                let end = first + level.buckets * GROUP_SIZE;
                assert!(
                    controls <= first && end <= controls + table.shape.primary_offset,
                    "d={d} n={n} entry {index}"
                );
            }
        }
        assert_ne!(shapes, 0, "d={d}");
    }
    // Below the smallest exponent no plan exists, so no shape with fewer
    // levels does.
    let below = ReserveFraction::from_exponent(geometry::MIN_FUNNEL_RESERVE_EXPONENT - 1).unwrap();
    assert!((2..4_000).all(|n| FunnelShape::from_slots(n, below).is_err()));
}

/// Every path that gives a table another storage gives it that storage's
/// head: growth, shrinking, the empty shape, and a clone. A clear keeps
/// both. Lookups, inserts and removals read and write through the head after
/// each.
#[test]
fn head_follows_its_storage_through_every_replacement() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let reserve = ReserveFraction::from_exponent(3).unwrap();
    let key_of = |index: u64| index.wrapping_mul(SPREAD);
    let check = |table: &mut FunnelTable<u64, u64, IdentityBuildHasher>, live: u64| {
        assert_head_addresses_storage(table);
        assert_eq!(table.entries() as u64, live);
        for index in 0..live {
            let key = key_of(index);
            let found = table.find_entry(&key, key).map(|entry| entry.value);
            assert_eq!(found, Some(index), "index {index}");
        }
        // Through the head and back out, where the table has room.
        if table.shape.max_insertions as u64 > live {
            let key = key_of(live);
            assert_eq!(map::TableBackend::insert(table, key, live, key), None);
            assert_eq!(map::TableBackend::take(table, &key, key), Some((key, live)));
        }
        assert_eq!(
            map::TableBackend::take(table, &key_of(live), key_of(live)),
            None
        );
    };

    let mut table = raw_table(144, 3);
    check(&mut table, 0);
    let live = 40;
    for index in 0..live {
        let key = key_of(index);
        assert_eq!(map::TableBackend::insert(&mut table, key, index, key), None);
    }
    check(&mut table, live);

    let grown = FunnelShape::for_insert_budget(256, reserve).unwrap();
    map::TableBackend::try_resize(&mut table, grown.n).unwrap();
    assert_eq!(table.shape.n, grown.n);
    assert_eq!(map::TableBackend::total_slots(&table), grown.n);
    check(&mut table, live);

    map::TableBackend::shrink_to(&mut table, 0);
    assert!(table.shape.n < grown.n);
    check(&mut table, live);

    let mut cloned = map::TableBackend::clone_table(&table);
    assert_ne!(cloned.storage.ctrl_ptr(), table.storage.ctrl_ptr());
    check(&mut cloned, live);
    drop(table);
    check(&mut cloned, live);

    map::TableBackend::clear(&mut cloned);
    check(&mut cloned, 0);

    map::TableBackend::shrink_to(&mut cloned, 0);
    assert_eq!(cloned.shape.n, 0);
    assert_head_addresses_storage(&cloned);
    assert_eq!(
        cloned
            .find_entry(&key_of(1), key_of(1))
            .map(|entry| entry.value),
        None
    );
    assert_eq!(
        map::TableBackend::take(&mut cloned, &key_of(1), key_of(1)),
        None
    );

    // Out of the empty shape again, through the insert's own growth.
    for index in 0..live {
        let key = key_of(index);
        assert_eq!(
            map::TableBackend::insert(&mut cloned, key, index, key),
            None
        );
        assert_head_addresses_storage(&cloned);
    }
    check(&mut cloned, live);
}

/// An empty shape keeps an all-absent head, which no insert walks and which
/// matches nothing in a first-match scan. Any other shape addresses its
/// levels from the head; only one whose buckets fit a group places through
/// it. An entry that is no level points at the group past the slots.
#[test]
fn only_the_empty_shape_keeps_an_absent_head() {
    let past_the_slots = |table: &FunnelTable<u64, u64, IdentityBuildHasher>,
                          head: &HeadLevel<SlotEntry<u64, u64>>| {
        head.buckets == 0 && table.slot_of(NonNull::new(head.ctrl).unwrap()) == table.shape.slots
    };
    let narrow_reserve = ReserveFraction::from_exponent(3).unwrap();
    let empty = FunnelShape::empty();
    assert_eq!(empty.head_insertions(), 0);
    let table = head_table(empty, narrow_reserve);
    assert!(table.head.iter().all(HeadLevel::is_absent));
    assert!(table.head.iter().all(|head| past_the_slots(&table, head)));

    let (wide, smallest_wide) = smallest_wide_shape();
    let wide_reserve = ReserveFraction::from_exponent(wide).unwrap();
    let large_wide = FunnelShape::for_insert_budget(1 << 19, wide_reserve).unwrap();
    let narrow =
        [1, 1 << 19].map(|budget| FunnelShape::for_insert_budget(budget, narrow_reserve).unwrap());
    let shapes = narrow
        .into_iter()
        .map(|shape| (shape, narrow_reserve))
        .chain([(smallest_wide, wide_reserve), (large_wide, wide_reserve)]);
    for (shape, reserve) in shapes {
        let fits = shape.beta <= GROUP_SIZE;
        let expected_head_insertions = if fits { shape.max_insertions } else { 0 };
        assert_eq!(shape.head_insertions(), expected_head_insertions);
        let table = head_table(shape, reserve);
        let recorded = table.shape.levels.len().min(OVERFLOW_LEVEL);
        for (head, level) in table.head.iter().zip(&table.shape.levels[..recorded]) {
            assert_eq!(head.multiplier, level.multiplier);
            assert_eq!(head.buckets, level.buckets);
            assert_eq!(
                table.slot_of(NonNull::new(head.ctrl).unwrap()),
                level.offset
            );
            // SAFETY: a level starts inside the storage.
            let data = unsafe { table.storage.slot_ptr(level.offset) };
            // SAFETY: slot zero of a level is inside it.
            assert_eq!(unsafe { head.entry(0) }.cast(), data);
        }
        assert!(table.head[recorded..].iter().all(HeadLevel::is_absent));
        assert!(
            table.head[recorded..]
                .iter()
                .all(|head| past_the_slots(&table, head))
        );
    }
}

/// Runs `check` on a full table, then again once every third key has left
/// a tombstone on the walks of the rest. `check` gets the table, the count
/// of keys placed in it, and a label for its messages.
fn check_full_then_tombstoned(
    check: impl Fn(&FunnelTable<u64, u64, IdentityBuildHasher>, u64, &str),
) {
    let mut table = raw_table(5_472, 8);
    let live = table.shape.max_insertions as u64;
    for key in 0..live {
        assert!(!table.place_unique(
            SlotEntry { key, value: key },
            table.hash_builder.hash_one(key)
        ));
    }
    check(&table, live, "clean full table");
    for key in (0..live).step_by(3) {
        let hash = table.hash_builder.hash_one(key);
        let slot = table.find(&key, hash).unwrap();
        map::TableBackend::remove(&mut table, slot);
    }
    assert!(tombstone_controls(&table) > 0);
    check(&table, live, "tombstoned table");
}

/// The placement walk must land where the ordered walk reports `Vacant`
/// for an absent key, on clean epochs and with tombstones on the walk.
#[test]
#[cfg_attr(miri, ignore)]
fn vacancy_walk_matches_the_ordered_walk_for_absent_keys() {
    check_full_then_tombstoned(|table, live, label| {
        let mut vacant = 0_usize;
        for key in live..live + 4_096 {
            let hash = table.hash_builder.hash_one(key);
            let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(hash);
            let exact = ordered_walk(table, &key, hash);
            assert_eq!(
                table.search_vacancy(probe),
                match exact {
                    Walked::Vacant(slot) => Some(table.vacancy_at(slot)),
                    Walked::Hit(_) | Walked::Full => None,
                },
                "{label} key={key}"
            );
            vacant += usize::from(matches!(exact, Walked::Vacant(_)));
        }
        assert!(vacant > 0, "{label}: fixture never reached a vacancy");
    });
}

/// With every level bit set, the read-only walk must report exactly the
/// ordered walk's hits, for present and absent keys, on clean epochs and with
/// tombstones on the walk.
#[test]
#[cfg_attr(miri, ignore)]
fn lookup_walk_matches_the_ordered_walk_hits() {
    check_full_then_tombstoned(|table, live, label| {
        // Every bit `level_bit` can record for this shape; a bit past the
        // last level would index out of bounds.
        let every_level = (0..table.shape.levels.len())
            .fold(OVERFLOW_LEVEL_BIT, |mask, level| mask | level_bit_of(level));
        for key in 0..live + 4_096 {
            let hash = table.hash_builder.hash_one(key);
            let fingerprint = table.prf.prepare(hash).fingerprint();
            let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(hash);
            let expected = match ordered_walk(table, &key, hash) {
                Walked::Hit(slot) => Some(slot),
                Walked::Vacant(_) | Walked::Full => None,
            };
            assert_eq!(
                table.lookup_recorded_levels(&key, probe, fingerprint, every_level),
                expected,
                "{label} key={key}"
            );
        }
    });
}

#[test]
#[cfg_attr(miri, ignore)]
fn deletes_past_the_threshold_refresh_the_membership_filter() {
    test_support::assert_deletes_past_threshold_refresh_filter::<
        FunnelTable<u64, u64, test_support::FixedHashBuilder>,
    >(
        |table, key| {
            table
                .membership_gate(table.hash_builder.hash_one(key))
                .passes()
        },
        FunnelTable::stale_membership,
        |threshold| threshold + 1,
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn pop_first_churn_restores_paper_placement() {
    test_support::assert_pop_first_churn_restores_paper_placement::<
        FunnelTable<u64, u64, test_support::FixedHashBuilder>,
    >(|table| table.exceptional_placement);
}

#[test]
#[cfg_attr(miri, ignore)]
fn selector_reuses_a_geometry_at_its_reported_capacity() {
    let reserve = ReserveFraction::from_exponent(3).unwrap();
    for requested in 1..512 {
        let selected = FunnelShape::for_insert_budget(requested, reserve).unwrap();
        let at_capacity = FunnelShape::for_insert_budget(selected.max_insertions, reserve).unwrap();
        assert_eq!(at_capacity.n, selected.n, "request={requested}");
        assert_eq!(at_capacity.max_insertions, selected.max_insertions);
    }
    let headline = FunnelShape::for_insert_budget(28_672, reserve).unwrap();
    assert_eq!(headline.n, 32_767);
    assert_eq!(headline.max_insertions, 28_672);
}

/// Rebuilds a scalar location's global slot from `shape`, checking each
/// component against the region it names.
fn decompose_scalar_location(shape: &FunnelShape, location: ScalarFunnelLocation) -> usize {
    match location {
        ScalarFunnelLocation::Ordinary {
            level,
            bucket,
            slot_in_bucket,
            ..
        } => {
            assert!(bucket < shape.levels[level].buckets);
            assert!(slot_in_bucket < shape.beta);
            bucket_slots(shape, &shape.levels[level], bucket)
                .nth(slot_in_bucket)
                .unwrap()
        }
        ScalarFunnelLocation::SpecialPrimary { slot, .. } => {
            assert!(slot < shape.primary_range.upper());
            shape.primary_offset + slot
        }
        ScalarFunnelLocation::SpecialFallback {
            bucket,
            slot_in_bucket,
            ..
        } => {
            assert!(bucket < shape.fallback_bucket_range.upper());
            assert!(slot_in_bucket < shape.fallback_bucket_width);
            shape.fallback_offset + bucket * shape.fallback_bucket_width + slot_in_bucket
        }
    }
}

/// The oracle's number for storage slot `slot`. The oracle packs each
/// level's buckets end to end. The storage lays a level out as every
/// bucket's first group of lanes, one whole group each, leaving the lanes
/// past a narrower bucket unused, then every bucket's remaining lanes end to
/// end. Both lay the special regions after the ordinary levels.
fn scalar_slot_number(config: PaperConfig, slot: usize) -> usize {
    let plan = config.funnel_plan().unwrap();
    let beta = plan.beta();
    let tail_width = beta.saturating_sub(GROUP_SIZE);
    let mut storage_base = 0;
    let mut oracle_base = 0;
    for buckets in plan.ordinary_bucket_counts() {
        let heads = buckets * GROUP_SIZE;
        let rel = slot - storage_base;
        if rel < heads + buckets * tail_width {
            let (bucket, lane) = if rel < heads {
                (rel / GROUP_SIZE, rel % GROUP_SIZE)
            } else {
                let past = rel - heads;
                (past / tail_width, GROUP_SIZE + past % tail_width)
            };
            assert!(lane < beta, "slot {slot} is a padding lane");
            return oracle_base + bucket * beta + lane;
        }
        storage_base += heads + buckets * tail_width;
        oracle_base += buckets * beta;
    }
    slot - storage_base + oracle_base
}

#[test]
#[cfg_attr(miri, ignore)]
fn funnel_locations_match_the_independent_scalar_oracle() {
    for &(n, d) in &[(144, 3), (344, 4), (1_372, 6), (5_472, 8), (21_856, 10)] {
        let config = PaperConfig::new(n, d).unwrap();
        let mut scalar = ScalarFunnel::new(
            config,
            FunnelPrf::new(FUNNEL_PROBE_SEED),
            NonZeroU32::new(probe::RANGE_WORD_CAP).unwrap(),
        );
        let mut table = raw_table(n, d);
        let mut locations = Vec::with_capacity(config.max_insertions());
        for identity in 0..config.max_insertions() as u64 {
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
            let actual = table.find(&identity, identity).unwrap();
            // The oracle numbers its slots without the padding lanes.
            assert_eq!(
                scalar_slot_number(config, actual),
                expected.global_slot(),
                "n={n} key={identity}"
            );
            // The shape's regions name the same slot by level, bucket and
            // lane.
            assert_eq!(
                actual,
                decompose_scalar_location(&table.shape, expected),
                "n={n} key={identity}"
            );
            locations.push((
                identity,
                actual,
                table.storage.checked_slot_ptr(actual) as usize,
            ));
            assert_eq!(table.find(&identity, identity), Some(actual));
        }
        assert_eq!(table.entries(), scalar.len());
        assert_eq!(scalar.locations().count(), locations.len());
        for (expected, identity) in scalar.locations() {
            let global_slot = locations[usize::try_from(identity).unwrap()].1;
            assert_eq!(
                decompose_scalar_location(&table.shape, expected),
                global_slot,
                "n={n} key={identity} {expected:?}"
            );
        }
        for &(identity, location, pointer) in &locations {
            assert_eq!(
                table.find(&identity, identity),
                Some(location),
                "moved n={n} key={identity}"
            );
            assert_eq!(table.storage.checked_slot_ptr(location) as usize, pointer);
        }

        let duplicate = config.max_insertions() as u64 / 2;
        let len = table.entries();
        assert_eq!(
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(
                &mut table,
                duplicate,
                u64::MAX,
                duplicate,
            ),
            Some(duplicate ^ 0x55)
        );
        assert_eq!(table.entries(), len);
        assert_eq!(
            table.find(&duplicate, duplicate),
            Some(locations[duplicate as usize].1)
        );

        let absent = config.max_insertions() as u64 + 1_000_000;
        assert_eq!(table.find(&absent, absent), None);
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn funnel_search_reaches_primary_and_alternating_fallback_in_order() {
    fn sample(identity: u64, domain: ProbeDomain, logical: u64, upper: usize) -> usize {
        probe::unbiased_probe_index(
            &FunnelPrf::new(FUNNEL_PROBE_SEED),
            identity,
            domain,
            logical,
            upper,
            probe::RANGE_WORD_CAP,
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
        if control::is_free(table.storage.checked_control(slot)) {
            // SAFETY: `checked_control` bounds-checked `slot`.
            unsafe {
                table
                    .storage
                    .write_with_control(slot, SlotEntry { key, value: key }, fingerprint);
            }
            // Placing a slot directly still owes the filter its record.
            let membership = table.membership_slot(key);
            table.record_membership(membership, table.level_bit(slot));
            table.set_entries(table.entries() + 1);
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
    let fingerprint = table.prf.prepare(identity).fingerprint();
    let dummy_fingerprint = fingerprint ^ 1;

    for level_index in 0..table.shape.levels.len() {
        let level = table.shape.levels[level_index];
        let bucket = sample(
            identity,
            ProbeDomain::FunnelOrdinary {
                level: level_index as u64,
            },
            0,
            level.buckets,
        );
        for slot in bucket_slots(&table.shape, &level, bucket) {
            occupy(&mut table, slot, u64::MAX - slot as u64, dummy_fingerprint);
        }
    }

    let first_primary = sample(
        identity,
        ProbeDomain::FunnelSpecialPrimary,
        0,
        table.shape.primary_range.upper(),
    );
    assert_eq!(
        ordered_walk(&table, &identity, identity),
        Walked::Vacant(table.shape.primary_offset + first_primary)
    );
    for logical in 0..table.shape.loglog_ceiling {
        let local = sample(
            identity,
            ProbeDomain::FunnelSpecialPrimary,
            u64::try_from(logical).unwrap(),
            table.shape.primary_range.upper(),
        );
        let slot = table.shape.primary_offset + local;
        occupy(&mut table, slot, u64::MAX - local as u64, dummy_fingerprint);
    }

    let first_fallback_bucket = sample(
        identity,
        ProbeDomain::FunnelSpecialFallbackChoiceA,
        0,
        fallback_count,
    );
    let second_fallback_bucket = sample(
        identity,
        ProbeDomain::FunnelSpecialFallbackChoiceB,
        0,
        fallback_count,
    );
    assert_ne!(first_fallback_bucket, second_fallback_bucket);
    let width = table.shape.fallback_bucket_width;
    let first_bucket_slot_zero = table.shape.fallback_offset + first_fallback_bucket * width;
    let second_bucket_slot_zero = table.shape.fallback_offset + second_fallback_bucket * width;
    assert_eq!(
        ordered_walk(&table, &identity, identity),
        Walked::Vacant(first_bucket_slot_zero)
    );

    occupy(
        &mut table,
        first_bucket_slot_zero,
        u64::MAX - 1,
        dummy_fingerprint,
    );
    occupy(
        &mut table,
        second_bucket_slot_zero,
        u64::MAX - 2,
        dummy_fingerprint,
    );
    let first_bucket_slot_one = first_bucket_slot_zero + 1;
    let second_bucket_slot_one = second_bucket_slot_zero + 1;
    assert_eq!(
        ordered_walk(&table, &identity, identity),
        Walked::Vacant(first_bucket_slot_one)
    );
    occupy(
        &mut table,
        first_bucket_slot_one,
        u64::MAX - 3,
        dummy_fingerprint,
    );
    assert_eq!(
        ordered_walk(&table, &identity, identity),
        Walked::Vacant(second_bucket_slot_one)
    );

    occupy(&mut table, second_bucket_slot_one, identity, fingerprint);
    let direct = core::ptr::from_ref(table.find_entry(&identity, identity).unwrap());
    assert_eq!(
        direct,
        table
            .storage
            .checked_slot_ptr(second_bucket_slot_one)
            .cast_const()
    );
}

#[test]
fn level_bits_follow_slot_levels_into_the_special_arrays() {
    let table = raw_table(32_768, 3);
    let levels = &table.shape.levels;
    assert!(
        levels.len() > OVERFLOW_LEVEL,
        "fixture must reach the overflow bit"
    );
    for (index, level) in levels.iter().enumerate() {
        let last = levels
            .get(index + 1)
            .map_or(table.shape.primary_offset, |next| next.offset)
            - 1;
        for slot in [level.offset, last] {
            assert_eq!(table.level_bit(slot), level_bit_of(index), "level {index}");
        }
    }
    for slot in [
        table.shape.primary_offset,
        table.shape.fallback_offset,
        table.shape.slots - 1,
    ] {
        assert_eq!(
            table.level_bit(slot),
            OVERFLOW_LEVEL_BIT,
            "special slot {slot}"
        );
    }
}

#[test]
fn exact_geometry_sums_to_n() {
    let mut table = raw_table(512, 3);
    for key in 0..128_u64 {
        table.insert_for_vacant_by_walk(key, key, key);
    }
    let ordinary_slots = table
        .shape
        .levels
        .iter()
        .map(|level| level.buckets * table.shape.beta)
        .sum::<usize>();
    assert_eq!(
        ordinary_slots
            + table.shape.primary_range.upper()
            + table.shape.fallback_bucket_range.upper() * table.shape.fallback_bucket_width,
        table.shape.n
    );
    let padding = table
        .shape
        .levels
        .iter()
        .map(|level| level.buckets * GROUP_SIZE.saturating_sub(table.shape.beta))
        .sum::<usize>();
    assert_eq!(table.storage.capacity(), table.shape.n + padding);
    assert_eq!(table.shape.slots, table.shape.n + padding);
}

/// A bulk delete that removes nothing cleans up once the tombstones in
/// place come within a group's share of the slots of the threshold, however
/// many placements took a tombstone's lane since the deletes. One tombstone
/// fewer leaves the table as it is, with the count as the bound.
#[test]
fn bulk_delete_cleans_up_a_group_share_of_the_slots_early() {
    type Map = FunnelHashMap<u64, u64, IdentityBuildHasher>;
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;

    for requested in [1, 512, 4_096] {
        for (short, cleans) in [(0, true), (1, false)] {
            let mut map = Map::with_capacity_and_hasher(requested, IdentityBuildHasher);
            let capacity = map.capacity() as u64;
            for index in 0..capacity {
                map.insert(index.wrapping_mul(SPREAD), index);
            }
            let (n, slots) = (map.table().shape.n, map.table().shape.slots);
            let threshold = capacity::tombstone_cleanup_threshold(n);
            let in_place = threshold + 1 - slots / GROUP_SIZE - short;
            for index in 0..=threshold as u64 {
                assert_eq!(map.remove(&index.wrapping_mul(SPREAD)), Some(index));
            }
            let mut fresh = capacity;
            while tombstone_controls(map.table()) > in_place {
                assert_eq!(map.insert(fresh.wrapping_mul(SPREAD), fresh), None);
                fresh += 1;
            }
            assert_eq!(tombstone_controls(map.table()), in_place);
            assert!(map.table().tombstone_bound() > threshold);
            let generation = map.epoch().generation;

            map.retain(|_, _| true);

            let table = map.table();
            let tombstones = if cleans { 0 } else { in_place };
            assert_eq!(tombstone_controls(table), tombstones, "{requested}");
            assert_eq!(table.tombstone_bound(), tombstones, "{requested}");
            assert_eq!(
                map.epoch().generation,
                generation + u64::from(cleans),
                "{requested}"
            );
            for index in threshold as u64 + 1..fresh {
                assert_eq!(map.get(&index.wrapping_mul(SPREAD)), Some(&index));
            }
        }
    }
}

#[test]
fn tombstone_before_a_duplicate_does_not_hide_the_duplicate() {
    let mut table = raw_table(144, 3);
    let first = table.insert_for_vacant_by_walk(100, 1, 42);
    let second = table.insert_for_vacant_by_walk(200, 2, 42);
    assert_ne!(first, second);
    let _ = <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::remove(&mut table, first);

    assert_eq!(
        <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(&mut table, 200, 20, 42,),
        Some(2)
    );
    assert_eq!(table.entries(), 1);
    assert_eq!(tombstone_controls(&table), 1);
    assert_eq!(table.find(&200, 42), Some(second));

    let reused = table.insert_for_vacant_by_walk(300, 3, 42);
    assert_eq!(reused, first);
    assert_eq!(tombstone_controls(&table), 0);
}

#[test]
fn clear_tombstones_each_slot_before_dropping_its_value() {
    test_support::assert_clear_tombstones_each_slot_before_dropping_its_value::<
        FunnelTable<u64, PanicOnFirstDrop, test_support::FixedHashBuilder>,
    >(
        |table| {
            (0..table.shape.slots)
                .map(|slot| table.storage.checked_control(slot))
                .collect()
        },
        |table| assert_eq!(table.entries(), occupied_controls(table)),
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn clear_interrupted_by_a_panicking_drop_keeps_survivors_reachable() {
    use crate::test_support::Deterministic;

    let drops = Arc::new(AtomicUsize::new(0));
    let mut map: FunnelHashMap<u64, PanicOnFirstDrop, test_support::FixedHashBuilder> =
        Deterministic::with_capacity(4_096);
    let keys = 0..map.capacity() as u64;
    for key in keys.clone() {
        map.insert(key, PanicOnFirstDrop(drops.clone()));
    }
    // Tombstones on the survivors' walks.
    // Leaked so the first value drop happens inside `clear`.
    for key in keys.clone().filter(|key| key % 4 == 0) {
        mem::forget(map.remove(&key));
    }

    assert!(catch_unwind(AssertUnwindSafe(|| map.clear())).is_err());
    assert!(map.table().tombstone_bound() >= tombstone_controls(map.table()));
    let reachable = keys.clone().filter(|key| map.get(key).is_some()).count();
    assert_eq!(reachable, map.len(), "every counted survivor is reachable");
    assert!(!map.is_empty(), "the panic interrupted the clear");

    // Reinserting every key must not duplicate a survivor.
    for key in keys.clone() {
        map.insert(key, PanicOnFirstDrop(drops.clone()));
    }
    assert_eq!(map.len(), keys.clone().count());
    assert_eq!(map.iter().count(), map.len());
}

#[test]
fn panicking_hasher_during_resize_keeps_every_entry() {
    test_support::assert_hash_panic_during_resize_keeps_every_entry::<
        FunnelTable<PanicHashKey, CountDrop, test_support::FixedHashBuilder>,
    >(|table| {
        assert_head_addresses_storage(table);
        assert_eq!(table.entries(), occupied_controls(table));
    });
}

/// Deletes the counts have yet to see when a resize starts are settled as the
/// new generation goes in, and must come back out with it when a panicking
/// hasher rolls the resize back.
#[test]
fn panicking_hasher_during_resize_rolls_back_uncounted_deletes() {
    const INSERTED: u64 = 9;
    const REMOVED: u64 = 4;
    let armed = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let reserve = ReserveFraction::from_exponent(3).unwrap();
    let shape = FunnelShape::from_slots(144, reserve).unwrap();
    let mut table = FunnelTable::<PanicHashKey, u64, IdentityBuildHasher>::try_from_shape(
        shape,
        reserve,
        IdentityBuildHasher,
        Global,
    )
    .unwrap();
    let key_of = |id: u64| PanicHashKey {
        id,
        armed: armed.clone(),
        drops: drops.clone(),
    };
    for id in 0..INSERTED {
        assert_eq!(
            map::TableBackend::insert(&mut table, key_of(id), id, id),
            None
        );
    }
    for id in 0..REMOVED {
        let slot = table.find(&key_of(id), id).unwrap();
        map::TableBackend::remove(&mut table, slot);
    }
    assert_ne!(table.uncounted_deletes(), 0, "the deletes were settled");
    let before = map::TableBackend::epoch_snapshot(&table);
    assert_eq!(before.distinct_insertions as u64, INSERTED);
    assert!(before.had_delete);
    let next_shape = FunnelShape::for_insert_budget(256, reserve).unwrap();

    armed.store(true, Ordering::SeqCst);
    let result = catch_unwind(AssertUnwindSafe(|| {
        map::TableBackend::try_resize(&mut table, next_shape.n).unwrap();
    }));
    armed.store(false, Ordering::SeqCst);
    assert!(result.is_err());

    assert_eq!(table.shape.n, 144);
    assert_eq!(table.entries() as u64, INSERTED - REMOVED);
    assert_eq!(tombstone_controls(&table) as u64, REMOVED);
    assert_eq!(table.stale_membership() as u64, REMOVED);
    assert_eq!(map::TableBackend::epoch_snapshot(&table), before);
    assert_eq!(
        table.head_left,
        table
            .shape
            .head_insertions()
            .saturating_sub(table.entries())
    );
    for id in 0..INSERTED {
        assert_eq!(
            map::TableBackend::find_entry(&table, &key_of(id), id).map(|entry| entry.value),
            (id >= REMOVED).then_some(id)
        );
    }

    // The counts still drive placement and the next resize.
    for id in 0..REMOVED {
        assert_eq!(
            map::TableBackend::insert(&mut table, key_of(id), id, id),
            None
        );
    }
    assert_eq!(table.entries() as u64, INSERTED);
    map::TableBackend::try_resize(&mut table, next_shape.n).unwrap();
    assert_eq!(table.entries() as u64, INSERTED);
    assert_eq!(tombstone_controls(&table), 0);
    for id in 0..INSERTED {
        assert_eq!(
            map::TableBackend::find_entry(&table, &key_of(id), id).map(|entry| entry.value),
            Some(id)
        );
    }
}

/// A keyed removal whose settling unwinds, on a hasher that panics in the
/// filter refresh, still drops the pair it unlinked, once: the key is gone
/// from the table and nothing is left to drop it later. On a shape whose
/// head finds the key, and on one whose head misses it in a bucket's tail,
/// where the walk past the head does.
#[test]
fn panicking_hasher_while_a_keyed_removal_settles_drops_the_removed_pair() {
    let headed = {
        let reserve = ReserveFraction::from_exponent(3).unwrap();
        (FunnelShape::from_slots(144, reserve).unwrap(), reserve, 12)
    };
    // Full, so that some bucket fills past its head group.
    let wide = {
        let (wide, _) = smallest_wide_shape();
        let reserve = ReserveFraction::from_exponent(wide).unwrap();
        let shape = FunnelShape::for_insert_budget(13, reserve).unwrap();
        let live = shape.max_insertions as u64 - 1;
        (shape, reserve, live)
    };
    assert!(headed.0.beta <= GROUP_SIZE);
    assert!(wide.0.beta > GROUP_SIZE);
    // The shape with bucket tails has to be filled and then cycled once per
    // insertion it allows, which the interpreter cannot finish.
    let shapes = if cfg!(miri) {
        vec![headed]
    } else {
        vec![headed, wide]
    };
    for (shape, reserve, live) in shapes {
        let armed = Arc::new(AtomicBool::new(false));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut table =
            FunnelTable::<PanicHashKey, CountDrop, IdentityBuildHasher>::try_from_shape(
                shape,
                reserve,
                IdentityBuildHasher,
                Global,
            )
            .unwrap();
        let key_of = |id: u64| PanicHashKey {
            id,
            armed: armed.clone(),
            drops: drops.clone(),
        };
        let value_drops = Arc::new(AtomicUsize::new(0));
        for id in 0..=live {
            let value = CountDrop(value_drops.clone());
            assert!(map::TableBackend::insert(&mut table, key_of(id), value, id).is_none());
        }
        // The head finds the cycled key exactly on the shape without bucket
        // tails; on the other, the key sits in a tail.
        let fits = table.shape.beta <= GROUP_SIZE;
        let in_head = |table: &FunnelTable<PanicHashKey, CountDrop, IdentityBuildHasher>,
                       id: u64| {
            let levels = table.membership_gate(id).recorded().unwrap();
            let prepared = table.prf.prepare(id);
            table.first_match(&key_of(id), prepared, levels).is_ok()
        };
        let churn = (0..=live)
            .rev()
            .find(|&id| {
                let ordinary = table
                    .find(&key_of(id), id)
                    .is_some_and(|slot| slot < table.shape.primary_offset);
                ordinary && in_head(&table, id) == fits
            })
            .unwrap();
        // Cycling one key re-takes its tombstone, so only the stale-filter
        // count grows and the delete that passes its threshold refreshes
        // the filter.
        let threshold = membership::refresh_deletes(table.shape.max_insertions);
        let probe = key_of(churn);
        for _ in 0..threshold {
            assert!(map::TableBackend::take(&mut table, &probe, churn).is_some());
            let value = CountDrop(value_drops.clone());
            assert!(map::TableBackend::insert(&mut table, key_of(churn), value, churn).is_none());
        }
        assert_eq!(in_head(&table, churn), fits);
        let (keys_before, values_before) = (
            drops.load(Ordering::SeqCst),
            value_drops.load(Ordering::SeqCst),
        );
        armed.store(true, Ordering::SeqCst);
        let result = catch_unwind(AssertUnwindSafe(|| {
            map::TableBackend::take(&mut table, &probe, churn)
        }));
        armed.store(false, Ordering::SeqCst);
        let panic = result.err().expect("the refresh hashed no key");
        assert!(
            panic
                .downcast_ref::<&str>()
                .is_some_and(|message| message.contains("armed key hash"))
        );
        assert_eq!(drops.load(Ordering::SeqCst), keys_before + 1);
        assert_eq!(value_drops.load(Ordering::SeqCst), values_before + 1);
        assert_eq!(table.entries() as u64, live);
        assert!(map::TableBackend::find_entry(&table, &probe, churn).is_none());
        for id in (0..=live).filter(|&id| id != churn) {
            assert!(map::TableBackend::find_entry(&table, &key_of(id), id).is_some());
        }
        // Only the live pairs are left for the table to drop.
        let (keys_before, values_before) = (
            drops.load(Ordering::SeqCst),
            value_drops.load(Ordering::SeqCst),
        );
        drop(table);
        assert_eq!((drops.load(Ordering::SeqCst) - keys_before) as u64, live);
        assert_eq!(
            (value_drops.load(Ordering::SeqCst) - values_before) as u64,
            live
        );
    }
}

#[test]
fn interrupted_filter_refresh_keeps_every_live_key_reachable() {
    test_support::assert_interrupted_refresh_keeps_live_keys_reachable::<
        FunnelTable<PanicHashKey, u64, test_support::FixedHashBuilder, ToggleAllocator>,
    >(
        |table, hash| table.membership_gate(hash).passes(),
        FunnelTable::stale_membership,
    );
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
    let reserve = ReserveFraction::from_exponent(3).unwrap();
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
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(&mut table, key, key, key,),
            None
        );
    }
    let arena_bytes = table.arena.layout_size();
    let locations: Vec<_> = (0..32_u64)
        .map(|key| (key, table.find(&key, key).unwrap()))
        .collect();
    let next = FunnelShape::for_insert_budget(512, reserve).unwrap();
    fail.store(true, Ordering::SeqCst);
    assert_eq!(
        map::TableBackend::try_resize(&mut table, next.n),
        Err(TryReserveError::AllocError)
    );
    assert_eq!(table.entries(), 32);
    assert_eq!(table.shape.n, 144);
    assert_eq!(table.arena.layout_size(), arena_bytes);
    for (key, location) in locations {
        assert_eq!(table.find(&key, key), Some(location));
    }

    fail.store(false, Ordering::SeqCst);
    drop(table);
    assert_eq!(allocations.load(Ordering::SeqCst), 1);
    assert_eq!(deallocations.load(Ordering::SeqCst), 1);
}

/// The tombstone-blind scan one control at a time: the result, and the
/// lanes whose keys it compares.
fn scalar_clean_scan(
    controls: &[u8],
    start: usize,
    width: usize,
    fingerprint: u8,
    hit: Option<usize>,
) -> (BucketScanResult<usize>, Vec<usize>) {
    let mut compared = Vec::new();
    for (slot, &control) in controls.iter().enumerate().skip(start).take(width) {
        if control == CTRL_EMPTY {
            return (BucketScanResult::Empty(slot), compared);
        }
        if control == fingerprint {
            compared.push(slot);
            if Some(slot) == hit {
                return (BucketScanResult::Hit(slot), compared);
            }
        }
    }
    (BucketScanResult::Full, compared)
}

/// Holds both vector bucket scans to their scalar order over
/// `controls[start..start + width]`, with `hit` the lane of the key.
fn assert_bucket_scans_match_scalar(
    controls: &[u8],
    start: usize,
    width: usize,
    fingerprint: u8,
    hit: Option<usize>,
    label: &str,
) {
    let (expected, expected_compared) = scalar_clean_scan(controls, start, width, fingerprint, hit);
    let mut compared = Vec::new();
    // SAFETY: the caller's `controls` pads `GROUP_SIZE - 1` bytes past the
    // bucket; the closure touches no slot data.
    let actual = unsafe {
        scan_clean_funnel_bucket(controls.as_ptr(), start, width, fingerprint, |slot| {
            compared.push(slot);
            (Some(slot) == hit).then_some(slot)
        })
    };
    assert_eq!(actual, expected, "{label}");
    assert_eq!(compared, expected_compared, "{label}");

    let first_free = controls[start..start + width]
        .iter()
        .position(|&control| control::is_free(control))
        .map(|lane| start + lane);
    // The run as one bucket: its head group, then the rest as its tail. A
    // bucket without a tail has none to read, so its tail offset is unused.
    let tail = if width > GROUP_SIZE {
        start + GROUP_SIZE
    } else {
        start
    };
    assert_eq!(
        // SAFETY: as above.
        unsafe { first_free_in_bucket(controls.as_ptr(), start, tail, BucketLanes::of(width)) },
        first_free,
        "{label}"
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn vector_bucket_scans_match_scalar_order_for_every_default_pattern() {
    const FP: u8 = 7;
    const OTHER: u8 = 1;
    const WIDTH: usize = 6;
    const PATTERN_COUNT: usize = 4_usize.pow(6);
    let states = [CTRL_EMPTY, CTRL_TOMBSTONE, OTHER, FP];

    for encoded in 0..PATTERN_COUNT {
        // Lanes past the bucket hold what a scan must not report.
        for padding in [FP, CTRL_EMPTY, CTRL_TOMBSTONE] {
            let mut controls = [padding; WIDTH + GROUP_SIZE - 1];
            let mut value = encoded;
            for control in &mut controls[..WIDTH] {
                *control = states[value & 3];
                value >>= 2;
            }
            for hit_lane in 0..=WIDTH {
                assert_bucket_scans_match_scalar(
                    &controls,
                    0,
                    WIDTH,
                    FP,
                    (hit_lane < WIDTH).then_some(hit_lane),
                    &format!("pattern={encoded} padding={padding:#x} hit={hit_lane}"),
                );
            }
        }
    }
}

#[test]
fn vector_bucket_scans_preserve_order_across_group_boundaries_and_padding() {
    const FP: u8 = 7;
    const OTHER: u8 = 1;

    let start = 3;
    for width in [10, 15, 16, 18, 32, 34] {
        let mut controls = vec![OTHER; start + width + GROUP_SIZE - 1];
        let logical_end = start + width;
        for (index, control) in controls[logical_end..].iter_mut().enumerate() {
            *control = if index.is_multiple_of(2) {
                FP
            } else {
                CTRL_EMPTY
            };
        }
        // Nothing free in the bucket: the scans end on its last lane.
        let collision = start + (GROUP_SIZE - 1).min(width - 2);
        let hit = start + GROUP_SIZE.min(width - 2);
        controls[collision] = FP;
        controls[hit] = FP;
        let label = format!("full width={width}");
        assert_bucket_scans_match_scalar(&controls, start, width, FP, Some(hit), &label);
        assert_bucket_scans_match_scalar(&controls, start, width, FP, None, &label);

        // A tombstone before the key, and an EMPTY in the last lane.
        controls[start + width / 4] = CTRL_TOMBSTONE;
        controls[logical_end - 1] = CTRL_EMPTY;
        let label = format!("tombstone width={width}");
        assert_bucket_scans_match_scalar(&controls, start, width, FP, Some(hit), &label);
        assert_bucket_scans_match_scalar(&controls, start, width, FP, None, &label);

        // An EMPTY ahead of the key ends the scan before it.
        controls.fill(OTHER);
        controls[start + width / 2] = CTRL_EMPTY;
        controls[logical_end - 1] = FP;
        controls[logical_end..].fill(FP);
        assert_bucket_scans_match_scalar(
            &controls,
            start,
            width,
            FP,
            Some(logical_end - 1),
            &format!("empty width={width}"),
        );
    }
}

#[test]
fn drop_continues_past_a_panicking_value() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut map: FunnelHashMap<u64, PanicOnFirstDrop, IdentityBuildHasher> =
        FunnelHashMap::with_capacity_and_hasher(256, IdentityBuildHasher);
    for key in 0..200 {
        map.insert(key, PanicOnFirstDrop(drops.clone()));
    }
    assert!(catch_unwind(AssertUnwindSafe(|| drop(map))).is_err());
    // The panicking value counts too, so every value dropped exactly once.
    assert_eq!(drops.load(Ordering::SeqCst), 200);
}

/// Smallest valid `n` by trying every slot count from 2 upward.
fn for_insert_budget_by_scan(requested: usize, reserve: ReserveFraction) -> usize {
    (2..usize::MAX)
        .find(|&n| {
            FunnelShape::from_slots(n, reserve).is_ok_and(|shape| shape.max_insertions >= requested)
        })
        .unwrap()
}

#[test]
#[cfg_attr(miri, ignore)]
fn for_insert_budget_finds_the_smallest_valid_slot_count() {
    for exponent in 3..=10 {
        let reserve = ReserveFraction::from_exponent(exponent).unwrap();
        for requested in [1, 2, 1_000, 20_000] {
            assert_eq!(
                FunnelShape::for_insert_budget(requested, reserve)
                    .unwrap()
                    .n,
                for_insert_budget_by_scan(requested, reserve),
                "exponent={exponent} requested={requested}"
            );
        }
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn large_reserve_exponent_sizes_without_scanning_every_slot_count() {
    let reserve = ReserveFraction::from_exponent(40).unwrap();
    let shape = FunnelShape::for_insert_budget(1, reserve).unwrap();
    assert!(FunnelShape::from_slots(shape.n - 1, reserve).is_err());
    assert!(crate::FunnelHashMap::<u64, u64>::try_with_capacity_and_reserve(1, reserve).is_err());
}

/// Whatever the first-match lookup answers itself, the ordered walk answers
/// the same; every other lookup is handed to that walk. Covers small and
/// large tables, shared fingerprints, deletes, absent keys,
/// and a bucket wider than one group.
#[test]
#[cfg_attr(miri, ignore = "walks hundreds of thousands of lookups twice")]
fn first_match_lookup_agrees_with_the_ordered_walk_whenever_it_answers() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let feasible = |n: &usize, d: u32| {
        FunnelShape::from_slots(*n, ReserveFraction::from_exponent(d).unwrap()).is_ok()
    };
    let shapes: Vec<(usize, u32)> = [(600, 3), (6_000, 3), (6_000, 4), (60_000, 9), (300_000, 3)]
        .into_iter()
        .map(|(at_least, d)| {
            let n = (at_least..2 * at_least).find(|n| feasible(n, d));
            (n.unwrap(), d)
        })
        .collect();
    for (n, d) in shapes {
        for shared_fingerprint in [false, true] {
            let mut table = raw_table(n, d);
            let inserted = table.shape.max_insertions as u64;
            // Under the table's first seed, which only a rebuild replaces.
            let prf = table.prf;
            let shared = prf.prepare(0).fingerprint();
            let kept = |key: &u64| !shared_fingerprint || prf.prepare(*key).fingerprint() == shared;
            let keys: Vec<u64> = (0..)
                .map(|index: u64| index.wrapping_mul(SPREAD))
                .filter(kept)
                .take(2 * table.shape.max_insertions)
                .collect();
            let key_of = |index: u64| keys[usize::try_from(index).unwrap()];
            for index in 0..inserted {
                let key = key_of(index);
                assert_eq!(map::TableBackend::insert(&mut table, key, index, key), None);
            }
            for index in (0..inserted).step_by(3) {
                let key = key_of(index);
                let slot = table.find(&key, key).unwrap();
                map::TableBackend::remove(&mut table, slot);
            }
            let wide = table.shape.beta > GROUP_SIZE;
            let (mut answered, mut handed_off) = (0_usize, 0_usize);
            for index in 0..2 * inserted {
                let key = key_of(index);
                let gate = table.membership_gate(key);
                let Some(recorded) = gate.recorded() else {
                    continue;
                };
                let walk = table.find_location_by_walk(&key, key, gate.levels());
                let live = index < inserted && index % 3 != 0;
                assert_eq!(walk.is_some(), live, "n {n} d {d} index {index}");
                // The whole lookup, through whichever path settles it.
                assert_eq!(table.find(&key, key), walk, "n {n} d {d} index {index}");
                let probe = table.prf.prepare(key);
                let scan = table
                    .first_match(&key, probe, recorded)
                    .map(|found| table.slot_of(found.lane));
                let found = scan.ok();
                // An empty bin and the overflow bit each end on an absent
                // entry, whatever the membership bits; neither finds
                // anything.
                let ends_on = |levels: u16, bits: u32| {
                    let unit =
                        WideLevelBin::of_recording_unit(unit_of(bits, levels), bits).unwrap();
                    table
                        .first_match(&key, probe, unit)
                        .map(|found| table.slot_of(found.lane))
                };
                for bits in [1, 1 << (MEMBERSHIP_BITS - 1)] {
                    for levels in [0, OVERFLOW_LEVEL_BIT] {
                        assert!(
                            ends_on(levels, bits).is_err_and(HeadLevel::is_absent),
                            "n {n} d {d} index {index}"
                        );
                    }
                }
                if scan.map_or_else(|last| table.unmatched_is_absent(last), |_| true) {
                    assert_eq!(found, walk, "n {n} d {d} index {index}");
                    // A miss in a head group never settles a bucket with a
                    // tail.
                    assert!(found.is_some() || !wide, "n {n} d {d} index {index}");
                    answered += 1;
                } else {
                    handed_off += 1;
                }
            }
            assert_ne!(answered, 0, "n {n} d {d}");
            if wide {
                assert_ne!(handed_off, 0, "n {n} d {d}");
            }
        }
    }
}

/// The first-match walk takes any unit that is not zero: an empty bin, bits
/// under the bin, every bit. It ends on the head entry of the bin's lowest
/// set bit, or on the entry of the unit's leading zeros for an empty bin; a
/// key it finds is where the ordered walk finds it, and bits added to a
/// key's own unit do not hide the key. On a shape whose buckets fit a group
/// and on one whose buckets have tails.
#[test]
fn first_match_walks_any_half_word_to_the_entry_of_its_lowest_bit() {
    const HALVES: [u32; 8] = [
        1,
        1 << 15,
        1 << 16,
        0x0000_FFFF,
        0x8000_0001,
        0x5555_5555,
        0xDEAD_BEEF,
        u32::MAX,
    ];
    let reserve = ReserveFraction::from_exponent(3).unwrap();
    let headed = head_table(
        FunnelShape::for_insert_budget(24, reserve).unwrap(),
        reserve,
    );
    let (wide, _) = smallest_wide_shape();
    let wide_reserve = ReserveFraction::from_exponent(wide).unwrap();
    let wide = head_table(
        FunnelShape::for_insert_budget(24, wide_reserve).unwrap(),
        wide_reserve,
    );
    assert!(headed.shape.beta <= GROUP_SIZE);
    assert!(wide.shape.beta > GROUP_SIZE);
    for mut table in [headed, wide] {
        let inserted = 24;
        assert!(table.shape.max_insertions as u64 >= inserted);
        for key in 0..inserted {
            assert_eq!(map::TableBackend::insert(&mut table, key, key, key), None);
        }
        let mut found_in_head = 0_usize;
        for key in 0..inserted + 4 {
            let probe = table.prf.prepare(key);
            let walk = table.find_location_by_walk(&key, key, u16::MAX);
            assert_eq!(walk.is_some(), key < inserted, "key {key}");
            let recorded = table.membership_gate(key).recorded();
            let own = recorded.map_or(0, WideLevelBin::get);
            let in_head =
                recorded.is_some_and(|levels| table.first_match(&key, probe, levels).is_ok());
            found_in_head += usize::from(in_head);
            for half in HALVES.into_iter().chain(HALVES.map(|half| half | own)) {
                let lowest = match half & UNIT_BIN_BITS {
                    0 => half.leading_zeros() as usize,
                    bin => (u32::BITS - 1 - bin.trailing_zeros()) as usize,
                };
                let unit = WideLevelBin::of_recording_unit(half, half).unwrap();
                match table.first_match(&key, probe, unit) {
                    Ok(found) => {
                        let slot = table.slot_of(found.lane);
                        assert_eq!(Some(slot), walk, "key {key} half {half:#x}");
                    }
                    Err(last) => {
                        assert!(
                            core::ptr::eq(last, &raw const table.head[lowest]),
                            "key {key} half {half:#x}"
                        );
                        assert!(!in_head || half & own != own, "key {key} half {half:#x}");
                    }
                }
            }
        }
        assert_ne!(found_in_head, 0);
    }
}

/// Removal by key takes each entry a model map holds and nothing else,
/// whichever lookup path finds it: the first-match scan, the walk past the
/// head that a key in a bucket's tail is handed to, and both again over the
/// tombstones earlier removals left.
#[test]
#[cfg_attr(miri, ignore = "fills tens of thousands of slots")]
fn removal_by_key_agrees_with_a_model_on_every_lookup_path() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let feasible = |n: &usize, d: u32| {
        FunnelShape::from_slots(*n, ReserveFraction::from_exponent(d).unwrap()).is_ok()
    };
    let check = |table: &FunnelTable<u64, u64, IdentityBuildHasher>,
                 model: &alloc::collections::BTreeMap<u64, u64>,
                 keys: u64| {
        assert_eq!(table.entries(), model.len());
        for index in 0..keys {
            let key = index.wrapping_mul(SPREAD);
            let found = table.find_entry(&key, key).map(|entry| entry.value);
            assert_eq!(found, model.get(&key).copied(), "index {index}");
        }
    };
    for (at_least, d) in [(600, 3), (6_000, 4), (60_000, 9)] {
        let n = (at_least..2 * at_least).find(|n| feasible(n, d)).unwrap();
        let mut table = raw_table(n, d);
        let mut model = alloc::collections::BTreeMap::new();
        let inserted = table.shape.max_insertions as u64 - 1;
        for index in 1..inserted {
            let key = index.wrapping_mul(SPREAD);
            assert_eq!(map::TableBackend::insert(&mut table, key, index, key), None);
            model.insert(key, index);
        }
        let keys = 2 * inserted;
        check(&table, &model, keys);
        // Present and absent keys, interleaved.
        for index in (0..keys).filter(|index| index % 3 != 1) {
            let key = index.wrapping_mul(SPREAD);
            assert_eq!(
                map::TableBackend::take(&mut table, &key, key),
                model.remove_entry(&key),
                "n {n} d {d} index {index}"
            );
            // A removed key is gone at once.
            assert_eq!(
                map::TableBackend::take(&mut table, &key, key),
                None,
                "n {n} d {d} index {index}"
            );
        }
        assert!(!model.is_empty());
        check(&table, &model, keys);
        // Over tombstones, and into the slots they free.
        for index in (1..inserted).filter(|index| index % 3 == 0) {
            let key = index.wrapping_mul(SPREAD);
            assert_eq!(
                map::TableBackend::insert(&mut table, key, !index, key),
                None
            );
            model.insert(key, !index);
        }
        check(&table, &model, keys);
        for index in 0..keys {
            let key = index.wrapping_mul(SPREAD);
            assert_eq!(
                map::TableBackend::take(&mut table, &key, key),
                model.remove_entry(&key),
                "n {n} d {d} index {index}"
            );
        }
        assert!(model.is_empty());
        check(&table, &model, keys);
    }
}

/// The slot the ordered walk finds `key` in.
fn walked_hit(table: &DifferentialTable, key: HashedKey) -> Option<usize> {
    match ordered_walk(table, &key, key.hash) {
        Walked::Hit(slot) => Some(slot),
        Walked::Vacant(_) | Walked::Full => None,
    }
}

/// Checks that a lookup and an entry search of each of `keys` find the slot
/// the ordered walk ends on. Returns how many of the keys sit in the special
/// arrays and how many in a bucket's tail.
fn assert_keyed_lookups_answer_as_the_walk(
    table: &DifferentialTable,
    keys: impl Iterator<Item = HashedKey>,
) -> (usize, usize) {
    let heads_end = |level: &LevelShape| level.offset + level.buckets * GROUP_SIZE;
    let level_end =
        |level: &LevelShape| level.offset + level.buckets * table.shape.beta.max(GROUP_SIZE);
    let (mut special, mut tail) = (0_usize, 0_usize);
    for key in keys {
        let walk = walked_hit(table, key);
        let levels = table.membership_gate(key.hash).levels();
        assert_eq!(
            table.find_location_by_walk(&key, key.hash, levels),
            walk,
            "{key:?}"
        );
        assert_eq!(table.find(&key, key.hash), walk, "{key:?}");
        assert_eq!(
            table.find_entry(&key, key.hash).map(core::ptr::from_ref),
            // SAFETY: the walk ends on an initialized entry.
            walk.map(|slot| core::ptr::from_ref(unsafe { table.storage.get_ref(slot) })),
            "{key:?}"
        );
        assert_eq!(table.find_for_entry(&key, key.hash).ok(), walk, "{key:?}");
        let Some(slot) = walk else { continue };
        special += usize::from(slot >= table.shape.primary_offset);
        tail += usize::from(
            table
                .shape
                .levels
                .iter()
                .any(|level| (heads_end(level)..level_end(level)).contains(&slot)),
        );
    }
    (special, tail)
}

/// Every keyed answer is the ordered walk's, for buckets that fit a group
/// and for buckets with tails: a lookup, an entry search and a removal find
/// the slot the walk ends on, an insert of a present key replaces the value
/// there, and one of an absent key places where the walk ends. The table is
/// full, with a cluster of keys sharing one hash spilling into the special
/// arrays, then thinned to tombstones and partly refilled over them.
#[test]
#[cfg_attr(miri, ignore = "fills tens of thousands of slots")]
fn keyed_operations_answer_as_the_ordered_walk_for_every_bucket_width() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let feasible = |n: &usize, d: u32| {
        FunnelShape::from_slots(*n, ReserveFraction::from_exponent(d).unwrap()).is_ok()
    };
    // Exponent `GROUP_SIZE / 2` gives buckets exactly one group wide.
    let exact = (6_000, u32::try_from(GROUP_SIZE / 2).unwrap());
    for (at_least, d) in [(6_000, 3), exact, (6_000, 5), (12_000, 7), (21_856, 10)] {
        let n = (at_least..2 * at_least).find(|n| feasible(n, d)).unwrap();
        let reserve = ReserveFraction::from_exponent(d).unwrap();
        let mut table = DifferentialTable::try_from_shape(
            FunnelShape::from_slots(n, reserve).unwrap(),
            reserve,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
        let budget = table.shape.max_insertions as u64;
        // Two keys past what the cluster's bucket in every level holds.
        let cluster = (table.shape.levels.len() * table.shape.beta + 2) as u64;
        let key_of = |id: u64| HashedKey {
            id,
            hash: if id < cluster { u64::MAX } else { id }.wrapping_mul(SPREAD),
        };
        let check_lookups = |table: &DifferentialTable, keys: u64| {
            assert_keyed_lookups_answer_as_the_walk(table, (0..keys).map(key_of))
        };
        for id in 0..budget {
            let key = key_of(id);
            assert_eq!(table.insert(key, id, key.hash), None, "d {d} id {id}");
        }
        let (special, tail) = check_lookups(&table, 2 * budget);
        assert_ne!(special, 0, "d {d}");
        assert_eq!(tail != 0, table.shape.beta > GROUP_SIZE, "d {d}");
        // Present keys: an insert replaces the value in place.
        for id in (0..budget).step_by(5) {
            let key = key_of(id);
            let slot = walked_hit(&table, key);
            assert_eq!(table.insert(key, !id, key.hash), Some(id), "d {d} id {id}");
            assert_eq!(table.find(&key, key.hash), slot, "d {d} id {id}");
            assert_eq!(
                table.find_entry(&key, key.hash).map(|entry| entry.value),
                Some(!id)
            );
        }
        // Removals take the slot the walk ends on and leave a tombstone.
        for id in (0..2 * budget).step_by(3) {
            let key = key_of(id);
            let slot = walked_hit(&table, key);
            let taken = table.take(&key, key.hash);
            assert_eq!(
                taken.map(|(key, _)| key.id),
                slot.map(|_| id),
                "d {d} id {id}"
            );
            if let Some(slot) = slot {
                // SAFETY: `slot` is below the storage capacity.
                let control = unsafe { table.storage.control_at(slot) };
                assert_eq!(control, CTRL_TOMBSTONE, "d {d} id {id}");
            }
        }
        let removed = budget - table.entries() as u64;
        check_lookups(&table, 2 * budget);
        // Absent keys: an insert below the budget places where the walk ends.
        let storage = table.storage.ctrl_ptr();
        let refilled = 2 * budget + removed / 2;
        for id in 2 * budget..refilled {
            let key = key_of(id);
            let Walked::Vacant(slot) = ordered_walk(&table, &key, key.hash) else {
                panic!("d {d} id {id} has no vacancy");
            };
            assert_eq!(table.insert(key, id, key.hash), None, "d {d} id {id}");
            assert_eq!(table.storage.ctrl_ptr(), storage, "d {d} id {id}");
            assert_eq!(table.find(&key, key.hash), Some(slot), "d {d} id {id}");
        }
        check_lookups(&table, refilled);
        assert!(!table.exceptional_placement, "d {d}");
    }
}
