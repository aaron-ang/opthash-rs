use core::cell::Cell;
use core::mem::ManuallyDrop;
use core::num::NonZeroU32;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::sync::Arc;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::*;
use crate::exact::probe::{self, ProbeDomain};
use crate::exact::reference::{ScalarFunnel, ScalarFunnelInsert, ScalarFunnelLocation};
use crate::test_support::{
    self, IdentityBuildHasher, PanicHashKey, PanicOnFirstDrop, ToggleAllocator,
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

/// Every map path that carries an absent search into insertion. Set
/// `get_or_insert` and `get_or_insert_with` wrap `Entry` and the key path.
#[derive(Clone, Copy, Debug)]
enum VacantPath {
    Entry,
    TryInsert,
    GetOrInsertKey,
}

#[test]
fn vacant_paths_reuse_search_unless_growth_invalidates_it() {
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
                assert_eq!(map.table().tombstones(), 1);
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
                assert_eq!(walks, 0, "{label}: absent search already found the vacancy");
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
fn entry_search_checks_exceptional_hits_before_reusing_vacancy() {
    use crate::map::TableBackend;

    let mut table = raw_table(512, 3);
    let key = 42;
    let fingerprint = table.prf.prepare(key).fingerprint();
    let exact = table.search_exact_for_insert(&key, key, fingerprint);
    let slot = table.shape.slots - 1;
    assert_ne!(exact, SearchResult::Vacant(slot));
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
    // scan before its exact-search vacancy is safe to reuse.
    let vacant = table.find_for_entry(&99, key).err().unwrap();
    VACANCY_WALKS.with(|walks| walks.set(0));
    let inserted = table.insert_for_vacant(99, 8, vacant);
    assert_eq!(VACANCY_WALKS.with(Cell::get), 0);
    assert_eq!(exact, SearchResult::Vacant(inserted));
    assert_eq!(table.find_location(&99, key), Some(inserted));
    assert_eq!(table.find_location(&key, key), Some(slot));
}

#[test]
fn vacant_entry_filter_rejection_still_searches_for_placement() {
    let comparisons = Arc::new(AtomicUsize::new(0));
    let key = CountingKey {
        id: 1,
        comparisons: comparisons.clone(),
    };
    let mut map = FunnelHashMap::with_capacity_and_hasher(64, test_support::fixed_hasher());
    VACANCY_WALKS.with(|walks| walks.set(0));
    assert_eq!(*map.entry(key.clone()).or_insert(10), 10);
    assert_eq!(comparisons.load(Ordering::Relaxed), 0);
    assert_eq!(VACANCY_WALKS.with(Cell::get), 1);
    assert_eq!(map.get(&key), Some(&10));
}

#[test]
fn exhausted_vacant_entry_rebuilds_and_walks_again_before_exceptional_placement() {
    use crate::map::TableBackend;

    let mut table = raw_table(512, 3);
    let hash = 42;
    let fingerprint = table.prf.prepare(hash).fingerprint();
    let absent = u64::MAX;
    while let SearchResult::Vacant(_) = table.search_exact_for_insert(&absent, hash, fingerprint) {
        let key = table.entries() as u64;
        table.insert_for_vacant_entry(key, key, hash);
        assert!(table.entries() < table.shape.max_insertions);
    }
    assert_eq!(
        table.search_exact_for_insert(&absent, hash, fingerprint),
        SearchResult::Full
    );
    let vacant = table.find_for_entry(&absent, hash).err().unwrap();
    let old_len = table.entries();
    let old_seed = table.prf;
    VACANCY_WALKS.with(|walks| walks.set(0));
    let inserted = table.insert_for_vacant(absent, 99, vacant);

    // The colliding keys were placed under one forced hash; the rebuild
    // rehashes them, so the walk after it finds a vacancy in the funnel.
    assert_eq!(
        VACANCY_WALKS.with(Cell::get),
        1,
        "the head walk places each survivor; the new key walks afresh"
    );
    assert_eq!(table.entries(), old_len + 1);
    assert_ne!(table.prf, old_seed);
    assert!(!table.exceptional_placement);
    assert_eq!(
        table.epoch_snapshot().transition,
        EpochTransition::PlacementRecovery
    );
    assert_eq!(table.entries(), old_len + 1);
    assert_eq!(table.find_location(&absent, hash), Some(inserted));
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

#[test]
fn dense_scan_preserves_order_while_removals_make_the_table_sparse() {
    let mut table = raw_table(344, 4);
    let slots = (0..320).filter(|slot| slot % 11 != 0).collect::<Vec<_>>();
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

#[test]
fn sparse_scan_visits_group_boundaries_and_tail_once_in_slot_order() {
    let mut table = raw_table(32_767, 3);
    let slots = [0, GROUP_SIZE - 1, GROUP_SIZE, 3 * GROUP_SIZE + 2, 32_766];
    for slot in slots {
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
    // SAFETY: the table holds well over `GROUP_SIZE + 1` slots.
    unsafe { table.storage.mark_tombstone(GROUP_SIZE + 1) };
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

#[test]
fn refresh_membership_rebuilds_the_recorded_filter() {
    let mut table = raw_table(32_767, 3);
    for key in 0..64_u64 {
        assert!(!table.place_unique(
            SlotEntry { key, value: key },
            table.hash_builder.hash_one(key)
        ));
    }
    let recorded = filter_tail(&table);
    table.clear_membership();
    table.refresh_membership();
    assert_eq!(filter_tail(&table), recorded);
}

/// Every unit of `table`'s filter tail, level bin and membership alike.
fn filter_tail<V>(table: &FunnelTable<u64, V, IdentityBuildHasher>) -> Vec<u64> {
    let units = table.membership.region.words;
    // SAFETY: the tail holds `units` initialized units from its base on; a
    // table without any reads none.
    unsafe { core::slice::from_raw_parts(table.membership_ptr(), units).to_vec() }
}

/// Every control byte and filter word of `table`.
fn controls_and_filter<V>(table: &FunnelTable<u64, V, IdentityBuildHasher>) -> (Vec<u8>, Vec<u64>) {
    // SAFETY: `slot < slots`, the storage capacity.
    let controls = (0..table.shape.slots)
        .map(|slot| unsafe { table.storage.control_at(slot) })
        .collect();
    (controls, filter_tail(table))
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
            let slot = walked.insert_for_vacant_entry(key, index, key);
            assert_eq!(
                inline.find_location(&key, key),
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
        let slot = rebuilt.find_location(&key, key).unwrap();
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
        walked.insert_for_vacant_entry(key, value, key);
    }
    assert_eq!(rebuilt.entries(), survivors.len(), "n {n} d {d}");
    assert_eq!(rebuilt.head_left, walked.head_left, "n {n} d {d}");
    assert_eq!(rebuilt.tombstones(), 0);
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

/// With tombstones the frameless insert stands aside: the placement walk
/// takes a tombstone ahead of the first EMPTY lane.
#[test]
#[cfg_attr(miri, ignore)]
fn insert_reuses_tombstones_like_the_placement_walk() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    for (n, d) in [(4096, 3), (1 << 14, 3)] {
        let mut inline = raw_table(n, d);
        let mut walked = raw_table(n, d);
        let budget = inline.shape.max_insertions as u64;
        for index in 0..budget {
            let key = index.wrapping_mul(SPREAD);
            map::TableBackend::insert(&mut inline, key, index, key);
            walked.insert_for_vacant_entry(key, index, key);
        }
        let removed = (0..budget).step_by(4);
        for index in removed.clone() {
            let key = index.wrapping_mul(SPREAD);
            for table in [&mut inline, &mut walked] {
                let slot = table.find_location(&key, key).unwrap();
                map::TableBackend::remove(table, slot);
            }
        }
        assert_eq!(inline.tombstones(), removed.clone().count());
        let mut reused_unrecorded = 0;
        for index in (budget..).take(removed.count()) {
            let key = index.wrapping_mul(SPREAD);
            let unrecorded = !inline.membership_gate(key).passes();
            let tombstones = walked.tombstones();
            assert_eq!(
                map::TableBackend::insert(&mut inline, key, index, key),
                None
            );
            let slot = walked.insert_for_vacant_entry(key, index, key);
            assert_eq!(
                inline.find_location(&key, key),
                Some(slot),
                "n {n} d {d} index {index}"
            );
            reused_unrecorded += usize::from(unrecorded && walked.tombstones() < tombstones);
        }
        assert_ne!(reused_unrecorded, 0, "n {n} d {d}");
        assert_eq!(inline.tombstones(), walked.tombstones());
        assert_eq!(controls_and_filter(&inline), controls_and_filter(&walked));
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
            .map(|bucket| (bucket, level.offset + bucket * table.shape.stride))
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
    }
}

/// A key whose hash the test chooses, so several keys can share one.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct HashedKey {
    id: u64,
    hash: u64,
}

impl core::hash::Hash for HashedKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

/// What a differential run met, so each fixture can prove its coverage.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Default)]
struct DifferentialCoverage {
    growths: usize,
    full_budget_inserts: usize,
    tombstone_cleanups: usize,
    clears: usize,
    reseeds: usize,
    exceptional: bool,
    overflow_entries: bool,
    /// A live key whose folded word is zero.
    zero_word_keys: bool,
    overwrites: usize,
    wide_buckets: bool,
    narrow_buckets: bool,
    /// Inserts of an unrecorded key that the head walk placed.
    head_placements: usize,
    /// Inserts of an unrecorded key below the budget that tombstones kept
    /// from the head walk.
    blocked_head_inserts: usize,
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
    use crate::map::TableBackend;

    assert_eq!(table.entries(), model.len());
    assert!(table.entries() <= table.shape.max_insertions);
    // The head placements left are those of a table without tombstones.
    let head_limit = if table.tombstones() == 0 {
        table.shape.head_insertions()
    } else {
        0
    };
    assert_eq!(table.head_left, head_limit.saturating_sub(model.len()));
    // The delete counts are exact with the uncounted deletes added, and no
    // delete ran past a threshold it had to settle at.
    // SAFETY: `slot < slots`, the storage capacity.
    let tombstone_controls = (0..table.shape.slots)
        .filter(|&slot| unsafe { table.storage.control_at(slot) } == CTRL_TOMBSTONE)
        .count();
    assert_eq!(table.tombstones(), tombstone_controls);
    // Lone deletes leave a due cleanup to the next insert of an absent key,
    // which the stream checks; the threshold must still have settled.
    assert_eq!(
        table.cleanup_due(),
        table.tombstones() > capacity::tombstone_cleanup_threshold(table.shape.n)
    );
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
            .find_location(key, key.hash)
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
            slot >= table.shape.primary_offset || slot % table.shape.stride < table.shape.beta,
            "{key:?} sits in a padding lane"
        );
        coverage.overflow_entries |= slot >= overflow_start;
        coverage.zero_word_keys |= key.hash == table.prf.zero_word_hash();
    }
    for key in absent {
        if !model.contains_key(key) {
            assert_eq!(table.find_location(key, key.hash), None, "{key:?}");
            assert_eq!(
                table.find_location_by_walk(key, key.hash, every_level),
                None,
                "{key:?}"
            );
        }
    }
}

/// Inserts `key`, which the model held `previous` for. Where the head walk
/// places a key the filter never recorded is read off the table before the
/// insert runs it, and the insert must have stored the key there.
fn insert_checking_the_head_walk(
    table: &mut DifferentialTable,
    key: HashedKey,
    value: u64,
    previous: Option<u64>,
    coverage: &mut DifferentialCoverage,
) {
    use crate::map::TableBackend;

    let before = table.membership_gate(key.hash);
    let unrecorded = !before.passes();
    let head = unrecorded
        .then(|| table.head_vacancy(table.prf.prepare(key.hash)))
        .flatten();
    coverage.blocked_head_inserts += usize::from(
        unrecorded && table.head_left == 0 && table.entries() < table.shape.max_insertions,
    );
    assert_eq!(table.insert(key, value, key.hash), previous, "{key:?}");
    if let Some(head) = head {
        assert_eq!(previous, None, "{key:?}");
        assert_eq!(
            table.find_location(&key, key.hash),
            Some(table.slot_of(NonNull::new(head.lane).unwrap())),
            "{key:?}"
        );
        assert_eq!(
            table.membership_gate(key.hash).levels(),
            before.levels() | head.level_bit,
            "{key:?}"
        );
        coverage.head_placements += 1;
    }
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
    use crate::map::TableBackend;

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
    let mut state = seed;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    assert_matches_model(&table, &model, universe, &mut coverage);
    let cycle = stream.filling + stream.mixed + stream.draining;
    for step in 0..stream.operations {
        // A filling stretch meets the insertion budget and growth, a mixed
        // one reuses tombstones, and a draining one removes only live keys,
        // so tombstones pass the cleanup threshold; its few inserts draw
        // from the whole universe, so one meets the cleanup left due.
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
        let tombstones = table.tombstones();
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
            let due = table.cleanup_due();
            insert_checking_the_head_walk(&mut table, key, value, previous, &mut coverage);
            // An absent key's insert runs the cleanup its deletes left due.
            if previous.is_none() {
                assert!(!table.cleanup_due(), "step {step}");
                coverage.tombstone_cleanups += usize::from(due);
            } else {
                assert_eq!(table.cleanup_due(), due, "step {step}");
            }
        } else if step % stream.clear_every == stream.clear_every - 1 {
            table.clear();
            model.clear();
            coverage.clears += 1;
        } else {
            let removed = table
                .find(&key, key.hash)
                .map(|location| table.remove(location));
            assert_eq!(
                removed,
                model.remove(&key).map(|value| (key, value)),
                "step {step} remove {key:?}"
            );
            // A remove of a live key adds a tombstone and never rebuilds.
            assert_eq!(
                table.tombstones(),
                tombstones + usize::from(removed.is_some()),
                "step {step}"
            );
        }
        assert!(table.entries() <= table.shape.max_insertions, "step {step}");
        // The first allocation is not a growth.
        coverage.growths += usize::from(slots != 0 && table.shape.n > slots);
        coverage.reseeds += usize::from(table.prf != prf);
        coverage.exceptional |= table.exceptional_placement;
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
        assert!(coverage.tombstone_cleanups > 0, "{coverage:?}");
        assert!(coverage.clears > 0, "{coverage:?}");
        assert!(coverage.overwrites > 0, "{coverage:?}");
        assert!(coverage.zero_word_keys, "{coverage:?}");
        assert!(!coverage.exceptional, "{coverage:?}");
        assert!(coverage.head_placements > 0, "{coverage:?}");
        assert!(coverage.blocked_head_inserts > 0, "{coverage:?}");
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
            assert!(coverage.tombstone_cleanups > 0, "{coverage:?}");
        }
    }
}

/// The smallest shapes on both sides of the group width, from a table without
/// storage through a spent budget, tombstones, a growth, a clear and a
/// reseeding rebuild, with a clone checked at each stage. Miri runs the wide
/// shape only where its budget stays small.
#[test]
fn smallest_shapes_agree_with_a_model_map_through_every_transition() {
    use crate::map::TableBackend;

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
        assert_eq!((table.entries(), table.tombstones()), (budget, 0), "d {d}");
        check(&table, &model);

        // Tombstones on the walks, then inserts that reuse some of them.
        for key in universe[..budget].iter().step_by(3) {
            let location = table.find(key, key.hash).unwrap();
            assert_eq!(table.remove(location), (*key, key.id), "d {d}");
            model.remove(key);
        }
        assert_ne!(table.tombstones(), 0, "d {d}");
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
    }
}

#[test]
fn levels_past_the_head_share_the_overflow_bit() {
    // A deeper level shares the overflow bit, which names no head entry.
    assert_eq!(level_bit_of(OVERFLOW_LEVEL), OVERFLOW_LEVEL_BIT);
    assert_eq!(level_bit_of(usize::MAX), OVERFLOW_LEVEL_BIT);
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
        assert_eq!(head.data, derived.data, "entry {index}");
    }
    assert_eq!(table.head_lanes, table.shape.head_lanes());
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
            let found = table.find_entry_ref(&key, key).map(|entry| entry.value);
            assert_eq!(found, Some(index), "index {index}");
        }
        // Through the head and back out, where the table has room.
        if table.shape.max_insertions as u64 > live {
            let key = key_of(live);
            assert_eq!(map::TableBackend::insert(table, key, live, key), None);
            assert_eq!(
                map::TableBackend::remove_key(table, &key, key),
                Some((key, live))
            );
        }
        assert_eq!(
            map::TableBackend::remove_key(table, &key_of(live), key_of(live)),
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
            .find_entry_ref(&key_of(1), key_of(1))
            .map(|entry| entry.value),
        None
    );
    assert_eq!(
        map::TableBackend::remove_key(&mut cloned, &key_of(1), key_of(1)),
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

/// An empty shape and one with buckets wider than a group keep an all-absent
/// head, which no insert walks and which matches nothing in a first-match
/// scan. Any other shape addresses its levels from the head. An entry that
/// is no level points at the group past the slots.
#[test]
fn lane_less_shapes_scan_nothing_and_keep_an_absent_head() {
    let (wide, smallest_wide) = smallest_wide_shape();
    let wide_reserve = ReserveFraction::from_exponent(wide).unwrap();
    let large_wide = FunnelShape::for_insert_budget(1 << 19, wide_reserve).unwrap();
    let past_the_slots = |table: &FunnelTable<u64, u64, IdentityBuildHasher>,
                          head: &HeadLevel<SlotEntry<u64, u64>>| {
        head.buckets == 0 && table.slot_of(NonNull::new(head.ctrl).unwrap()) == table.shape.slots
    };
    for shape in [FunnelShape::empty(), smallest_wide, large_wide] {
        assert!(!shape.has_head());
        assert_eq!(shape.head_insertions(), 0);
        let table = head_table(shape, wide_reserve);
        assert!(
            table.head[..OVERFLOW_LEVEL]
                .iter()
                .all(HeadLevel::is_absent),
            "n {}",
            table.shape.n
        );
        assert!(table.head.iter().all(|head| past_the_slots(&table, head)));
    }

    let narrow_reserve = ReserveFraction::from_exponent(3).unwrap();
    for budget in [1, 1 << 19] {
        let shape = FunnelShape::for_insert_budget(budget, narrow_reserve).unwrap();
        assert!(shape.beta <= GROUP_SIZE);
        assert_eq!(shape.head_insertions(), shape.max_insertions);
        let table = head_table(shape, narrow_reserve);
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
            assert_eq!(head.data.cast(), data);
        }
        assert!(
            table.head[recorded..OVERFLOW_LEVEL]
                .iter()
                .all(HeadLevel::is_absent)
        );
        assert!(table.head[OVERFLOW_LEVEL].is_absent());
        assert!(!table.head[HEAD_ENTRIES - 1].is_absent());
        assert!(
            table.head[recorded..]
                .iter()
                .all(|head| past_the_slots(&table, head))
        );
    }
}

/// The placement walk must land where the exact search reports `Vacant`
/// for an absent key, on clean epochs and with tombstones on the walk.
#[test]
#[cfg_attr(miri, ignore)]
fn vacancy_walk_matches_exact_search_for_absent_keys() {
    let mut table = raw_table(5_472, 8);
    let live = table.shape.max_insertions as u64;
    for key in 0..live {
        assert!(!table.place_unique(
            SlotEntry { key, value: key },
            table.hash_builder.hash_one(key)
        ));
    }
    let check = |table: &FunnelTable<u64, u64, IdentityBuildHasher>, label: &str| {
        let mut vacant = 0_usize;
        for key in live..live + 4_096 {
            let hash = table.hash_builder.hash_one(key);
            let fingerprint = table.prf.prepare(hash).fingerprint();
            let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(hash);
            let exact = table.search_exact_for_insert(&key, hash, fingerprint);
            assert_eq!(
                table.search_vacancy(probe),
                table.vacancy_of(exact),
                "{label} key={key}"
            );
            vacant += usize::from(matches!(exact, SearchResult::Vacant(_)));
        }
        assert!(vacant > 0, "{label}: fixture never reached a vacancy");
    };
    check(&table, "clean full table");

    for key in (0..live).step_by(3) {
        let hash = table.hash_builder.hash_one(key);
        let slot = table.find_location(&key, hash).unwrap();
        map::TableBackend::remove(&mut table, slot);
    }
    assert!(table.tombstones() > 0);
    check(&table, "tombstoned table");
}

/// With every level bit set, the read-only walk must report exactly the exact
/// search's hits, for present and absent keys, on clean epochs and with
/// tombstones on the walk.
#[test]
#[cfg_attr(miri, ignore)]
fn lookup_walk_matches_exact_search_hits() {
    let mut table = raw_table(5_472, 8);
    let live = table.shape.max_insertions as u64;
    for key in 0..live {
        assert!(!table.place_unique(
            SlotEntry { key, value: key },
            table.hash_builder.hash_one(key)
        ));
    }
    // Every bit `level_bit` can record for this shape; a bit past the last
    // level would index out of bounds.
    let every_level = (0..table.shape.levels.len())
        .fold(OVERFLOW_LEVEL_BIT, |mask, level| mask | level_bit_of(level));
    let check = |table: &FunnelTable<u64, u64, IdentityBuildHasher>, label: &str| {
        for key in 0..live + 4_096 {
            let hash = table.hash_builder.hash_one(key);
            let fingerprint = table.prf.prepare(hash).fingerprint();
            let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(hash);
            let expected = match table.search_exact_for_insert(&key, hash, fingerprint) {
                SearchResult::Hit(slot) => Some(slot),
                SearchResult::Vacant(_) | SearchResult::Full | SearchResult::RangeFailure => None,
            };
            assert_eq!(
                table.lookup_recorded_levels(&key, probe, fingerprint, every_level),
                expected,
                "{label} key={key}"
            );
        }
    };
    check(&table, "clean full table");

    for key in (0..live).step_by(3) {
        let hash = table.hash_builder.hash_one(key);
        let slot = table.find_location(&key, hash).unwrap();
        map::TableBackend::remove(&mut table, slot);
    }
    assert!(table.tombstones() > 0);
    check(&table, "tombstoned table");
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
fn gated_insert_skips_the_duplicate_walk_only_for_unrecorded_keys() {
    let mut table = raw_table(344, 4);
    for key in 0..64_u64 {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(map::TableBackend::insert(&mut table, key, key, hash), None);
        assert!(table.membership_maybe_contains(hash));
    }
    for key in 0..64_u64 {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(
            map::TableBackend::insert(&mut table, key, key + 1, hash),
            Some(key)
        );
    }
    assert_eq!(table.entries(), 64);
    for key in 0..64_u64 {
        let hash = table.hash_builder.hash_one(key);
        let slot = table.find_location(&key, hash).unwrap();
        // SAFETY: `find_location` returns occupied in-bounds slots.
        assert_eq!(unsafe { table.storage.get_ref(slot) }.value, key + 1);
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn selector_finds_known_minimum_exact_geometries() {
    for &(d, expected) in &[
        (3, 144),
        (4, 344),
        (6, 1_372),
        (8, 5_472),
        (9, 10_924),
        (10, 21_856),
    ] {
        let reserve = ReserveFraction::from_exponent(d).unwrap();
        let shape = FunnelShape::for_insert_budget(1, reserve).unwrap();
        assert_eq!(shape.n, expected, "d={d}");
        assert!(PaperConfig::new(shape.n, d).unwrap().funnel_plan().is_ok());
    }
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
            shape.levels[level].offset + bucket * shape.stride + slot_in_bucket
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
            let actual = table.find_location(&identity, identity).unwrap();
            // The oracle numbers its slots without the padding lanes, so the
            // two are compared by level, bucket and lane.
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
            assert_eq!(table.find_location(&identity, identity), Some(actual));
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
                table.find_location(&identity, identity),
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
            table.find_location(&duplicate, duplicate),
            Some(locations[duplicate as usize].1)
        );

        let absent = config.max_insertions() as u64 + 1_000_000;
        assert_eq!(table.find_location(&absent, absent), None);
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
        let start = level.offset + bucket * table.shape.stride;
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
        table.search_exact_for_insert(&identity, identity, fingerprint),
        SearchResult::Vacant(first_bucket_slot_zero)
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
        table.search_exact_for_insert(&identity, identity, fingerprint),
        SearchResult::Vacant(first_bucket_slot_one)
    );
    occupy(
        &mut table,
        first_bucket_slot_one,
        u64::MAX - 3,
        dummy_fingerprint,
    );
    assert_eq!(
        table.search_exact_for_insert(&identity, identity, fingerprint),
        SearchResult::Vacant(second_bucket_slot_one)
    );

    occupy(&mut table, second_bucket_slot_one, identity, fingerprint);
    let direct = core::ptr::from_ref(table.find_entry_ref(&identity, identity).unwrap());
    assert_eq!(
        direct,
        table
            .storage
            .checked_slot_ptr(second_bucket_slot_one)
            .cast_const()
    );
}

#[test]
fn membership_filter_records_every_inserted_key() {
    let mut table = raw_table(512, 3);
    for key in 0..200_u64 {
        table.insert_for_vacant_entry(key, key, key);
    }
    for key in 0..200_u64 {
        assert!(
            table.membership_maybe_contains(key),
            "inserted key {key} must pass its own filter"
        );
        assert_eq!(
            table.find_location(&key, key),
            Some(
                table
                    .find_by_full_scan(&key, table.prf.prepare(key).fingerprint())
                    .unwrap()
            ),
            "filter must not hide key {key}"
        );
    }
    // Identity hashing here, so absent keys must carry their own spread the
    // way a real hasher's output would.
    let absent = (1..=500_u64).map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    let rejected = absent
        .filter(|&key| !table.membership_maybe_contains(key))
        .count();
    assert!(
        rejected > 400,
        "filter rejected only {rejected} of 500 absent keys"
    );
}

#[test]
fn membership_filter_keeps_survivors_after_removals() {
    let mut table = raw_table(512, 3);
    for key in 0..200_u64 {
        table.insert_for_vacant_entry(key, key, key);
    }
    for key in (0..200_u64).step_by(2) {
        let slot = table
            .find_location(&key, key)
            .expect("inserted key is present");
        <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::remove(&mut table, slot);
    }
    for key in (1..200_u64).step_by(2) {
        assert!(
            table.find_location(&key, key).is_some(),
            "removals must not clear the filter bits of surviving key {key}"
        );
    }
}

#[test]
fn membership_filter_survives_growth_and_clone() {
    let mut table = raw_table(512, 3);
    let start_slots = table.shape.n;
    let mut key = 0_u64;
    while table.shape.n == start_slots {
        table.insert_for_vacant_entry(key, key, key);
        key += 1;
    }
    assert!(table.shape.n > start_slots, "growth must have happened");
    let cloned = <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::clone_table(&table);
    for probe in 0..key {
        assert!(
            table.membership_maybe_contains(probe),
            "growth must rebuild the filter for key {probe}"
        );
        assert!(
            cloned.find_location(&probe, probe).is_some(),
            "clone must carry the filter for key {probe}"
        );
    }
}

#[test]
fn membership_filter_is_reset_by_clear_and_wipe() {
    for wipe in [false, true] {
        let mut table = raw_table(512, 3);
        for key in 0..200_u64 {
            table.insert_for_vacant_entry(key, key, key);
        }
        if wipe {
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::wipe_all(&mut table);
        } else {
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::clear(&mut table);
        }
        let recorded = (0..200_u64)
            .filter(|&key| table.membership_maybe_contains(key))
            .count();
        assert_eq!(recorded, 0, "reset must clear every filter word");
    }
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

/// Every live entry's level bit is set in its bin and the masked lookup finds
/// it; returns the level bits the live entries cover.
fn assert_level_masks_cover_live(table: &FunnelTable<u64, u64, IdentityBuildHasher>) -> u16 {
    let mut covered = 0;
    let mut scan = OccupiedIndices::new();
    while let Some(slot) = scan.step(&table.storage) {
        // SAFETY: `step` yields occupied in-bounds slots.
        let key = unsafe { table.storage.get_ref(slot) }.key;
        let hash = table.hash_builder.hash_one(key);
        let level_bit = table.level_bit(slot);
        assert_ne!(
            table.membership_gate(hash).levels() & level_bit,
            0,
            "slot {slot} lost its level bit"
        );
        assert_eq!(
            table.find_location(&key, hash),
            Some(slot),
            "masked lookup missed slot {slot}"
        );
        covered |= level_bit;
    }
    covered
}

#[test]
#[cfg_attr(miri, ignore)]
fn level_masks_never_lose_a_live_key() {
    use crate::map::TableBackend;

    let spread = |i: u64| i.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    let mut table = raw_table(65_536, 6);
    let live = table.shape.max_insertions as u64;
    for i in 0..live {
        let key = spread(i);
        assert_eq!(table.insert(key, i, key), None);
    }
    assert_eq!(
        assert_level_masks_cover_live(&table),
        u16::MAX,
        "a full table must cover every level bit, overflow included"
    );
    // Absent keys whose gate passes still miss: an EMPTY that ends a masked
    // walk early never turns into a false hit.
    for i in live..live + 4_096 {
        let key = spread(i);
        assert_eq!(table.find_location(&key, key), None);
    }

    for i in (0..live).step_by(3) {
        let key = spread(i);
        let slot = table.find_location(&key, key).unwrap();
        table.remove(slot);
    }
    assert_level_masks_cover_live(&table);
    table.refresh_membership();
    assert_level_masks_cover_live(&table);
    table.resize_with_transition(table.shape.n, EpochTransition::PlacementRecovery);
    assert_level_masks_cover_live(&table);
    assert_level_masks_cover_live(&table.clone_table());
    table.resize_with_transition(2 * table.shape.n, EpochTransition::ExplicitResize);
    assert_level_masks_cover_live(&table);
    for i in (0..live).filter(|i| i % 3 != 0) {
        let key = spread(i);
        let slot = table.find_location(&key, key).unwrap();
        // SAFETY: `find_location` returns occupied in-bounds slots.
        assert_eq!(unsafe { table.storage.get_ref(slot) }.value, i);
    }
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
        .map(|level| level.buckets * (table.shape.stride - table.shape.beta))
        .sum::<usize>();
    assert_eq!(table.storage.capacity(), table.shape.n + padding);
    assert_eq!(table.shape.slots, table.shape.n + padding);
}

#[test]
fn tombstones_never_hide_survivors_and_are_reused() {
    let mut table = raw_table(512, 3);
    for key in 0..200_u64 {
        table.insert_for_vacant_entry(key, key, key);
    }
    let removed = table.find_location(&7, 7).unwrap();
    let (key, value) =
        <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::remove(&mut table, removed);
    assert_eq!((key, value), (7, 7));
    for key in 0..200_u64 {
        if key != 7 {
            assert!(table.find_location(&key, key).is_some(), "lost key {key}");
        }
    }
    let tombstones = table.tombstones();
    let replacement = table.insert_for_vacant_entry(10_000, 1, 7);
    assert_eq!(replacement, removed);
    assert_eq!(table.tombstones(), tombstones - 1);
    assert_eq!(table.entries(), 200);
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
    assert_eq!(table.entries(), 1);
    assert_eq!(table.tombstones(), 1);
    assert_eq!(table.find_location(&200, 42), Some(second));

    let reused = table.insert_for_vacant_entry(300, 3, 42);
    assert_eq!(reused, first);
    assert_eq!(table.tombstones(), 0);
}

#[test]
fn clear_tombstones_each_slot_before_dropping_its_value() {
    let drops = Arc::new(AtomicUsize::new(0));
    let reserve = ReserveFraction::from_exponent(3).unwrap();
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
        table.insert_for_vacant_entry(key, PanicOnFirstDrop(drops.clone()), key);
    }
    let first_occupied = (0..table.shape.slots)
        .find(|&slot| control::is_occupied(table.storage.checked_control(slot)))
        .unwrap();

    let result = catch_unwind(AssertUnwindSafe(|| {
        <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::clear(&mut table);
    }));
    assert!(result.is_err());
    assert_eq!(
        table.storage.checked_control(first_occupied),
        CTRL_TOMBSTONE
    );
    assert_eq!(
        table.entries(),
        (0..table.shape.slots)
            .filter(|&slot| control::is_occupied(table.storage.checked_control(slot)))
            .count()
    );

    <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::clear(&mut table);
    assert_eq!(table.entries(), 0);
    assert_eq!(drops.load(Ordering::SeqCst), 3);
    // SAFETY: `table` is dropped once and not used afterward.
    unsafe { ManuallyDrop::drop(&mut table) };
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
    for id in 0..3 {
        let key = PanicHashKey {
            id,
            armed: armed.clone(),
            drops: drops.clone(),
        };
        let hash = id;
        assert_eq!(
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::insert(&mut table, key, id, hash,),
            None
        );
    }
    let next_shape = FunnelShape::for_insert_budget(256, reserve).unwrap();

    armed.store(true, Ordering::SeqCst);
    let result = catch_unwind(AssertUnwindSafe(|| {
        map::TableBackend::try_resize(&mut table, next_shape.n).unwrap();
    }));
    assert!(result.is_err());
    assert_eq!(table.shape.n, 144);
    assert_eq!(table.entries(), 3);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_head_addresses_storage(&table);
    assert_eq!(
        table.entries(),
        (0..table.shape.slots)
            .filter(|&slot| control::is_occupied(table.storage.checked_control(slot)))
            .count()
    );

    armed.store(false, Ordering::SeqCst);
    for id in 0..3 {
        let probe = PanicHashKey {
            id,
            armed: armed.clone(),
            drops: Arc::new(AtomicUsize::new(0)),
        };
        assert_eq!(
            <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::find_entry(&table, &probe, id)
                .map(|entry| entry.value),
            Some(id)
        );
    }
    let replacement = PanicHashKey {
        id: 99,
        armed: armed.clone(),
        drops: drops.clone(),
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
        table.entries(),
        (0..table.shape.slots)
            .filter(|&slot| control::is_occupied(table.storage.checked_control(slot)))
            .count()
    );
    drop(table);
    assert_eq!(drops.load(Ordering::SeqCst), 4);
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
        let slot = table.find_location(&key_of(id), id).unwrap();
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
    assert_eq!(table.tombstones() as u64, REMOVED);
    assert_eq!(table.stale_membership() as u64, REMOVED);
    assert_eq!(map::TableBackend::epoch_snapshot(&table), before);
    assert_eq!(
        table.head_left,
        table.head_limit().saturating_sub(table.entries())
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
    assert_eq!(table.tombstones(), 0);
    for id in 0..INSERTED {
        assert_eq!(
            map::TableBackend::find_entry(&table, &key_of(id), id).map(|entry| entry.value),
            Some(id)
        );
    }
}

/// A filter refresh hashes every live key. A hasher that panics part way
/// through must leave the filter recording every live key.
#[test]
fn panicking_hasher_during_filter_refresh_keeps_every_key_recorded() {
    const LIVE: u64 = 12;
    const CHURN: u64 = LIVE;
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
    for id in 0..LIVE {
        assert_eq!(
            map::TableBackend::insert(&mut table, key_of(id), id, id),
            None
        );
    }

    // Cycling one key re-takes its tombstone, so only the stale-filter count
    // grows and the delete that passes its threshold refreshes the filter.
    let threshold = membership::refresh_deletes(table.shape.max_insertions);
    for cycle in 0..=threshold {
        assert_eq!(
            map::TableBackend::insert(&mut table, key_of(CHURN), CHURN, CHURN),
            None
        );
        let slot = table.find_location(&key_of(CHURN), CHURN).unwrap();
        if cycle < threshold {
            map::TableBackend::remove(&mut table, slot);
            assert_eq!(table.stale_membership(), cycle + 1);
            continue;
        }
        armed.store(true, Ordering::SeqCst);
        let result = catch_unwind(AssertUnwindSafe(|| {
            map::TableBackend::remove(&mut table, slot);
        }));
        armed.store(false, Ordering::SeqCst);
        assert!(result.is_err(), "the refresh hashed no key");
    }

    assert_eq!(table.entries() as u64, LIVE);
    for id in 0..LIVE {
        assert!(table.membership_gate(id).passes(), "key {id} unrecorded");
        assert_eq!(
            map::TableBackend::find_entry(&table, &key_of(id), id).map(|entry| entry.value),
            Some(id)
        );
    }
    assert_eq!(
        map::TableBackend::find_entry(&table, &key_of(CHURN), CHURN).map(|entry| entry.value),
        None
    );

    // The refresh is still owed, and runs at the next settling delete.
    assert_eq!(
        map::TableBackend::insert(&mut table, key_of(CHURN), CHURN, CHURN),
        None
    );
    let slot = table.find_location(&key_of(CHURN), CHURN).unwrap();
    map::TableBackend::remove(&mut table, slot);
    assert_eq!(table.stale_membership(), 0);
    for id in 0..LIVE {
        assert_eq!(
            map::TableBackend::find_entry(&table, &key_of(id), id).map(|entry| entry.value),
            Some(id)
        );
    }
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
        .map(|key| (key, table.find_location(&key, key).unwrap()))
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
        assert_eq!(table.find_location(&key, key), Some(location));
    }

    fail.store(false, Ordering::SeqCst);
    drop(table);
    assert_eq!(allocations.load(Ordering::SeqCst), 1);
    assert_eq!(deallocations.load(Ordering::SeqCst), 1);
}

#[test]
#[cfg_attr(miri, ignore)]
fn vector_bucket_scan_matches_scalar_order_for_every_default_pattern() {
    const FP: u8 = 7;
    const OTHER: u8 = 1;
    const WIDTH: usize = 6;
    const PATTERN_COUNT: usize = 4_usize.pow(6);
    let states = [CTRL_EMPTY, CTRL_TOMBSTONE, OTHER, FP];

    for encoded in 0..PATTERN_COUNT {
        let mut controls = [FP; WIDTH + crate::raw::config::GROUP_SIZE - 1];
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
                    expected = BucketScanResult::Empty(expected_first_tombstone.unwrap_or(lane));
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
            // SAFETY: `controls` pads `GROUP_SIZE - 1` bytes past `WIDTH`; the
            // closure touches no slot data.
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

            // The tombstone-blind scan compares the same lanes and finds the
            // same hit; otherwise it reports the first EMPTY, which is the
            // general scan's vacancy only when no tombstone precedes it.
            let expected_clean = match expected {
                BucketScanResult::Empty(_) => BucketScanResult::Empty(
                    controls[..WIDTH]
                        .iter()
                        .position(|&control| control == CTRL_EMPTY)
                        .unwrap(),
                ),
                other => other,
            };
            let mut clean_compared = Vec::new();
            // SAFETY: as above.
            let clean = unsafe {
                scan_clean_funnel_bucket(controls.as_ptr(), 0, WIDTH, FP, |slot| {
                    clean_compared.push(slot);
                    (Some(slot) == expected_hit).then_some(slot)
                })
            };
            assert_eq!(
                clean, expected_clean,
                "clean pattern={encoded} hit={hit_lane}"
            );
            assert_eq!(
                clean_compared, expected_compared,
                "clean pattern={encoded} hit={hit_lane}"
            );
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
            // SAFETY: `controls` spans `start + width + GROUP_SIZE - 1` bytes;
            // the closure touches no slot data.
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
            // SAFETY: `controls` spans `start + width + GROUP_SIZE - 1` bytes;
            // the closure touches no slot data.
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
    for exponent in 3..=7 {
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
                let slot = table.find_location(&key, key).unwrap();
                map::TableBackend::remove(&mut table, slot);
            }
            let wide = table.shape.beta > GROUP_SIZE;
            let (mut answered, mut handed_off) = (0_usize, 0_usize);
            for index in 0..2 * inserted {
                let key = key_of(index);
                let gate = table.membership_gate(key);
                if !gate.passes() {
                    continue;
                }
                let walk = table.find_location_by_walk(&key, key, gate.levels());
                let live = index < inserted && index % 3 != 0;
                assert_eq!(walk.is_some(), live, "n {n} d {d} index {index}");
                // The whole lookup, through whichever path settles it.
                assert_eq!(
                    table.find_location(&key, key),
                    walk,
                    "n {n} d {d} index {index}"
                );
                let probe = table.prf.prepare(key);
                let scan = table
                    .first_match(&key, probe, gate.levels().into())
                    .map(|found| table.slot_of(found.lane));
                let found = scan.ok();
                // An empty bin and the overflow bit each scan an absent head
                // entry, which finds nothing.
                for absent in [0, OVERFLOW_LEVEL_BIT] {
                    let at_absent = table
                        .first_match(&key, probe, absent.into())
                        .map(|found| table.slot_of(found.lane))
                        .ok();
                    assert_eq!(at_absent, None, "n {n} d {d} index {index}");
                }
                if scan.map_or_else(|last| table.unmatched_is_absent(last), |_| true) {
                    assert_eq!(found, walk, "n {n} d {d} index {index}");
                    // A bucket wider than a group is never scanned here.
                    assert!(!wide, "n {n} d {d} index {index}");
                    answered += 1;
                } else {
                    handed_off += 1;
                }
            }
            if wide {
                assert_ne!(handed_off, 0, "n {n} d {d}");
            } else {
                assert_ne!(answered, 0, "n {n} d {d}");
            }
        }
    }
}

/// The walk that searches and places a recorded key at once answers as the
/// lookup and the head placement do apart: a key it reports present is where
/// the lookup finds it, and a vacancy it reports is the head walk's, for a
/// key the lookup does not find. It settles nothing in a table with
/// tombstones, and inserts through it agree with a model map.
#[test]
#[cfg_attr(miri, ignore = "fills tens of thousands of slots")]
fn recorded_key_search_agrees_with_the_lookup_and_the_head_walk() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let feasible = |n: &usize, d: u32| {
        FunnelShape::from_slots(*n, ReserveFraction::from_exponent(d).unwrap()).is_ok()
    };
    // (present, vacant, unsettled) over every recorded key below `keys`.
    let census = |table: &FunnelTable<u64, u64, IdentityBuildHasher>, keys: u64| {
        let (mut present, mut vacant, mut unsettled) = (0_usize, 0_usize, 0_usize);
        // The inserted sequence, then a scrambled one whose keys the filter
        // records by chance.
        let scrambled = |index: u64| {
            let word = index.wrapping_mul(SPREAD);
            (word ^ (word >> 29)).wrapping_mul(0xBF58_476D_1CE4_E5B9)
        };
        let sequence = (0..keys)
            .map(|index| index.wrapping_mul(SPREAD))
            .chain((0..keys).map(scrambled));
        for (index, key) in sequence.enumerate() {
            let gate = table.membership_gate(key);
            if !gate.passes() {
                continue;
            }
            let probe = table.prf.prepare(key);
            let location = table.find_location(&key, key);
            match table.search_head(&key, probe, gate.levels()) {
                HeadSearch::Present(lane) => {
                    assert_eq!(Some(table.slot_of(lane)), location, "index {index}");
                    present += 1;
                }
                HeadSearch::Vacant(vacancy) => {
                    assert_eq!(location, None, "index {index}");
                    let head = table.head_vacancy(probe).unwrap();
                    assert_eq!(vacancy.lane, head.lane, "index {index}");
                    assert_eq!(vacancy.entry, head.entry, "index {index}");
                    assert_eq!(vacancy.level_bit, head.level_bit, "index {index}");
                    vacant += 1;
                }
                HeadSearch::Unsettled => unsettled += 1,
            }
        }
        (present, vacant, unsettled)
    };
    for (at_least, d) in [(600, 3), (6_000, 4), (60_000, 9)] {
        let n = (at_least..2 * at_least).find(|n| feasible(n, d)).unwrap();
        let mut table = raw_table(n, d);
        let wide = !table.shape.has_head();
        let mut model = alloc::collections::BTreeMap::new();
        let limit = table.shape.max_insertions as u64;
        let keys = 2 * limit;
        let (mut present, mut vacant) = (0, 0);
        // Odd indices first, so the even ones are absent keys the filter
        // partly records by the time they are inserted.
        for parity in [1, 0] {
            for index in (1..limit - 1).filter(|index| index % 2 == parity) {
                let key = index.wrapping_mul(SPREAD);
                assert_eq!(
                    map::TableBackend::insert(&mut table, key, index, key),
                    model.insert(key, index),
                    "n {n} d {d} index {index}"
                );
            }
            let (now_present, now_vacant, unsettled) = census(&table, keys);
            present += now_present;
            vacant += now_vacant;
            assert!(!wide || now_present + now_vacant == 0, "n {n} d {d}");
            assert!(wide || unsettled < now_present, "n {n} d {d}");
        }
        assert_eq!(wide, present == 0, "n {n} d {d}");
        assert_eq!(wide, vacant == 0, "n {n} d {d}");
        // Every key again: a present one is replaced, never placed twice.
        for index in 1..limit - 1 {
            let key = index.wrapping_mul(SPREAD);
            assert_eq!(
                map::TableBackend::insert(&mut table, key, !index, key),
                model.insert(key, !index),
                "n {n} d {d} index {index}"
            );
        }
        assert_eq!(table.entries(), model.len());
        for index in 0..keys {
            let key = index.wrapping_mul(SPREAD);
            let found = table.find_entry_ref(&key, key).map(|entry| entry.value);
            assert_eq!(found, model.get(&key).copied(), "n {n} d {d} index {index}");
        }
        // A tombstone takes the head placement away, and the walk with it.
        let key = SPREAD;
        assert!(map::TableBackend::remove_key(&mut table, &key, key).is_some());
        assert_eq!(table.head_left, 0);
        let (present, vacant, _) = census(&table, keys);
        assert_eq!((present, vacant), (0, 0), "n {n} d {d}");
    }
}

/// Removal by key takes each entry a model map holds and nothing else,
/// whichever lookup path finds it: the first-match scan, the ordered walk a
/// wide bucket hands the lookup to, and both again over the tombstones
/// earlier removals left.
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
            let found = table.find_entry_ref(&key, key).map(|entry| entry.value);
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
                map::TableBackend::remove_key(&mut table, &key, key),
                model.remove_entry(&key),
                "n {n} d {d} index {index}"
            );
            // A removed key is gone at once.
            assert_eq!(
                map::TableBackend::remove_key(&mut table, &key, key),
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
                map::TableBackend::remove_key(&mut table, &key, key),
                model.remove_entry(&key),
                "n {n} d {d} index {index}"
            );
        }
        assert!(model.is_empty());
        check(&table, &model, keys);
    }
}

/// Whatever vacancy the head-only placement walk reports, the general walk
/// reports the same; a bucket wider than one group is always handed to that
/// walk. Fills each table to its insertion limit through the insert that
/// takes the head walk, then checks the filter covers every key.
#[test]
#[cfg_attr(miri, ignore = "fills tens of thousands of slots")]
fn head_vacancy_agrees_with_the_placement_walk_whenever_it_answers() {
    const SPREAD: u64 = 0x9E37_79B9_7F4A_7C15;
    let feasible = |n: &usize, d: u32| {
        FunnelShape::from_slots(*n, ReserveFraction::from_exponent(d).unwrap()).is_ok()
    };
    for (at_least, d) in [(600, 3), (6_000, 4), (60_000, 9)] {
        let n = (at_least..2 * at_least).find(|n| feasible(n, d)).unwrap();
        let mut table = raw_table(n, d);
        let wide = table.shape.beta > GROUP_SIZE;
        let inserted = table.shape.max_insertions as u64;
        let mut answered = 0_usize;
        for index in 0..inserted {
            let key = index.wrapping_mul(SPREAD);
            let probe = table.prf.prepare(key);
            let general = table.search_vacancy(probe);
            if let Some(head) = table.first_empty_in_head(probe) {
                let head = Vacancy {
                    slot: table.slot_of(NonNull::new(head.lane).unwrap()),
                    level_bit: head.level_bit,
                };
                assert_eq!(Some(head), general, "n {n} d {d} index {index}");
                answered += 1;
            }
            assert_eq!(map::TableBackend::insert(&mut table, key, index, key), None);
        }
        assert_eq!(answered == 0, wide, "n {n} d {d}");
        assert_level_masks_cover_live(&table);
        for index in 0..inserted {
            let key = index.wrapping_mul(SPREAD);
            let slot = table.find_location(&key, key);
            assert!(slot.is_some(), "n {n} d {d} index {index}");
        }
    }
}
