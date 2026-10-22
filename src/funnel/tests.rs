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
                assert_eq!(map.table().tombstones, 1);
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
                // Rebuild places each old key; the new key needs its own fresh walk.
                assert!(comparisons.load(Ordering::Relaxed) > 0, "{label}");
                assert_eq!(walks, capacity + 1, "{label}");
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
    let fingerprint = control::control_fingerprint(key);
    let exact = table.search_exact_for_insert(&key, key, fingerprint);
    let slot = table.shape.n - 1;
    assert_ne!(exact, SearchResult::Vacant(slot));
    table.place_new_entry(slot, key, 7, table.membership_slot(key), fingerprint, true);
    assert_eq!(table.find_for_entry(&key, key).ok(), Some(slot));

    // A different key with the same hash must complete the exceptional
    // scan before its exact-search vacancy is safe to reuse.
    let vacant = table.find_for_entry(&99, key).err().unwrap();
    VACANCY_WALKS.with(|walks| walks.set(0));
    let inserted = table.insert_for_vacant(99, 8, vacant);
    assert_eq!(VACANCY_WALKS.with(Cell::get), 0);
    assert_eq!(exact, SearchResult::Vacant(inserted));
    assert_eq!(table.find_location(&99, key, fingerprint), Some(inserted));
    assert_eq!(table.find_location(&key, key, fingerprint), Some(slot));
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
fn vacant_entry_reuses_exhausted_search_before_exceptional_placement() {
    use crate::map::TableBackend;

    let mut table = raw_table(512, 3);
    let hash = 42;
    let fingerprint = control::control_fingerprint(hash);
    let absent = u64::MAX;
    while let SearchResult::Vacant(_) = table.search_exact_for_insert(&absent, hash, fingerprint) {
        let key = table.len as u64;
        table.insert_for_vacant_entry(key, key, hash);
        assert!(table.len < table.shape.max_insertions);
    }
    assert_eq!(
        table.search_exact_for_insert(&absent, hash, fingerprint),
        SearchResult::Full
    );
    let vacant = table.find_for_entry(&absent, hash).err().unwrap();
    let old_len = table.len;
    VACANCY_WALKS.with(|walks| walks.set(0));
    let inserted = table.insert_for_vacant(absent, 99, vacant);
    assert_eq!(
        VACANCY_WALKS.with(Cell::get),
        0,
        "an exhausted exact search needs no second walk"
    );
    assert!(table.exceptional_placement);
    assert_eq!(table.len, old_len + 1);
    assert_eq!(
        table.find_location(&absent, hash, fingerprint),
        Some(inserted)
    );
}

fn raw_table(n: usize, d: u32) -> FunnelTable<u64, u64, IdentityBuildHasher> {
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
            slot,
            key,
            key + 100,
            table.membership_slot(hash),
            control::control_fingerprint(hash),
            true,
        );
    }
    let mut scan = map::TableBackend::scan(&table);
    for slot in slots {
        let (ptr, found) = map::TableBackend::scan_next(&table, &mut scan).unwrap();
        assert_eq!(found, slot);
        let entry = unsafe { ptr.read() };
        assert_eq!((entry.key, entry.value), (slot as u64, slot as u64 + 100));
        map::TableBackend::extract_finish(&mut table, slot);
    }
    assert!(map::TableBackend::scan_next(&table, &mut scan).is_none());
    assert!(map::TableBackend::scan_next(&table, &mut scan).is_none());
    assert_eq!(table.len, 0);
}

#[test]
fn sparse_scan_visits_group_boundaries_and_tail_once_in_slot_order() {
    let mut table = raw_table(32_767, 3);
    let slots = [0, GROUP_SIZE - 1, GROUP_SIZE, 3 * GROUP_SIZE + 2, 32_766];
    for slot in slots {
        let key = slot as u64;
        let hash = table.hash_builder.hash_one(key);
        table.place_new_entry(
            slot,
            key,
            key + 100,
            table.membership_slot(hash),
            control::control_fingerprint(hash),
            true,
        );
    }
    // Include a deleted slot next to a live slot in a cached group.
    table.storage.mark_tombstone(GROUP_SIZE + 1);
    let mut scan = map::TableBackend::scan(&table);
    for slot in slots {
        let (ptr, found) = map::TableBackend::scan_next(&table, &mut scan).unwrap();
        assert_eq!(found, slot);
        assert_eq!(unsafe { (*ptr).value }, slot as u64 + 100);
        // Draining changes control bytes while the cursor holds its mask.
        let entry = unsafe { ptr.read() };
        assert_eq!(entry.key, slot as u64);
        map::TableBackend::extract_finish(&mut table, slot);
    }
    assert!(map::TableBackend::scan_next(&table, &mut scan).is_none());
    assert!(map::TableBackend::scan_next(&table, &mut scan).is_none());
    assert_eq!(table.len, 0);
}

#[test]
fn refresh_membership_rebuilds_the_recorded_filter() {
    let mut table = raw_table(32_767, 3);
    for key in 0..64_u64 {
        assert!(!table.insert_unique(key, key));
    }
    let recorded = unsafe {
        core::slice::from_raw_parts(table.membership_ptr(), table.membership.words).to_vec()
    };
    table.clear_membership();
    table.refresh_membership();
    assert_eq!(
        unsafe { core::slice::from_raw_parts(table.membership_ptr(), table.membership.words) },
        recorded
    );
}

#[test]
#[cfg_attr(miri, ignore)]
fn clean_and_dirty_search_modes_agree_without_tombstones() {
    let mut table = raw_table(344, 4);
    for key in 0..128_u64 {
        assert!(!table.insert_unique(key, key));
    }
    assert_eq!(table.tombstones, 0);

    for key in 0..256_u64 {
        let hash = table.hash_builder.hash_one(key);
        let fingerprint = control::control_fingerprint(hash);
        let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(hash);
        let clean = table.search_exact_mode::<_, true>(&key, probe, fingerprint);
        let dirty = table.search_exact_mode::<_, false>(&key, probe, fingerprint);
        assert_eq!(clean, dirty, "key={key}");
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
        assert!(!table.insert_unique(key, key));
    }
    let check = |table: &FunnelTable<u64, u64, IdentityBuildHasher>, label: &str| {
        let mut vacant = 0_usize;
        for key in live..live + 4_096 {
            let hash = table.hash_builder.hash_one(key);
            let fingerprint = control::control_fingerprint(hash);
            let probe = FunnelPrf::new(FUNNEL_PROBE_SEED).prepare(hash);
            let exact = table.search_exact_for_insert(&key, hash, fingerprint);
            assert_eq!(table.search_vacancy(probe), exact, "{label} key={key}");
            vacant += usize::from(matches!(exact, SearchResult::Vacant(_)));
        }
        assert!(vacant > 0, "{label}: fixture never reached a vacancy");
    };
    check(&table, "clean full table");

    for key in (0..live).step_by(3) {
        let hash = table.hash_builder.hash_one(key);
        let fingerprint = control::control_fingerprint(hash);
        let slot = table.find_location(&key, hash, fingerprint).unwrap();
        map::TableBackend::remove(&mut table, slot);
    }
    assert!(table.tombstones > 0);
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
        |table| table.stale_membership,
    );
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
    assert_eq!(table.len, 64);
    for key in 0..64_u64 {
        let hash = table.hash_builder.hash_one(key);
        let fingerprint = control::control_fingerprint(hash);
        let slot = table.find_location(&key, hash, fingerprint).unwrap();
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
            assert!(bucket < shape.levels[level].bucket_range.upper());
            assert!(slot_in_bucket < shape.beta);
            shape.levels[level].offset + bucket * shape.beta + slot_in_bucket
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
            let actual = table
                .find_location(&identity, identity, control::control_fingerprint(identity))
                .unwrap();
            assert_eq!(actual, expected.global_slot(), "n={n} key={identity}");
            locations.push((identity, actual, table.storage.slot_ptr(actual) as usize));
            assert_eq!(
                table.find_location(&identity, identity, control::control_fingerprint(identity),),
                Some(actual)
            );
        }
        assert_eq!(table.len, scalar.len());
        assert_eq!(scalar.locations().count(), locations.len());
        for (expected, identity) in scalar.locations() {
            let global_slot = locations[usize::try_from(identity).unwrap()].1;
            assert_eq!(expected.global_slot(), global_slot, "n={n} key={identity}");
            assert_eq!(
                decompose_scalar_location(&table.shape, expected),
                global_slot,
                "n={n} key={identity} {expected:?}"
            );
        }
        for &(identity, location, pointer) in &locations {
            assert_eq!(
                table.find_location(&identity, identity, control::control_fingerprint(identity),),
                Some(location),
                "moved n={n} key={identity}"
            );
            assert_eq!(table.storage.slot_ptr(location) as usize, pointer);
        }

        let duplicate = config.max_insertions() as u64 / 2;
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

        let absent = config.max_insertions() as u64 + 1_000_000;
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
        if control::is_free(table.storage.control_at(slot)) {
            table
                .storage
                .write_with_control(slot, SlotEntry { key, value: key }, fingerprint);
            // Placing a slot directly still owes the filter its record.
            let membership = table.membership_slot(key);
            table.record_membership(membership);
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
    let direct = core::ptr::from_ref(
        table
            .find_entry_ref(&identity, identity, fingerprint)
            .unwrap(),
    );
    assert_eq!(
        direct,
        table.storage.slot_ptr(second_bucket_slot_one).cast_const()
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
            table.find_location(&key, key, control::control_fingerprint(key)),
            Some(
                table
                    .find_by_full_scan(&key, control::control_fingerprint(key))
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
            .find_location(&key, key, control::control_fingerprint(key))
            .expect("inserted key is present");
        <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::remove(&mut table, slot);
    }
    for key in (1..200_u64).step_by(2) {
        assert!(
            table
                .find_location(&key, key, control::control_fingerprint(key))
                .is_some(),
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
            cloned
                .find_location(&probe, probe, control::control_fingerprint(probe))
                .is_some(),
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
    let first_occupied = (0..table.shape.n)
        .find(|&slot| control::is_occupied(table.storage.control_at(slot)))
        .unwrap();

    let result = catch_unwind(AssertUnwindSafe(|| {
        <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::clear(&mut table);
    }));
    assert!(result.is_err());
    assert_eq!(table.storage.control_at(first_occupied), CTRL_EMPTY);
    assert_eq!(
        table.len,
        (0..table.shape.n)
            .filter(|&slot| control::is_occupied(table.storage.control_at(slot)))
            .count()
    );

    <FunnelTable<_, _, _, _> as map::TableBackend<_, _>>::clear(&mut table);
    assert_eq!(table.len, 0);
    assert_eq!(drops.load(Ordering::SeqCst), 3);
    unsafe { ManuallyDrop::drop(&mut table) };
}

#[test]
fn failed_fallible_resize_leaves_a_valid_table() {
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
        table.try_resize_exact(next_shape.n).unwrap();
    }));
    assert!(result.is_err());
    assert_eq!(
        table.len,
        (0..table.shape.n)
            .filter(|&slot| control::is_occupied(table.storage.control_at(slot)))
            .count()
    );

    armed.store(false, Ordering::SeqCst);
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
        table.len,
        (0..table.shape.n)
            .filter(|&slot| control::is_occupied(table.storage.control_at(slot)))
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
