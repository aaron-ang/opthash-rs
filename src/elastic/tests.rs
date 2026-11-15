use super::*;

use core::hash::{BuildHasher, Hasher};
use core::mem::ManuallyDrop;
use core::num::{NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::exact::reference::{ScalarElastic, ScalarElasticLimits};
use crate::map::TableBackend;
use crate::test_support::{
    self, CountDrop, Deterministic, FixedElasticHashMap, FixedHashBuilder, IdentityBuildHasher,
    PanicHashKey, PanicOnFirstDrop, ToggleAllocator, fixed_hasher,
};
use alloc::sync::Arc;
use std::panic::{AssertUnwindSafe, catch_unwind};

#[derive(Clone, Copy)]
struct ConstHashBuilder;

struct ConstHasher;

impl Hasher for ConstHasher {
    fn finish(&self) -> u64 {
        0
    }

    fn write(&mut self, _: &[u8]) {}
}

impl BuildHasher for ConstHashBuilder {
    type Hasher = ConstHasher;

    fn build_hasher(&self) -> Self::Hasher {
        ConstHasher
    }
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct Zst;

#[repr(align(256))]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct OverAligned(u64);

fn assert_exact_trace(n: usize, reserve_exponent: u32, identities: impl IntoIterator<Item = u64>) {
    let reserve = ReserveFraction::from_exponent(reserve_exponent).unwrap();
    let config = PaperConfig::new(n, reserve_exponent).unwrap();
    let plan = config.elastic_plan();
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            n,
            reserve,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
    assert_eq!(
        table
            .levels
            .iter()
            .map(ArenaSlots::capacity)
            .collect::<Vec<_>>(),
        plan.level_lengths().collect::<Vec<_>>()
    );
    assert_eq!(
        table.scheduler.batch_ends.as_ref(),
        plan.batch_quotas()
            .scan(0_usize, |total, quota| {
                *total += quota;
                Some(*total)
            })
            .collect::<Vec<_>>()
    );

    let limits = ScalarElasticLimits::new(
        NonZeroUsize::new(ELASTIC_PROBE_BUDGET_C).unwrap(),
        NonZeroU32::new(probe::RANGE_WORD_CAP).unwrap(),
        NonZeroU64::new(UNIFORM_SEARCH_CAP).unwrap(),
        NonZeroU128::new(QUERY_POSITION_CAP).unwrap(),
    );
    let mut scalar = ScalarElastic::new(config, CounterPrf::new(ELASTIC_PROBE_SEED), limits);

    for identity in identities {
        let prepared = PreparedElasticKey::new(identity);
        assert_eq!(table.hash_builder.hash_one(identity), identity);
        assert!(table.len < table.max_insertions);
        let target = table.scheduler.target(table.len);
        let placement = table
            .choose_slot_for_new_key(prepared.route.probe, target)
            .unwrap();
        let expected = scalar.insert(identity);
        let global_slot = table.levels[..placement.level]
            .iter()
            .map(ArenaSlots::capacity)
            .sum::<usize>()
            + placement.slot;

        // The oracle's case label is not carried by the table; its
        // observable outcome (level, slot, and paper position) is.
        assert_eq!(placement.level, expected.location.level);
        assert_eq!(placement.slot, expected.location.slot_in_level);
        assert_eq!(global_slot, expected.location.global_slot);
        assert_eq!(placement.phi(), expected.phi);
        assert_eq!(
            placement.phi(),
            probe::elastic_phi(
                expected.location.level as u128 + 1,
                u128::from(expected.paper_probe)
            )
            .unwrap()
        );

        assert_eq!(
            table.place_new_entry(
                identity,
                identity,
                prepared,
                control::control_fingerprint(identity),
                placement,
            ),
            (placement.level, placement.slot)
        );
        assert_eq!(
            table
                .levels
                .iter()
                .map(|level| level.len as usize)
                .collect::<Vec<_>>(),
            scalar.level_occupancy()
        );
        assert_eq!(
            table.find_slot_indices_prepared(
                &identity,
                prepared,
                control::control_fingerprint(identity),
            ),
            Some((placement.level, placement.slot))
        );
        let query = scalar.query(identity);
        assert_eq!(query.global_slot, global_slot);
        assert!(
            query.found_position <= placement.phi(),
            "lookup order visits phi={} no later than placement phi={}",
            query.found_position,
            placement.phi()
        );
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn elastic_placement_matches_the_scalar_paper_model() {
    assert_exact_trace(8, 3, [0, 1, 2, 1523, 2540, 2541, 2542]);
    for &(n, reserve_exponent) in &[(31, 4), (65, 6), (257, 8)] {
        let target = PaperConfig::new(n, reserve_exponent)
            .unwrap()
            .max_insertions();
        assert_exact_trace(
            n,
            reserve_exponent,
            (0..target).map(|identity| identity as u64),
        );
    }
}

#[test]
fn compact_query_counters_cover_every_supported_geometry() {
    assert_eq!(
        PaperConfig::new(
            usize::try_from(MAX_ELASTIC_SLOTS).unwrap_or(usize::MAX),
            ReserveFraction::DEFAULT.exponent()
        )
        .unwrap()
        .elastic_plan()
        .level_count(),
        u32::BITS as usize
    );
    #[cfg(target_pointer_width = "64")]
    {
        let max_slots = usize::try_from(MAX_ELASTIC_SLOTS).unwrap();
        assert!(ElasticGeometry::for_insert_budget(max_slots, ReserveFraction::DEFAULT).is_none());
        let result = ElasticTable::<u64, u64, IdentityBuildHasher>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                max_slots + 1,
                ReserveFraction::DEFAULT,
                IdentityBuildHasher,
                Global,
            );
        assert!(matches!(result, Err(TryReserveError::CapacityOverflow)));
    }
    assert!(probe::elastic_phi(1, 383).unwrap() <= QUERY_POSITION_CAP);
    assert!(probe::elastic_phi(1, 384).unwrap() > QUERY_POSITION_CAP);
    for level in 0..u32::BITS as usize {
        for_each_phi_route(level, 1, QUERY_POSITION_CAP, |paper_probe, _| {
            assert!(usize::try_from(paper_probe - 1).unwrap() < QUERY_PROBE_LIMIT);
        });
    }

    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            31,
            ReserveFraction::from_exponent(4).unwrap(),
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
    table.schedule_levels_through(table.levels.len() - 1);
    table.extend_probe_schedule(QUERY_POSITION_CAP);
    assert!(
        table
            .probe_schedule
            .routes()
            .iter()
            .all(|route| route.counter_base() != H11_COUNTER_BASE)
    );
}

/// Walks `level`'s probes in paper order from `from_probe`, visiting each
/// `(paper_probe, phi)` with `phi <= position_cap` inside the uniform search
/// cap. Level 0's first probe is skipped: it is the schedule's direct route, so
/// no route is ever pushed for it.
fn for_each_phi_route(
    level: usize,
    from_probe: u128,
    position_cap: u128,
    mut visit: impl FnMut(u128, u128),
) {
    let paper_level = level as u128 + 1;
    let mut paper_probe = if level == 0 && from_probe == 1 {
        2
    } else {
        from_probe
    };
    while paper_probe <= u128::from(UNIFORM_SEARCH_CAP) {
        let phi =
            probe::elastic_phi(paper_level, paper_probe).expect("bounded Elastic query coordinate");
        if phi > position_cap {
            break;
        }
        visit(paper_probe, phi);
        paper_probe += 1;
    }
}

/// `(level, logical probe)` of every route a schedule over the first
/// `levels` levels holds at `high_water`, in position order.
fn routes_in_position_order(levels: usize, high_water: u128) -> Vec<(usize, u128)> {
    let mut expected = Vec::new();
    for level in 0..levels {
        for_each_phi_route(level, 1, high_water, |paper_probe, phi| {
            expected.push((phi, level, paper_probe - 1));
        });
    }
    expected.sort_unstable();
    expected
        .into_iter()
        .map(|(_, level, logical)| (level, logical))
        .collect()
}

#[test]
fn query_schedule_stays_in_position_order_through_every_extension() {
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            4_096,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
    let scheduled = |table: &ElasticTable<u64, u64, IdentityBuildHasher>| {
        table
            .probe_schedule
            .routes()
            .iter()
            .map(|route| {
                let (level, logical) = route.coordinates();
                (level as usize, u128::from(logical))
            })
            .collect::<Vec<_>>()
    };
    let level_count = table.levels.len();
    assert!(level_count >= 4);
    let mut high_water = 0_u128;
    let mut extensions_onto_routes = 0;
    let mut extensions_in_place = 0;
    while high_water < QUERY_POSITION_CAP {
        // While a level is left, each step first brings in the next one,
        // which rebuilds the schedule up to the high water reached so far.
        // The steps after that extend it in place.
        if (table.scheduled_levels as usize) < level_count {
            table.schedule_levels_through(table.scheduled_levels as usize);
            assert_eq!(
                scheduled(&table),
                routes_in_position_order(table.scheduled_levels as usize, high_water)
            );
        } else {
            extensions_in_place += 1;
        }
        extensions_onto_routes += usize::from(!table.probe_schedule.routes().is_empty());
        high_water = (high_water * 2 + 3).min(QUERY_POSITION_CAP);
        table.extend_probe_schedule(high_water);
        assert_eq!(
            scheduled(&table),
            routes_in_position_order(table.scheduled_levels as usize, high_water)
        );
        assert!(table.probe_schedule.addresses(&table.levels));
    }
    assert_eq!(table.scheduled_levels as usize, level_count);
    assert!(extensions_onto_routes > 3 && extensions_in_place > 3);
}

#[test]
fn query_schedule_never_reallocates_within_an_epoch() {
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            8_192,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
    let initial_ptr = table.probe_schedule.direct();
    let initial_capacity = table.probe_schedule.route_capacity();

    table.schedule_levels_through(table.levels.len() - 1);
    table.extend_probe_schedule(QUERY_POSITION_CAP);

    assert_eq!(table.probe_schedule.direct(), initial_ptr);
    assert_eq!(table.probe_schedule.route_capacity(), initial_capacity);
    assert_eq!(table.probe_schedule.routes().len(), initial_capacity);
    assert!(table.probe_schedule.ends_with_sentinel());
}

#[test]
fn query_schedule_holds_every_route_once_in_position_order() {
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            8_193,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();

    table.schedule_levels_through(table.levels.len() - 1);
    table.extend_probe_schedule(QUERY_POSITION_CAP);

    let mut expected = Vec::new();
    for level in 0..table.levels.len() {
        for_each_phi_route(level, 1, QUERY_POSITION_CAP, |paper_probe, phi| {
            expected.push((phi, level, paper_probe - 1));
        });
    }
    expected.sort_unstable();
    let scheduled = table
        .probe_schedule
        .routes()
        .iter()
        .map(|route| {
            let (level, logical) = route.coordinates();
            assert_eq!(level, u32::from(route.level()));
            let region = &table.levels[level as usize];
            assert_eq!(
                route.control() == region.ctrl_ptr.cast_const(),
                region.index_shift() != GENERAL_REDUCTION
            );
            (level as usize, u128::from(logical))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        scheduled,
        expected
            .iter()
            .map(|&(_, level, logical)| (level, logical))
            .collect::<Vec<_>>()
    );
}

#[test]
fn elastic_geometry_carries_capacity_and_batch_state() {
    for &requested in &[0usize, 1, 127, 1_000, 10_000] {
        let reserve_fraction = ReserveFraction::DEFAULT;
        let geometry = ElasticGeometry::for_insert_budget(requested, reserve_fraction).unwrap();
        assert!(
            geometry.max_insertions >= requested,
            "requested={requested} max_insertions={}",
            geometry.max_insertions
        );
        assert_eq!(
            geometry.level_capacities.iter().sum::<usize>(),
            geometry.total_slots
        );
        assert_eq!(
            geometry.batch_plan.iter().sum::<usize>(),
            geometry.max_insertions
        );
        if geometry.total_slots >= 2 {
            let config =
                PaperConfig::new(geometry.total_slots, reserve_fraction.exponent()).unwrap();
            let plan = config.elastic_plan();
            assert_eq!(
                *geometry.level_capacities,
                plan.level_lengths().collect::<Vec<_>>()
            );
            assert_eq!(
                *geometry.batch_plan,
                plan.batch_quotas().collect::<Vec<_>>()
            );
        }
    }
}

/// Panics in the drop that finds `drops` at `panic_at`.
struct PanicOnNthDrop {
    drops: Arc<AtomicUsize>,
    panic_at: usize,
}

impl Drop for PanicOnNthDrop {
    fn drop(&mut self) {
        assert_ne!(
            self.drops.fetch_add(1, Ordering::Relaxed),
            self.panic_at,
            "intentional drop panic"
        );
    }
}

#[test]
fn lookups_find_every_live_entry_after_a_clear_that_panicked() {
    const KEYS: usize = 900;
    for panic_at in [0, 1, KEYS / 2, KEYS - 2, KEYS - 1] {
        let drops = Arc::new(AtomicUsize::new(0));
        let value = || PanicOnNthDrop {
            drops: drops.clone(),
            panic_at,
        };
        let mut map = ManuallyDrop::new(FixedElasticHashMap::<u64, PanicOnNthDrop>::with_capacity(
            KEYS,
        ));
        for key in 0..KEYS as u64 {
            map.insert(key, value());
        }

        let result = catch_unwind(AssertUnwindSafe(|| map.clear()));
        assert!(result.is_err());
        // The drain stopped at the panicking drop, which left the map too.
        assert_eq!(map.len(), KEYS - panic_at - 1);
        let found = (0..KEYS as u64)
            .filter(|key| map.get(key).is_some())
            .count();
        assert_eq!(found, map.len());

        // The interrupted drain reads as a run of removals: nothing is
        // flagged exceptional, and later inserts place without a recovery.
        assert_eq!(map.table().probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG, 0);
        let recoveries = map.epoch().placement_recoveries;
        let live = map.len();
        for key in KEYS as u64..2 * KEYS as u64 {
            map.insert(key, value());
        }
        assert_eq!(map.epoch().placement_recoveries, recoveries);
        assert_eq!(map.len(), live + KEYS);
        let found = (0..2 * KEYS as u64)
            .filter(|key| map.get(key).is_some())
            .count();
        assert_eq!(found, map.len());

        map.clear();
        assert!(map.is_empty());
        // SAFETY: `map` is not used after this drop.
        unsafe { ManuallyDrop::drop(&mut map) };
    }
}

#[test]
fn clear_tombstones_each_slot_before_dropping_its_value() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut map = ManuallyDrop::new(FixedElasticHashMap::<u64, PanicOnFirstDrop>::with_capacity(
        32,
    ));
    for key in 0..3 {
        map.insert(key, PanicOnFirstDrop(drops.clone()));
    }
    let first_occupied = map
        .table()
        .levels
        .iter()
        .enumerate()
        .find_map(|(level_index, level)| {
            (0..level.capacity())
                .find(|&slot| control::is_occupied(level.checked_control(slot)))
                .map(|slot| (level_index, slot))
        })
        .unwrap();

    let result = catch_unwind(AssertUnwindSafe(|| map.clear()));
    assert!(result.is_err());
    assert_eq!(
        map.table().levels[first_occupied.0].checked_control(first_occupied.1),
        CTRL_TOMBSTONE
    );
    assert_eq!(map.table().levels[first_occupied.0].tombstones, 1);
    let live_controls = map
        .table()
        .levels
        .iter()
        .map(|level| {
            (0..level.capacity())
                .filter(|&slot| control::is_occupied(level.checked_control(slot)))
                .count()
        })
        .sum::<usize>();
    assert_eq!(map.len(), live_controls);
    assert!(map.table().levels.iter().all(|level| {
        level.len as usize
            == (0..level.capacity())
                .filter(|&slot| control::is_occupied(level.checked_control(slot)))
                .count()
    }));

    map.clear();
    assert!(map.is_empty());
    assert_eq!(drops.load(Ordering::SeqCst), 3);
    // SAFETY: `map` is not used after this drop.
    unsafe { ManuallyDrop::drop(&mut map) };
}

#[test]
fn caught_hash_panic_during_try_resize_keeps_every_entry() {
    let panic = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let key_drops = Arc::new(AtomicUsize::new(0));
    let key = |id: u64| PanicHashKey {
        id,
        armed: panic.clone(),
        drops: key_drops.clone(),
    };
    let mut map = FixedElasticHashMap::<PanicHashKey, CountDrop>::with_capacity(32);
    for id in 0..16_u64 {
        map.insert(key(id), CountDrop(drops.clone()));
    }

    panic.store(true, Ordering::SeqCst);
    let result = catch_unwind(AssertUnwindSafe(|| map.try_reserve(4_096)));
    assert!(result.is_err());
    panic.store(false, Ordering::SeqCst);

    let live_controls = map
        .table()
        .levels
        .iter()
        .map(|level| {
            (0..level.capacity())
                .filter(|&slot| control::is_occupied(level.checked_control(slot)))
                .count()
        })
        .sum::<usize>();
    assert_eq!(map.len(), live_controls);
    assert!(map.table().levels.iter().all(|level| {
        level.len as usize
            == (0..level.capacity())
                .filter(|&slot| control::is_occupied(level.checked_control(slot)))
                .count()
    }));
    // The old table stays intact until every entry has been rehashed.
    assert_eq!(map.len(), 16);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(key_drops.load(Ordering::SeqCst), 0);

    let live_keys = map.keys().map(|key| key.id).collect::<Vec<_>>();
    map.insert(key(100), CountDrop(drops.clone()));
    map.try_reserve(4_096).unwrap();
    for id in live_keys.into_iter().chain([100]) {
        assert!(map.contains_key(&key(id)));
    }
    drop(map);
    assert_eq!(drops.load(Ordering::SeqCst), 17);
}

#[test]
fn elastic_metadata_is_appended_without_moving_control_or_data() {
    fn assert_layout<K, V>() {
        for &slots in &[0, 1, 7, 8, 31, 256] {
            let (base, data_offset) = arena::layout_for::<K, V>(slots).unwrap();
            let extended = elastic_arena_layout::<K, V>(slots).unwrap();
            assert_eq!(extended.data_base_off, data_offset);
            if slots == 0 {
                assert_eq!(extended.layout.size(), 0);
                assert_eq!(extended.membership.words, 0);
            } else {
                assert_eq!(extended.membership.offset, base.size());
                assert_eq!(
                    extended.membership.words,
                    slots.div_ceil(membership::SLOTS_PER_WORD)
                );
                assert!(extended.layout.size() > base.size());
            }
        }
    }

    assert_layout::<u64, u64>();
    assert_layout::<Zst, Zst>();
    assert_layout::<OverAligned, OverAligned>();
    assert!(mem::size_of::<MetadataWord>() <= 2 * membership::SLOTS_PER_WORD);

    let table =
        ElasticTable::<OverAligned, OverAligned, FixedHashBuilder>::with_capacity_and_reserve_and_hasher_in(
            64,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        );
    let layout = elastic_arena_layout::<OverAligned, OverAligned>(table.total_slots).unwrap();
    assert_eq!(
        table.membership_ptr().addr(),
        // SAFETY: the membership offset lies within the arena layout.
        unsafe { table.arena.as_ptr().add(layout.membership.offset) }.addr()
    );
    assert_eq!(
        table.membership_ptr().addr() % mem::align_of::<MetadataWord>(),
        0
    );
    for word in 0..table.membership.words {
        // SAFETY: `word < words` indexes an initialized metadata word.
        let metadata = unsafe { *table.membership_ptr().add(word) };
        assert_eq!(metadata.membership, 0);
        assert_eq!(metadata.level_bins, [0; 4]);
    }
    assert_eq!(
        table.levels[0].data_ptr().addr() % mem::align_of::<OverAligned>(),
        0
    );
}

#[test]
fn normal_inserts_advance_batch_scheduler() {
    let mut map: FixedElasticHashMap<usize, usize> = FixedElasticHashMap::with_capacity(1024);
    let initial_quota = map.table().scheduler.batch_ends[0];
    assert!(
        initial_quota > 0,
        "test requires a non-empty bootstrap batch"
    );

    for key in 0..initial_quota {
        map.insert(key, key);
    }
    // Positions `0..quota` were bootstrap placements; position `quota`,
    // the next insert, opens the first level pair.
    assert_eq!(
        map.table().scheduler.target_at(initial_quota - 1),
        BatchTarget::Bootstrap
    );
    assert_eq!(map.table().scheduler.current_batch_index, 0);

    map.insert(initial_quota, initial_quota);
    let len = map.len();
    assert_eq!(
        map.table().scheduler.target_at(len),
        BatchTarget::LevelPair(0)
    );
    assert!(map.table().scheduler.current_batch_index > 0);
}

#[test]
fn batch_target_follows_the_live_count_in_both_directions() {
    let mut map: FixedElasticHashMap<usize, usize> = FixedElasticHashMap::with_capacity(1024);
    let quota = map.table().scheduler.batch_ends[0];
    assert!(quota > 0);

    for key in 0..=quota {
        map.insert(key, key);
    }
    let len = map.len();
    assert_eq!(
        map.table().scheduler.target_at(len),
        BatchTarget::LevelPair(0)
    );

    // Two removals put the live count back inside the bootstrap window.
    assert_eq!(map.remove(&0), Some(0));
    assert_eq!(map.remove(&1), Some(1));
    let len = map.len();
    assert_eq!(map.table().scheduler.target_at(len), BatchTarget::Bootstrap);

    // The scalar oracle's prefix-sum rule, restated: batch `i` holds the
    // positions in `[ends[i-1], ends[i])`.
    let ends = map.table().scheduler.batch_ends.clone();
    let mut scheduler = map.table().scheduler.clone();
    for len in 0..*ends.last().unwrap() {
        let expected = ends.iter().position(|&end| len < end).unwrap();
        let target = scheduler.target(len);
        let index = match target {
            BatchTarget::Bootstrap => 0,
            BatchTarget::LevelPair(pair) => pair + 1,
        };
        assert_eq!(index, expected, "len {len}");
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn pop_first_churn_restores_paper_placement() {
    test_support::assert_pop_first_churn_restores_paper_placement::<
        ElasticTable<u64, u64, FixedHashBuilder>,
    >(|table| table.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG != 0);
}

#[test]
#[cfg_attr(miri, ignore)]
fn deletes_past_the_threshold_refresh_the_membership_filter() {
    test_support::assert_deletes_past_threshold_refresh_filter::<
        ElasticTable<u64, u64, FixedHashBuilder>,
    >(
        |table, key| {
            let prepared = PreparedElasticKey::new(table.hash_builder.hash_one(key));
            table.route_filter(prepared).maybe_present
        },
        |table| table.stale_membership,
    );
}

#[test]
fn duplicate_insert_does_not_advance_the_paper_schedule() {
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(64);
    assert_eq!(map.insert(7, 11), None);
    let batch = map.table().scheduler.current_batch_index;
    let len = map.len();
    let target = map.table().scheduler.target_at(len);

    assert_eq!(map.insert(7, 13), Some(11));
    assert_eq!(map.len(), 1);
    assert_eq!(map.table().scheduler.current_batch_index, batch);
    let len = map.len();
    assert_eq!(map.table().scheduler.target_at(len), target);
    assert_eq!(map.get(&7), Some(&13));
}

/// Independent restatement of the filter's bit pattern, kept here so a
/// change to the shared derivation has to be deliberate.
fn membership_bits_from_signature(signature: u64) -> u64 {
    let first = signature & 63;
    let second = (signature >> 32) & 63;
    let third = (signature >> 16) & 63;
    (1_u64 << first) | (1_u64 << second) | (1_u64 << third)
}

fn membership_maybe_contains_prepared<K, V, S, A>(
    table: &ElasticTable<K, V, S, A>,
    prepared: PreparedElasticKey,
) -> bool
where
    K: Eq + Hash,
    S: BuildHasher,
    A: Allocator + Clone,
{
    table.membership_maybe_contains(prepared.route, prepared.membership)
}

#[test]
fn compact_prepared_elastic_state_is_register_sized() {
    assert_eq!(mem::size_of::<PreparedElasticRoute>(), 8);
    assert_eq!(mem::align_of::<PreparedElasticRoute>(), 8);
    assert_eq!(mem::size_of::<PreparedElasticKey>(), 16);
    assert_eq!(mem::align_of::<PreparedElasticKey>(), 8);
}

#[test]
fn route_summary_saturates_deep_levels_into_the_last_bit() {
    assert_eq!(summary_level(0), 0);
    assert_eq!(
        summary_level(ROUTE_SUMMARY_LEVELS - 2),
        ROUTE_SUMMARY_LEVELS - 2
    );
    assert_eq!(
        summary_level(ROUTE_SUMMARY_LEVELS - 1),
        ROUTE_SUMMARY_LEVELS - 1
    );
    assert_eq!(
        summary_level(ROUTE_SUMMARY_LEVELS),
        ROUTE_SUMMARY_LEVELS - 1
    );
    assert_eq!(summary_level(40), ROUTE_SUMMARY_LEVELS - 1);

    // Expansion is the inverse view: the saturating bit covers every level
    // index at or past it, and a clear bit widens to nothing.
    let filter = |level_mask| ElasticRouteFilter {
        maybe_present: true,
        level_mask,
    };
    assert_eq!(filter(0).expanded_level_mask(), 0);
    assert_eq!(filter(0b101).expanded_level_mask(), 0b101);
    assert_eq!(
        filter(1 << (ROUTE_SUMMARY_LEVELS - 1)).expanded_level_mask(),
        u32::MAX << (ROUTE_SUMMARY_LEVELS - 1)
    );
    let level_limit = usize::try_from(probe::ELASTIC_LEVEL_LIMIT).unwrap();
    for level in 0..level_limit {
        let recorded = filter(1 << summary_level(level)).expanded_level_mask();
        assert_ne!(recorded & (1 << level), 0, "level {level} lost its bit");
    }
}

#[test]
fn route_summary_still_narrows_shallow_levels_on_wide_geometries() {
    // More levels than summary bits, so the last bit saturates.
    let capacity = if cfg!(miri) { 1 << 16 } else { 1 << 20 };
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(capacity, IdentityBuildHasher);
    assert!(
        map.table().levels.len() > ROUTE_SUMMARY_LEVELS,
        "fixture needs more levels than the summary width, got {}",
        map.table().levels.len()
    );
    let key_count = if cfg!(miri) { 64_u64 } else { 4_096_u64 };
    for key in 0..key_count {
        map.insert(key, key);
    }
    for key in 0..key_count {
        let prepared = PreparedElasticKey::new(key);
        let mask = map.table().route_filter(prepared).level_mask;
        assert!(mask != 0 && u16::try_from(mask).is_ok(), "mask {mask:#x}");
        assert!(
            mask.count_ones() < u32::try_from(ROUTE_SUMMARY_LEVELS).unwrap(),
            "key {key} mask {mask:#x} must exclude at least one level"
        );
        assert_eq!(map.get(&key), Some(&key));
    }
    assert_eq!(map.get(&(key_count + 1)), None);
}

#[test]
fn prepared_route_keeps_the_geometry_independent_signature() {
    for hash in (0..65_536_u64).map(|value| value.wrapping_mul(0x9e37_79b9_7f4a_7c15)) {
        let route = PreparedElasticRoute::new(hash);
        let signature = route.signature();
        assert_eq!(signature, route.probe.routing_signature());
    }
}

#[test]
fn compact_membership_matches_the_existing_signature_formula() {
    for hash in (0..16_384_u64).map(|value| value.rotate_left(19)) {
        let prepared = PreparedElasticKey::new(hash);
        let signature = prepared.route.signature();
        let expected = membership_bits_from_signature(signature);
        assert_eq!(prepared.membership.bits(), expected);
        for words in [1_usize, 3, 17, 257] {
            let product = u128::from(signature) * u128::try_from(words).unwrap();
            assert_eq!(
                MembershipKey::word(signature, words),
                usize::try_from(product >> 64).unwrap(),
            );
        }
    }
}

#[test]
fn prepared_elastic_key_uses_the_exact_probe_signature() {
    let hash = 0xd1b5_4a32_d192_ed03;
    let prepared = PreparedElasticKey::new(hash);
    assert_eq!(
        prepared.route.signature(),
        prepared.route.probe.routing_signature()
    );
}

#[test]
fn elastic_controls_keep_the_public_hash_fingerprint() {
    let hash = 1_u64;
    let prepared = PreparedElasticKey::new(hash);
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(64, IdentityBuildHasher);

    map.insert(hash, 7);
    let location = map
        .table()
        .find_slot_indices_prepared(&hash, prepared, control::control_fingerprint(hash))
        .unwrap();

    assert_eq!(
        map.table().levels[location.0].checked_control(location.1),
        control::control_fingerprint(hash)
    );
}

#[test]
fn route_summary_conservatively_records_every_live_level() {
    let (capacity, key_count, additional) = if cfg!(miri) {
        (128, 128_u64, 1_024)
    } else {
        (4_096, 4_096_u64, 20_000)
    };
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(capacity, IdentityBuildHasher);
    for key in 0..key_count {
        map.insert(key, key ^ 0x55);
    }

    let mut key_levels = vec![None; usize::try_from(key_count).unwrap()];
    for (level_index, level) in map.table().levels.iter().enumerate() {
        for slot in 0..level.capacity() {
            if control::is_occupied(level.checked_control(slot)) {
                // SAFETY: `slot` is in bounds and occupied.
                let key = unsafe { level.get_ref(slot) }.key;
                key_levels[usize::try_from(key).unwrap()] = Some(level_index);
            }
        }
    }
    for (key, level_index) in (0..key_count).zip(key_levels) {
        let level_index = level_index.unwrap();
        let prepared = PreparedElasticKey::new(key);
        assert_ne!(
            map.table().route_filter(prepared).level_mask & (1_u32 << summary_level(level_index)),
            0,
            "key {key} at level {level_index}"
        );
        assert_eq!(map.get(&key), Some(&(key ^ 0x55)));
    }
    assert!(
        map.table()
            .levels
            .iter()
            .filter(|level| level.len != 0)
            .count()
            > 1,
        "route summary must cover more than one occupied level"
    );

    let cloned = map.clone();
    for key in 0..key_count {
        assert_eq!(cloned.get(&key), Some(&(key ^ 0x55)));
    }

    map.reserve(additional);
    for key in 0..key_count {
        assert_eq!(map.get(&key), Some(&(key ^ 0x55)));
    }

    map.clear();
    assert!(map.table().levels.len() <= ROUTE_SUMMARY_LEVELS);
    for word in 0..map.table().membership.words {
        assert_eq!(
            // SAFETY: `word < words` indexes an initialized metadata word.
            unsafe { (*map.table().membership_ptr().add(word)).level_bins },
            [0; 4]
        );
    }
}

#[test]
fn prepared_elastic_key_remains_geometry_independent_across_growth() {
    let hash = 0x9e37_79b9_7f4a_7c15;
    let prepared = PreparedElasticKey::new(hash);
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(1, IdentityBuildHasher);
    map.insert(hash, 7);
    map.reserve(4_096);
    assert!(membership_maybe_contains_prepared(map.table(), prepared));
    assert_eq!(map.get(&hash), Some(&7));
}

#[test]
fn membership_filter_never_forgets_live_or_deleted_hashes() {
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(64, IdentityBuildHasher);
    let inserted_hash = map.table().hash_builder.hash_one(7_u64);
    let prepared = PreparedElasticKey::new(inserted_hash);
    assert!(!membership_maybe_contains_prepared(map.table(), prepared));

    assert_eq!(map.insert(7, 11), None);
    assert!(membership_maybe_contains_prepared(map.table(), prepared));

    assert_eq!(map.insert(7, 13), Some(11));
    assert_eq!(map.len(), 1);
    assert!(membership_maybe_contains_prepared(map.table(), prepared));

    assert_eq!(map.remove(&7), Some(13));
    assert!(membership_maybe_contains_prepared(map.table(), prepared));
    assert_eq!(map.insert(7, 17), None);
    assert_eq!(map.get(&7), Some(&17));
}

#[test]
fn blocked_membership_never_forgets_inserted_hashes() {
    let key_count = if cfg!(miri) { 128_u64 } else { 1_024_u64 };
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(
            usize::try_from(key_count * 2).unwrap(),
            IdentityBuildHasher,
        );
    for key in 0..key_count {
        map.insert(key, key);
    }
    for key in 0..key_count {
        assert!(membership_maybe_contains_prepared(
            map.table(),
            PreparedElasticKey::new(key)
        ));
    }
}

#[test]
fn prepared_membership_remains_valid_across_growth() {
    let key = 0xD1B5_4A32_D192_ED03_u64;
    let prepared = PreparedElasticKey::new(key);
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(1, IdentityBuildHasher);

    map.insert(key, 7);
    assert!(membership_maybe_contains_prepared(map.table(), prepared));
    let old_slots = map.table().total_slots;

    map.reserve(1_024);
    assert!(map.table().total_slots > old_slots);
    assert!(membership_maybe_contains_prepared(map.table(), prepared));
    assert_eq!(map.get(&key), Some(&7));
}

#[test]
fn membership_filter_resets_and_rebuilds_at_table_boundaries() {
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(128, IdentityBuildHasher);
    for key in 0_u64..96 {
        map.insert(key, key ^ 0x55);
    }

    let mut cloned = map.clone();
    for key in 0_u64..96 {
        let hash = cloned.table().hash_builder.hash_one(key);
        assert!(membership_maybe_contains_prepared(
            cloned.table(),
            PreparedElasticKey::new(hash),
        ));
        assert_eq!(cloned.get(&key), Some(&(key ^ 0x55)));
    }

    cloned.clear();
    for key in 0_u64..96 {
        let hash = cloned.table().hash_builder.hash_one(key);
        assert!(!membership_maybe_contains_prepared(
            cloned.table(),
            PreparedElasticKey::new(hash),
        ));
    }

    for key in 256_u64..384 {
        cloned.insert(key, key);
    }
    cloned.reserve(512);
    for key in 256_u64..384 {
        let hash = cloned.table().hash_builder.hash_one(key);
        assert!(membership_maybe_contains_prepared(
            cloned.table(),
            PreparedElasticKey::new(hash),
        ));
        assert_eq!(cloned.get(&key), Some(&key));
    }
}

#[test]
fn all_vacant_entry_apis_record_membership() {
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(128, IdentityBuildHasher);

    map.try_insert(11, 1).unwrap();
    map.entry(22).or_insert(2);
    map.get_or_insert_key_with(&33_u64, 3, |key| *key);

    for key in [11_u64, 22, 33] {
        let hash = map.table().hash_builder.hash_one(key);
        assert!(membership_maybe_contains_prepared(
            map.table(),
            PreparedElasticKey::new(hash)
        ));
        assert!(map.contains_key(&key));
    }
}

#[test]
fn drain_and_failed_reserve_preserve_membership_invariants() {
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(128, IdentityBuildHasher);
    for key in 0_u64..64 {
        map.insert(key, key);
    }
    assert!(map.try_reserve(usize::MAX).is_err());
    for key in 0_u64..64 {
        let hash = map.table().hash_builder.hash_one(key);
        assert!(membership_maybe_contains_prepared(
            map.table(),
            PreparedElasticKey::new(hash)
        ));
        assert_eq!(map.get(&key), Some(&key));
    }

    map.drain().for_each(drop);
    assert!(map.is_empty());
    for key in 0_u64..64 {
        let hash = map.table().hash_builder.hash_one(key);
        assert!(!membership_maybe_contains_prepared(
            map.table(),
            PreparedElasticKey::new(hash)
        ));
    }
}

#[test]
fn allocator_failure_does_not_publish_or_forget_membership() {
    let fail = Arc::new(AtomicBool::new(true));
    let alloc = ToggleAllocator::new(Arc::clone(&fail));
    let failed = ElasticHashMap::<u64, u64, IdentityBuildHasher, ToggleAllocator>::
        try_with_capacity_and_reserve_and_hasher_in(
            128,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            alloc.clone(),
        );
    assert!(matches!(
        failed,
        Err(TryBuildError::Reserve(TryReserveError::AllocError))
    ));

    fail.store(false, Ordering::SeqCst);
    let mut map = ElasticHashMap::<u64, u64, IdentityBuildHasher, ToggleAllocator>::
        with_capacity_and_reserve_and_hasher_in(
            128,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            alloc,
        );
    for key in 0_u64..64 {
        map.insert(key, key ^ 0x5a);
    }

    fail.store(true, Ordering::SeqCst);
    assert_eq!(map.try_reserve(4_096), Err(TryReserveError::AllocError));
    for key in 0_u64..64 {
        let hash = map.table().hash_builder.hash_one(key);
        assert!(membership_maybe_contains_prepared(
            map.table(),
            PreparedElasticKey::new(hash)
        ));
        assert_eq!(map.get(&key), Some(&(key ^ 0x5a)));
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn colliding_hashes_remain_distinguishable_through_delete_and_reuse() {
    let mut map: ElasticHashMap<u64, u64, ConstHashBuilder> =
        ElasticHashMap::with_capacity_and_hasher(512, ConstHashBuilder);
    let colliding_count = 64_u64;
    for key in 0..colliding_count {
        map.insert(key, key);
    }
    assert_eq!(map.remove(&0), Some(0));
    assert_eq!(map.insert(u64::MAX, 7), None);
    for key in 1..colliding_count {
        assert_eq!(map.get(&key), Some(&key));
    }
    assert_eq!(map.get(&u64::MAX), Some(&7));
}

#[test]
#[cfg_attr(miri, ignore)]
fn finite_probe_exhaustion_uses_observable_exceptional_recovery() {
    let reserve = ReserveFraction::DEFAULT;
    let mut table = ElasticTable::<u64, u64, ConstHashBuilder>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            8_192,
            reserve,
            ConstHashBuilder,
            Global,
        )
        .unwrap();
    let fingerprint = control::control_fingerprint(0);
    let prepared = PreparedElasticKey::new(0);
    let mut next_key = 0_u64;

    // Occupy every slot the shared hash can reach in every level, so no batch
    // target can place it.
    let block_every_route = |table: &mut ElasticTable<u64, u64, ConstHashBuilder>,
                             next_key: &mut u64| {
        for level in 0..table.levels.len() {
            let paper_level = level as u128 + 1;
            for logical_index in 0..UNIFORM_SEARCH_CAP {
                let paper_probe = u128::from(logical_index) + 1;
                if probe::elastic_phi(paper_level, paper_probe).unwrap() > QUERY_POSITION_CAP {
                    break;
                }
                let slot = table.route_exact(level, 0, logical_index).unwrap();
                if control::is_free(table.levels[level].checked_control(slot)) {
                    // SAFETY: `checked_control` bounds-checked `slot`.
                    unsafe {
                        table.levels[level].write_with_control(
                            slot,
                            SlotEntry {
                                key: *next_key,
                                value: *next_key,
                            },
                            fingerprint,
                        );
                    }
                    table.levels[level].len += 1;
                    table.len += 1;
                    *next_key += 1;
                }
            }
        }
    };
    block_every_route(&mut table, &mut next_key);
    assert!(table.len < table.max_insertions);
    assert!(
        table
            .choose_slot_for_new_key(prepared.route.probe, BatchTarget::Bootstrap)
            .is_none()
    );
    assert!(
        table
            .choose_slot_on_other_targets(prepared.route.probe, BatchTarget::Bootstrap)
            .is_none()
    );

    let before = table.epoch.snapshot(table.len);
    let location = table.insert_for_vacant_entry(u64::MAX, 7, 0);
    let after = table.epoch.snapshot(table.len);
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(after.placement_recoveries, before.placement_recoveries + 1);
    assert_eq!(after.transition, EpochTransition::PlacementRecovery);
    assert_ne!(table.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG, 0);
    assert!(membership_maybe_contains_prepared(&table, prepared));
    assert_eq!(
        table.find_slot_indices_prepared(&u64::MAX, prepared, fingerprint),
        Some(location)
    );
    for key in 0..next_key {
        assert!(
            table
                .find_slot_indices_prepared(&key, prepared, fingerprint)
                .is_some()
        );
    }

    // The epoch already failed its rebuild, so the next failure places
    // exceptionally without another O(n) rebuild.
    block_every_route(&mut table, &mut next_key);
    assert!(table.len < table.max_insertions);
    let before = table.epoch.snapshot(table.len);
    let location = table.insert_for_vacant_entry(u64::MAX - 1, 8, 0);
    let after = table.epoch.snapshot(table.len);
    assert_eq!(after.generation, before.generation);
    assert_eq!(after.placement_recoveries, before.placement_recoveries + 1);
    assert_eq!(
        table.find_slot_indices_prepared(&(u64::MAX - 1), prepared, fingerprint),
        Some(location)
    );
}

#[test]
fn direct_lookup_returns_the_compared_slot_reference() {
    let mut table: ElasticTable<usize, usize, FixedHashBuilder> =
        ElasticTable::with_capacity_and_reserve_and_hasher_in(
            1024,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        );
    let mut insertion_count = 0;
    while insertion_count < table.max_insertions
        && !table.levels.iter().skip(1).any(|level| level.len > 0)
    {
        let key = insertion_count;
        table.place_unique(
            SlotEntry {
                key,
                value: key ^ 0xa5a5,
            },
            table.hash_builder.hash_one(key),
        );
        insertion_count += 1;
    }
    assert!(
        table.levels.iter().skip(1).any(|level| level.len > 0),
        "test must exercise lookup beyond level 0"
    );

    for key in 0..insertion_count {
        let hash = table.hash_builder.hash_one(key);
        let prepared = PreparedElasticKey::new(hash);
        let fingerprint = control::control_fingerprint(hash);
        let location = table
            .find_slot_indices_prepared(&key, prepared, fingerprint)
            .expect("inserted key must have a location");
        let direct = table
            .find_entry_prepared(&key, prepared, fingerprint)
            .expect("inserted key must have an entry reference");
        // SAFETY: `find_slot_indices_prepared` returns an occupied in-bounds slot.
        let resolved = unsafe { table.levels[location.0].get_ref(location.1) };
        assert!(ptr::eq(direct, resolved), "key {key} returned a new slot");
    }

    let missing = usize::MAX;
    let hash = table.hash_builder.hash_one(missing);
    let prepared = PreparedElasticKey::new(hash);
    let fingerprint = control::control_fingerprint(hash);
    assert!(
        table
            .find_entry_prepared(&missing, prepared, fingerprint)
            .is_none()
    );
}

#[test]
fn delete_below_cleanup_threshold_preserves_survivor_locations() {
    let mut map: FixedElasticHashMap<usize, usize> = FixedElasticHashMap::with_capacity(512);
    for key in 0..100 {
        map.insert(key, key);
    }
    let before: Vec<_> = (1..100)
        .map(|key| {
            let hash = map.table().hash_builder.hash_one(key);
            map.table()
                .find_slot_indices_prepared(
                    &key,
                    PreparedElasticKey::new(hash),
                    control::control_fingerprint(hash),
                )
                .unwrap()
        })
        .collect();

    assert_eq!(map.remove(&0), Some(0));

    let after: Vec<_> = (1..100)
        .map(|key| {
            let hash = map.table().hash_builder.hash_one(key);
            map.table()
                .find_slot_indices_prepared(
                    &key,
                    PreparedElasticKey::new(hash),
                    control::control_fingerprint(hash),
                )
                .unwrap()
        })
        .collect();
    assert_eq!(after, before);
}

#[test]
fn rebuild_inserts_advance_batch_scheduler() {
    let mut table: ElasticTable<usize, usize, FixedHashBuilder> =
        ElasticTable::with_capacity_and_reserve_and_hasher_in(
            1024,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        );
    let initial_quota = table.scheduler.batch_ends[0];
    assert!(
        initial_quota > 0,
        "test requires a non-empty bootstrap batch"
    );

    for key in 0..=initial_quota {
        table.place_unique(
            SlotEntry { key, value: key },
            table.hash_builder.hash_one(key),
        );
    }

    let len = table.len;
    assert_eq!(table.scheduler.target(len), BatchTarget::LevelPair(0));
    assert!(table.scheduler.current_batch_index > 0);
}

#[test]
#[cfg_attr(miri, ignore)]
fn vacant_insert_uses_the_table_insertion_limit() {
    let mut table: ElasticTable<usize, usize, FixedHashBuilder> =
        ElasticTable::with_capacity_and_reserve_and_hasher_in(
            1024,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        );
    let rebuild_slots = table.total_slots * 2;
    let rebuild_geometry =
        ElasticGeometry::for_slots(rebuild_slots, table.reserve_fraction).unwrap();
    let bootstrap_quota = rebuild_geometry.batch_plan[0];

    for key in 0..bootstrap_quota {
        table.place_unique(
            SlotEntry { key, value: key },
            table.hash_builder.hash_one(key),
        );
    }
    table.max_insertions = table.len;
    table.scheduler.settled_limit = table.len;
    table.scheduler.sync(table.len);
    let previous_slots = table.total_slots;

    let key = bootstrap_quota;
    let hash = table.hash_builder.hash_one(key);
    table.insert_for_vacant_entry(key, key, hash);

    assert!(table.total_slots > previous_slots);
    let len = table.len;
    assert_eq!(table.scheduler.target(len), BatchTarget::LevelPair(0));
    assert!(table.scheduler.current_batch_index > 0);
}

#[test]
#[cfg_attr(miri, ignore)]
fn clone_and_clear_preserve_elastic_lookups() {
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(512);
    for i in 0..384 {
        map.insert(i, i ^ 0xa5a5);
    }

    let cloned = map.clone();
    for i in 0..384 {
        assert_eq!(cloned.get(&i), Some(&(i ^ 0xa5a5)));
    }
    for i in 10_000..10_128 {
        assert_eq!(cloned.get(&i), None);
    }

    map.clear();
    for i in 512..896 {
        map.insert(i, i ^ 0x5a5a);
    }
    for i in 512..896 {
        assert_eq!(map.get(&i), Some(&(i ^ 0x5a5a)));
    }
    for i in 0..384 {
        assert_eq!(map.get(&i), None);
    }
}

#[test]
fn retain_does_not_trigger_mid_iter_resize_with_clustered_tombstones() {
    let mut map: FixedElasticHashMap<i32, i32> = FixedElasticHashMap::with_capacity(256);
    let cap = i32::try_from(map.capacity()).expect("test capacity fits i32");
    let n = cap * 2 / 3;
    for i in 0..n {
        map.insert(i, i);
    }
    let initial_capacity = map.capacity();
    map.retain(|k, _| k % 2 == 0);

    let expected_count = (0..n).filter(|i| i % 2 == 0).count();
    assert_eq!(map.len(), expected_count);
    for i in 0..n {
        if i % 2 == 0 {
            assert_eq!(map.get(&i), Some(&i), "kept key {i} missing");
        } else {
            assert!(map.get(&i).is_none(), "dropped key {i} survived");
        }
    }
    assert_eq!(
        map.capacity(),
        initial_capacity,
        "retain cannot resize while its scan is active"
    );
}

#[test]
fn inserts_spill_to_deeper_levels_at_high_load() {
    // Paper §4: batches push later inserts into deeper levels.
    let mut map: FixedElasticHashMap<i32, i32> = FixedElasticHashMap::with_capacity(512);
    assert!(
        map.table().levels.len() > 1,
        "test requires multi-level layout"
    );
    let max = i32::try_from(map.capacity()).expect("test capacity fits i32");
    for i in 0..max {
        map.insert(i, i);
    }
    assert!(
        map.table().levels.iter().skip(1).any(|level| level.len > 0),
        "expected the exact batch schedule to populate a deeper level"
    );
    for i in 0..max {
        assert_eq!(map.get(&i), Some(&i));
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn removing_every_entry_empties_every_level() {
    let mut map: FixedElasticHashMap<i32, i32> = FixedElasticHashMap::with_capacity(512);
    let max = i32::try_from(map.capacity()).expect("test capacity fits i32");
    for i in 0..max {
        map.insert(i, i);
    }
    for i in 0..max {
        map.remove(&i);
    }
    assert_eq!(map.len(), 0);
    assert!(map.table().levels.iter().all(|level| level.len == 0));
}

#[test]
fn probe_schedule_capacity_table_matches_the_route_walk() {
    let mut walked = 0;
    assert_eq!(PROBE_SCHEDULE_CAPACITY[0], 0);
    for level in 0..MAX_LEVELS {
        for_each_phi_route(level, 1, QUERY_POSITION_CAP, |_, _| walked += 1);
        assert_eq!(PROBE_SCHEDULE_CAPACITY[level + 1], walked);
    }
}

#[test]
fn drop_continues_past_a_panicking_value() {
    let drops = Arc::new(AtomicUsize::new(0));
    let mut map = FixedElasticHashMap::<usize, PanicOnFirstDrop>::with_capacity(256);
    // Fill until entries spill past level 0, so the walk resumed after the
    // panic must cross levels.
    let mut inserted = 0;
    while !map.table().levels.iter().skip(1).any(|level| level.len > 0) {
        map.insert(inserted, PanicOnFirstDrop(drops.clone()));
        inserted += 1;
    }
    assert!(catch_unwind(AssertUnwindSafe(|| drop(map))).is_err());
    // The panicking value counts too, so every value dropped exactly once.
    assert_eq!(drops.load(Ordering::SeqCst), inserted);
}

#[test]
#[cfg_attr(miri, ignore)]
fn delete_churn_does_not_target_saturated_levels() {
    // Random inserts, removes, and small `retain` sweeps over a fixed key
    // space settle the table near three fifths full while the live count
    // keeps crossing batch boundaries.
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(0);
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = || {
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    };

    let mut recoveries = 0;
    let mut generation = map.epoch().generation;
    for step in 0..200_000_u64 {
        let key = next() % 2_000;
        match next() % 10 {
            0..5 => {
                map.insert(key, step);
            }
            5..8 => {
                map.remove(&key);
            }
            8 => {
                let residue = next() % 97;
                map.retain(|&k, _| k % 97 != residue);
            }
            _ => {}
        }
        let epoch = map.epoch();
        if epoch.generation != generation && epoch.transition == EpochTransition::PlacementRecovery
        {
            recoveries += 1;
        }
        generation = epoch.generation;
    }

    assert_eq!(recoveries, 0, "placement recoveries under delete churn");
}

#[test]
#[cfg_attr(miri, ignore)]
fn case_one_probe_past_the_query_cap_falls_through_to_the_next_level() {
    // At delta = 2^-16 the Case 1 budget reaches 128 probes, one more than a
    // level-8 lookup can reach. A vacancy found only by that last probe must
    // count as a failed probe, as in the paper, not abort the placement.
    const LEVEL: usize = 8;
    let reserve = ReserveFraction::from_exponent(16).unwrap();
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(1 << 20, reserve, IdentityBuildHasher, Global)
        .unwrap();
    let level_slots = table.levels[LEVEL].capacity();
    let reachable = (1..=QUERY_POSITION_CAP)
        .take_while(|&probe| {
            probe::elastic_phi(LEVEL as u128 + 1, probe).unwrap() <= QUERY_POSITION_CAP
        })
        .count() as u64;
    let budget = probe::elastic_dyadic_probe_budget(
        level_slots / 16,
        level_slots,
        reserve.exponent(),
        ELASTIC_PROBE_BUDGET_C,
    )
    .unwrap() as u64;
    assert!(
        budget > reachable,
        "fixture needs a budget past the query cap"
    );

    // A key whose last budgeted probe lands on a slot no earlier probe visits.
    let (key_hash, unreachable_slot) = (0_u64..)
        .find_map(|hash| {
            let last = table.route_exact(LEVEL, hash, reachable)?;
            (0..reachable)
                .all(|index| table.route_exact(LEVEL, hash, index) != Some(last))
                .then_some((hash, last))
        })
        .unwrap();

    // Fill the level to one sixteenth free, keeping only that slot among the
    // key's reachable probes open; leave the next level empty.
    let probed = (0..reachable).map(|index| table.route_exact(LEVEL, key_hash, index).unwrap());
    let fill_order = probed.chain(0..level_slots).collect::<Vec<_>>();
    let mut next_key = 0_u64;
    for slot in fill_order {
        if slot == unreachable_slot
            || !control::is_free(table.levels[LEVEL].checked_control(slot))
            || table.levels[LEVEL].free_slots() == level_slots / 16
        {
            continue;
        }
        // SAFETY: `checked_control` bounds-checked `slot`.
        unsafe {
            table.levels[LEVEL].write_with_control(
                slot,
                SlotEntry {
                    key: next_key,
                    value: next_key,
                },
                control::OCCUPIED_BIT,
            );
        }
        table.levels[LEVEL].len += 1;
        table.len += 1;
        next_key += 1;
    }
    assert!(
        (0..reachable).all(|index| {
            let slot = table.route_exact(LEVEL, key_hash, index).unwrap();
            !control::is_free(table.levels[LEVEL].checked_control(slot))
        }),
        "every reachable probe must be occupied"
    );

    let prepared = PreparedElasticKey::new(key_hash);
    let placement = table
        .choose_slot_for_new_key(prepared.route.probe, BatchTarget::LevelPair(LEVEL))
        .expect("Case 1 falls through to the next level");
    assert_eq!(placement.level, LEVEL + 1);
}

/// For every key below `keys` that sits past the first probe of its level:
/// the key holding that first slot, the key itself, the level, and the slot.
fn keys_behind_another_on_their_route(
    map: &FixedElasticHashMap<u64, u64>,
    keys: u64,
) -> Vec<(u64, u64, usize, usize)> {
    let table = map.table();
    let mut behind = Vec::new();
    for key in 0..keys {
        let hash = table.hash_builder.hash_one(key);
        let (level, slot) = table.find(&key, hash).unwrap();
        let region = &table.levels[level];
        let word = PreparedElasticKey::new(hash)
            .route
            .probe
            .sequence(table.fold_multiplier)
            .word(probe::elastic_level_run(level).0);
        let first = probe::shifted_elastic_index(word, region.index_shift());
        if first != slot {
            assert!(control::is_occupied(region.checked_control(first)));
            // SAFETY: the slot is in bounds and occupied, checked above.
            let ahead = unsafe { region.get_ref(first) }.key;
            behind.push((ahead, key, level, first));
        }
    }
    behind
}

#[test]
fn lookup_passes_a_tombstone_ahead_of_a_live_key_on_its_route() {
    const KEYS: u64 = 2_048;
    let mut map: FixedElasticHashMap<u64, u64> =
        FixedElasticHashMap::with_capacity(usize::try_from(KEYS).unwrap());
    for key in 0..KEYS {
        map.insert(key, key);
    }
    assert_ne!(map.table().levels[0].index_shift(), GENERAL_REDUCTION);
    let behind = keys_behind_another_on_their_route(&map, KEYS);
    assert!(behind.len() > 64);

    let mut removed = alloc::collections::BTreeSet::new();
    for &(ahead, survivor, level, first) in &behind {
        if removed.contains(&survivor) || !removed.insert(ahead) {
            continue;
        }
        assert_eq!(map.remove(&ahead), Some(ahead));
        assert_eq!(
            map.table().levels[level].checked_control(first),
            CTRL_TOMBSTONE
        );
        assert_eq!(map.get(&survivor), Some(&survivor));
    }
    for key in 0..KEYS {
        assert_eq!(map.get(&key).is_some(), !removed.contains(&key));
    }
}

/// Logical probes of `level` the schedule holds, in order.
fn scheduled_logical_probes<K, V, S, A: Allocator + Clone>(
    table: &ElasticTable<K, V, S, A>,
    level: usize,
) -> Vec<u64> {
    let mut logical = table
        .probe_schedule
        .routes()
        .iter()
        .filter(|route| route.level() as usize == level)
        .map(|route| route.coordinates().1)
        .collect::<Vec<_>>();
    logical.sort_unstable();
    logical
}

#[test]
fn a_table_without_metadata_words_rejects_every_lookup() {
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(0);
    assert_eq!(map.table().membership.words, 0);
    for key in 0..1_000_u64 {
        let prepared = PreparedElasticKey::new(map.table().hash_builder.hash_one(key));
        let filter = map.table().route_filter(prepared);
        assert!(!filter.maybe_present);
        assert_eq!(filter.level_mask, 0);
        assert_eq!(map.get(&key), None);
        assert!(!map.contains_key(&key));
        assert_eq!(map.remove(&key), None);
    }

    // The first insert grows into a table with words of its own.
    assert_eq!(map.insert(7, 70), None);
    assert_ne!(map.table().membership.words, 0);
    assert_eq!(map.get(&7), Some(&70));
    assert_eq!(map.get(&8), None);
}

#[test]
#[cfg_attr(
    miri,
    ignore = "checks the whole schedule after each of thousands of inserts"
)]
fn first_entry_in_a_deeper_level_reschedules_through_that_level() {
    const KEYS: u64 = 3_000;
    let mut map: FixedElasticHashMap<u64, u64> =
        FixedElasticHashMap::with_capacity(usize::try_from(KEYS).unwrap());
    let mut reschedules = 0;
    let mut scheduled_levels = 0;
    for key in 0..KEYS {
        map.insert(key, key);
        let table = map.table();
        let deepest = table
            .levels
            .iter()
            .rposition(|level| level.len > 0)
            .unwrap();
        assert!(deepest < table.scheduled_levels as usize);
        if table.scheduled_levels != scheduled_levels {
            assert_eq!(table.scheduled_levels as usize, deepest + 1);
            assert_eq!(table.levels[deepest].len, 1);
            scheduled_levels = table.scheduled_levels;
            reschedules += 1;
        }

        // Every scheduled level holds exactly its first `scheduled_probes`
        // probes (level zero's first is the direct slot), and no other
        // level counts any.
        for (level, region) in table.levels.iter().enumerate() {
            if level >= table.scheduled_levels as usize {
                assert_eq!(region.scheduled_probes, 0);
                continue;
            }
            let direct = u64::from(level == 0);
            let logical = scheduled_logical_probes(table, level);
            assert!(
                logical
                    .iter()
                    .copied()
                    .eq(direct..direct + logical.len() as u64)
            );
            assert_eq!(
                direct + logical.len() as u64,
                u64::from(region.scheduled_probes)
            );
        }
        assert_eq!(map.get(&key), Some(&key));
    }
    assert!(reschedules >= 3);
    for key in 0..KEYS {
        assert_eq!(map.get(&key), Some(&key));
    }
}

fn assert_reinsert_replaces<S: BuildHasher + Clone>(
    table: &mut ElasticTable<u64, u64, S>,
    keys: u64,
) {
    let len = table.len;
    for key in 0..keys {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(table.insert(key, key ^ 0xff, hash), Some(key));
        assert_eq!(table.find_value(&key, hash), Some(&(key ^ 0xff)));
    }
    assert_eq!(table.len, len);
    let hash = table.hash_builder.hash_one(keys);
    assert_eq!(table.insert(keys, 1, hash), None);
    assert_eq!(table.len, len + 1);
    assert_eq!(table.find_value(&keys, hash), Some(&1));
}

#[test]
fn reinsert_replaces_the_value_on_a_general_reduction_table() {
    const KEYS: u64 = 600;
    let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            1_000,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
    assert_eq!(table.levels[0].index_shift(), GENERAL_REDUCTION);
    for key in 0..KEYS {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(table.insert(key, key, hash), None);
    }
    assert_reinsert_replaces(&mut table, KEYS);
}

#[test]
fn reinsert_replaces_the_value_on_a_table_flagged_exceptional() {
    const KEYS: u64 = 600;
    let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            1_024,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
    assert_ne!(table.levels[0].index_shift(), GENERAL_REDUCTION);
    for key in 0..KEYS {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(table.insert(key, key, hash), None);
    }
    // The flag only widens a lookup, so raising it by hand is a valid state.
    table.probe_high_water |= EXCEPTIONAL_PLACEMENT_FLAG;
    assert_reinsert_replaces(&mut table, KEYS);
}

#[test]
fn schedule_lookup_agrees_with_the_general_walk_and_the_full_scan() {
    let mut hits = 0;
    let mut filtered_misses = 0;
    let mut walked_misses = 0;
    let mut shifted_tables = 0;
    let mut general_tables = 0;
    let (slot_counts, floor): (&[usize], _) = if cfg!(miri) {
        (&[32, 100, 256, 300], 100)
    } else {
        (&[32, 128, 1_000, 2_048, 3_000, 8_192], 1_000)
    };
    for &slots in slot_counts {
        let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                slots,
                ReserveFraction::DEFAULT,
                fixed_hasher(),
                Global,
            )
            .unwrap();
        if table.levels[0].index_shift() == GENERAL_REDUCTION {
            general_tables += 1;
        } else {
            shifted_tables += 1;
        }
        let budget = table.max_insertions as u64;
        for key in 0..budget {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.insert(key, key, hash), None);
        }
        for key in (0..budget).step_by(3) {
            let hash = table.hash_builder.hash_one(key);
            let location = table.find(&key, hash).unwrap();
            assert_eq!(table.remove(location), (key, key));
        }
        for key in (0..budget).step_by(6) {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.insert(key, key, hash), None);
        }
        assert!(table.probe_schedule.addresses(&table.levels));
        for key in 0..2 * budget {
            let hash = table.hash_builder.hash_one(key);
            let prepared = PreparedElasticKey::new(hash);
            let fingerprint = control::control_fingerprint(hash);
            let scheduled = table.find_slot_indices_prepared(&key, prepared, fingerprint);
            let scanned =
                table.find_by_full_scan(&key, fingerprint, |level, slot, _| (level, slot));
            assert_eq!(scheduled, scanned);
            assert_eq!(scheduled.is_some(), key < budget && key % 6 != 3);
            let filter = table.route_filter(prepared);
            if filter.maybe_present {
                let walked = table.find_by_general_schedule(
                    &key,
                    prepared,
                    fingerprint,
                    filter.expanded_level_mask(),
                    |level, slot, _| (level, slot),
                );
                assert_eq!(scheduled, walked);
            }
            match (scheduled, filter.maybe_present) {
                (Some(_), _) => hits += 1,
                (None, true) => walked_misses += 1,
                (None, false) => filtered_misses += 1,
            }
        }
    }
    assert!(hits > floor && filtered_misses > floor && walked_misses > 0);
    assert!(shifted_tables > 0 && general_tables > 0);
}

#[test]
fn settled_insert_slot_agrees_with_the_general_placement() {
    const KEYS: u64 = if cfg!(miri) { 600 } else { 6_000 };
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(0);
    let mut settled = 0;
    let mut unsettled = 0;
    for key in 0..KEYS {
        // Removing an earlier key now and then leaves tombstones for the
        // searches to reuse and moves the live count back across batches.
        if key % 7 == 3 {
            map.remove(&(key / 2));
        }
        let table = map.table();
        let probe = PreparedElasticKey::new(table.hash_builder.hash_one(key))
            .route
            .probe;
        if let Some((level, slot, control)) = table.settled_slot(probe) {
            // SAFETY: the settled search returns a slot of `level`.
            assert_eq!(control, unsafe { table.levels[level].control_at(slot) });
            let target = table.scheduler.target_at(table.len);
            let general = table
                .choose_slot_for_new_key(probe, target)
                .expect("the settled search found a slot");
            assert_eq!((level, slot), (general.level, general.slot));
            assert!(general.paper_probe <= u64::from(table.levels[level].scheduled_probes));
            settled += 1;
        } else {
            unsettled += 1;
        }
        map.insert(key, key);
    }
    assert!(settled > unsettled);
    assert!(unsettled > 16);
    for key in 0..KEYS {
        let removed = (0..KEYS).any(|later| later % 7 == 3 && later / 2 == key && later > key);
        assert_eq!(map.get(&key).is_some(), !removed, "{key}");
    }
}

#[test]
fn shifted_vacancy_search_agrees_with_the_general_one() {
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(1_024);
    for key in 0..900 {
        map.insert(key, key);
    }
    let table = map.table();
    assert_ne!(table.levels[0].index_shift(), GENERAL_REDUCTION);
    let mut found = 0;
    let mut missed = 0;
    let keys = if cfg!(miri) { 300_u64 } else { 2_000 };
    for key in 0..keys {
        let probe = PreparedElasticKey::new(table.hash_builder.hash_one(key))
            .route
            .probe;
        for level in 0..table.levels.len() {
            for budget in [0, 1, 2, 7, 64] {
                let region = &table.levels[level];
                // SAFETY: `region` is `level`, and level zero reduces by
                // shift, so every level does.
                let shifted = unsafe { table.first_shifted_vacancy(probe, level, region, budget) }
                    .map(|(slot, paper_probe, control)| {
                        // SAFETY: the search returns a slot of `region`.
                        assert_eq!(control, unsafe { region.control_at(slot) });
                        (slot, paper_probe)
                    });
                assert_eq!(shifted, table.first_vacancy_general(probe, level, budget));
                if shifted.is_some() {
                    found += 1;
                } else {
                    missed += 1;
                }
            }
        }
    }
    assert!(found > 1_000 && missed > 1_000);
}

#[test]
fn levels_reduce_all_by_shift_or_all_by_the_general_reduction() {
    let mut shifted_tables = 0;
    let mut general_tables = 0;
    let mut single_slot_levels = 0;
    for slots in [
        1, 2, 3, 4, 7, 8, 16, 31, 64, 100, 1_000, 1_024, 4_096, 5_000, 65_536,
    ] {
        if cfg!(miri) && slots > 100 {
            continue;
        }
        let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                slots,
                ReserveFraction::DEFAULT,
                fixed_hasher(),
                Global,
            )
            .unwrap();
        let shifts = table
            .levels
            .iter()
            .map(|level| probe::elastic_index_shift(level.capacity()))
            .collect::<Vec<_>>();
        single_slot_levels += table
            .levels
            .iter()
            .filter(|level| level.capacity() == 1)
            .count();
        if shifts.iter().all(Option::is_some) {
            shifted_tables += 1;
            for (level, shift) in table.levels.iter().zip(&shifts) {
                assert_eq!(Some(level.index_shift()), *shift);
            }
        } else {
            general_tables += 1;
            for level in &table.levels {
                assert_eq!(level.index_shift(), GENERAL_REDUCTION);
            }
        }

        let keys = table.max_insertions as u64;
        for key in 0..keys {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.insert(key, key, hash), None);
        }
        for key in 0..keys {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.find_value(&key, hash), Some(&key));
        }
    }
    assert!(shifted_tables > 0 && general_tables > 0 && single_slot_levels > 0);
}

#[test]
fn schedule_addresses_the_levels_of_every_table_it_serves() {
    type Table = ElasticTable<u64, u64, FixedHashBuilder>;
    fn check(table: &Table) -> bool {
        assert!(table.probe_schedule.addresses(&table.levels));
        table.levels[0].index_shift() == GENERAL_REDUCTION
    }
    let mut general_tables = 0;
    let mut shifted_tables = 0;
    let slot_counts: &[usize] = if cfg!(miri) {
        &[1, 3, 32, 48]
    } else {
        &[1, 3, 32, 1_000, 2_048, 3_000]
    };
    for &slots in slot_counts {
        let mut table = Table::try_with_slots_and_reserve_fraction_and_hasher_in(
            slots,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
        let mut seen = vec![check(&table)];
        // Twice the budget takes the table through a growth.
        let keys = 2 * table.max_insertions as u64;
        for key in 0..keys {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.insert(key, key, hash), None);
            seen.push(check(&table));
        }
        let cloned = map::TableBackend::clone_table(&table);
        let general = check(&cloned);
        seen.push(general);
        // Only routes that probe nothing fit another table's levels.
        assert_eq!(cloned.probe_schedule.addresses(&table.levels), general);
        for key in 0..keys + 64 {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(cloned.find(&key, hash).is_some(), key < keys);
        }
        map::TableBackend::clear(&mut table);
        seen.push(check(&table));
        general_tables += seen.iter().filter(|&&general| general).count();
        shifted_tables += seen.iter().filter(|&&general| !general).count();
    }
    assert!(general_tables > 0 && shifted_tables > 0);
}

/// Small enough to run under Miri, and reaches the lookup's direct route,
/// the sentinel's control bytes, the static empty filter word and the
/// settled insert on every table shape.
#[test]
fn lookup_and_insert_paths_hold_on_every_small_table_shape() {
    type Table = ElasticTable<u64, u64, FixedHashBuilder>;
    fn assert_holds(table: &Table, present: impl Fn(u64) -> bool, keys: u64) {
        assert!(table.probe_schedule.addresses(&table.levels));
        for key in 0..keys + 8 {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.find_value(&key, hash), present(key).then_some(&key));
        }
    }
    let mut settled = 0;
    let mut general_tables = 0;
    let mut shifted_tables = 0;
    for slots in [0, 1, 2, 3, 5, 16, 24, 64] {
        let mut table = Table::try_with_slots_and_reserve_fraction_and_hasher_in(
            slots,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
        assert_holds(&table, |_| false, 0);
        // Twice the budget takes the table through a growth.
        let budget = table.max_insertions;
        let keys = 2 * budget.max(8) as u64;
        for key in 0..keys {
            match table.levels.first().map(Level::index_shift) {
                Some(GENERAL_REDUCTION) => general_tables += 1,
                Some(_) => shifted_tables += 1,
                None => {}
            }
            let hash = table.hash_builder.hash_one(key);
            let probe = PreparedElasticKey::new(hash).route.probe;
            settled += usize::from(table.settled_slot(probe).is_some());
            assert_eq!(table.insert(key, key, hash), None);
            assert_eq!(table.insert(key, key, hash), Some(key));
        }
        assert!(table.max_insertions > budget, "slots {slots}");
        assert_holds(&table, |key| key < keys, keys);

        let cloned = map::TableBackend::clone_table(&table);
        for key in (0..keys).step_by(2) {
            let hash = table.hash_builder.hash_one(key);
            let location = table.find(&key, hash).unwrap();
            assert_eq!(table.remove(location), (key, key));
        }
        assert_holds(&table, |key| key < keys && key % 2 == 1, keys);
        assert_holds(&cloned, |key| key < keys, keys);

        map::TableBackend::clear(&mut table);
        assert_holds(&table, |_| false, keys);
        for key in 0..4 {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.insert(key, key, hash), None);
        }
        assert_holds(&table, |key| key < 4, keys);
    }
    assert!(settled > 0 && general_tables > 0 && shifted_tables > 0);
}

#[test]
fn lookups_resolve_on_the_smallest_tables() {
    let mut single_slot_first_levels = 0;
    for slots in 1..=5 {
        let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                slots,
                ReserveFraction::DEFAULT,
                fixed_hasher(),
                Global,
            )
            .unwrap();
        single_slot_first_levels += usize::from(table.levels[0].capacity() == 1);
        let budget = table.max_insertions as u64;
        for key in 0..budget {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.insert(key, key, hash), None);
        }
        for key in 0..64 {
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.find(&key, hash).is_some(), key < budget);
        }
    }
    assert!(single_slot_first_levels > 0);
}

#[test]
fn clone_carries_the_schedule_onto_its_own_levels() {
    const KEYS: u64 = 3_000;
    let mut map: FixedElasticHashMap<u64, u64> =
        FixedElasticHashMap::with_capacity(usize::try_from(KEYS).unwrap());
    for key in 0..KEYS - 64 {
        map.insert(key, key);
    }
    let mut cloned = map.clone();
    {
        let (source, copy) = (map.table(), cloned.table());
        assert!(source.scheduled_levels >= 3);
        assert_eq!(copy.scheduled_levels, source.scheduled_levels);
        assert!(
            copy.levels
                .iter()
                .map(|level| level.scheduled_probes)
                .eq(source.levels.iter().map(|level| level.scheduled_probes))
        );
        assert_eq!(copy.probe_high_water, source.probe_high_water);
        assert_eq!(
            copy.probe_schedule.routes().len(),
            source.probe_schedule.routes().len()
        );
        for (ours, theirs) in copy
            .probe_schedule
            .routes()
            .iter()
            .zip(source.probe_schedule.routes())
        {
            assert_eq!(
                (ours.level(), ours.index_shift(), ours.sequence_index()),
                (
                    theirs.level(),
                    theirs.index_shift(),
                    theirs.sequence_index()
                )
            );
            assert_eq!(
                ours.control(),
                copy.levels[ours.level() as usize].ctrl_ptr.cast_const()
            );
            assert_ne!(ours.control(), theirs.control());
        }
        assert!(copy.probe_schedule.ends_with_sentinel());
        assert!(copy.probe_schedule.addresses(&copy.levels));
        assert!(!copy.probe_schedule.addresses(&source.levels));
    }
    drop(map);
    for key in 0..KEYS - 64 {
        assert_eq!(cloned.get(&key), Some(&key));
    }
    for key in KEYS - 64..KEYS {
        cloned.insert(key, key);
    }
    for key in 0..KEYS {
        assert_eq!(cloned.get(&key), Some(&key));
    }
    assert_eq!(cloned.get(&KEYS), None);
}

#[test]
fn seeded_operation_mix_matches_an_ordered_map_model() {
    const KEY_SPACE: u64 = if cfg!(miri) { 200 } else { 3_000 };
    const STEPS: u64 = if cfg!(miri) { 4_000 } else { 200_000 };
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(16);
    let mut model = alloc::collections::BTreeMap::<u64, u64>::new();
    for step in 0..STEPS {
        let roll = next() % 10_000;
        let key = next() % KEY_SPACE;
        match roll {
            0..5_000 => assert_eq!(map.insert(key, step), model.insert(key, step)),
            5_000..7_500 => assert_eq!(map.remove(&key), model.remove(&key)),
            7_500..9_980 => assert_eq!(map.get(&key), model.get(&key)),
            9_980..9_988 => {
                let modulus = 2 + next() % 5;
                map.retain(|key, _| key % modulus != 0);
                model.retain(|key, _| key % modulus != 0);
            }
            9_988..9_992 => {
                let mut drained = map.drain().collect::<Vec<_>>();
                let expected = mem::take(&mut model).into_iter().collect::<Vec<_>>();
                drained.sort_unstable();
                assert_eq!(drained, expected);
            }
            9_992..9_995 => {
                map.clear();
                model.clear();
            }
            _ => map = map.clone(),
        }
        assert_eq!(map.len(), model.len());
        if step % 4_096 == 0 {
            for key in 0..KEY_SPACE {
                assert_eq!(map.get(&key), model.get(&key));
            }
            assert_eq!(map.iter().count(), model.len());
        }
    }
    for key in 0..KEY_SPACE {
        assert_eq!(map.get(&key), model.get(&key));
    }
}

/// Whether `level` is where the paper lets a key inserted under `target` go.
fn target_holds(target: BatchTarget, level: usize) -> bool {
    match target {
        BatchTarget::Bootstrap => level == 0,
        BatchTarget::LevelPair(current) => level == current || level == current + 1,
    }
}

#[test]
fn all_zero_and_all_one_hashes_place_inside_their_active_pair() {
    let capacities: &[usize] = if cfg!(miri) {
        &[256]
    } else {
        &[256, 2_048, 16_384]
    };
    for &capacity in capacities {
        let mut map =
            crate::ElasticHashMap::<u64, u64, IdentityBuildHasher>::with_capacity_and_hasher(
                capacity,
                IdentityBuildHasher,
            );
        let limit = map.capacity();
        for filler in 1..limit as u64 {
            if filler % (limit as u64 / 32) == 1 {
                for special in [0, u64::MAX] {
                    let mut probed = map.clone();
                    let table = probed.table();
                    let target = table.scheduler.target_at(table.len);
                    probed.insert(special, 0);
                    let table = probed.table();
                    let (level, _) = table.find(&special, special).unwrap();
                    assert!(
                        target_holds(target, level),
                        "hash {special:#x} after {} of {limit} keys: level {level}, {target:?}",
                        filler - 1
                    );
                    assert_eq!(table.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG, 0);
                    assert_eq!(probed.epoch().placement_recoveries, 0);
                }
            }
            map.insert(filler, filler);
        }
        assert_eq!(map.capacity(), limit);
    }
}

#[test]
fn the_fold_multiplier_as_a_hash_stays_findable_and_unflagged() {
    const KEY: u64 = probe::ELASTIC_FOLD_MULTIPLIER;
    let capacities: &[usize] = if cfg!(miri) {
        &[16, 64]
    } else {
        &[16, 256, 2_048]
    };
    for &capacity in capacities {
        let mut map =
            crate::ElasticHashMap::<u64, u64, IdentityBuildHasher>::with_capacity_and_hasher(
                capacity,
                IdentityBuildHasher,
            );
        let limit = map.capacity();
        for filler in 1..limit as u64 {
            let mut probed = map.clone();
            assert_eq!(probed.insert(KEY, 1), None);
            assert_eq!(probed.insert(KEY, 2), Some(1));
            assert_eq!(probed.len(), map.len() + 1);
            assert_eq!(probed.get(&KEY), Some(&2));
            for present in 1..filler {
                assert_eq!(probed.get(&present), Some(&present));
            }
            assert_eq!(
                probed.table().probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG,
                0
            );
            assert_eq!(probed.epoch().placement_recoveries, 0);
            assert_eq!(probed.remove(&KEY), Some(2));
            assert_eq!(probed.get(&KEY), None);
            map.insert(filler, filler);
        }
    }
}

#[test]
fn settled_gate_is_the_batch_window_under_the_insertion_limit() {
    for (slots, shifted) in [(1_024, true), (1_000, false), (4_096, true)] {
        let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                slots,
                ReserveFraction::DEFAULT,
                fixed_hasher(),
                Global,
            )
            .unwrap();
        assert_eq!(table.levels[0].index_shift() != GENERAL_REDUCTION, shifted);
        let mut settled_inserts = 0;
        for key in 0..table.max_insertions as u64 {
            for len in [table.len.saturating_sub(1), table.len, table.len + 1] {
                assert_eq!(
                    table.scheduler.settles(len),
                    shifted && len < table.max_insertions && table.scheduler.covers(len)
                );
            }
            settled_inserts += usize::from(table.scheduler.settles(table.len));
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.insert(key, key, hash), None);
        }
        assert!(!table.scheduler.settles(table.len));
        assert_eq!(settled_inserts > table.max_insertions / 2, shifted);
        assert_eq!(settled_inserts == 0, !shifted);
    }
}
