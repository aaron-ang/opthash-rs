use super::*;

use core::hash::{BuildHasher, Hasher};
use core::mem::ManuallyDrop;
use core::num::{NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::exact::reference::{ScalarElastic, ScalarElasticLimits};
use crate::map::TableBackend;
use crate::raw::control::CTRL_TOMBSTONE;
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

/// A table and the scalar paper model, stepped together.
struct ExactTrace {
    table: ElasticTable<u64, u64, IdentityBuildHasher>,
    scalar: ScalarElastic<CounterPrf>,
}

fn assert_exact_trace(n: usize, reserve_exponent: u32, identities: impl IntoIterator<Item = u64>) {
    let mut trace = ExactTrace::new(n, reserve_exponent);
    for identity in identities {
        trace.insert(identity);
    }
}

impl ExactTrace {
    fn new(n: usize, reserve_exponent: u32) -> Self {
        let reserve = ReserveFraction::from_exponent(reserve_exponent).unwrap();
        let config = PaperConfig::new(n, reserve_exponent).unwrap();
        let plan = config.elastic_plan();
        let table = ElasticTable::<u64, u64, IdentityBuildHasher>::
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
            NonZeroUsize::new(ELASTIC_PROBE_BUDGET_C as usize).unwrap(),
            NonZeroU32::new(probe::RANGE_WORD_CAP).unwrap(),
            NonZeroU64::new(UNIFORM_SEARCH_CAP).unwrap(),
            NonZeroU128::new(QUERY_POSITION_CAP).unwrap(),
        );
        let scalar = ScalarElastic::new(config, CounterPrf::new(ELASTIC_PROBE_SEED), limits);
        Self { table, scalar }
    }

    /// Inserts `identity` into both and returns the level it went to.
    fn insert(&mut self, identity: u64) -> usize {
        let Self { table, scalar } = self;
        {
            let prepared = PreparedElasticRoute::new(identity);
            assert_eq!(table.hash_builder.hash_one(identity), identity);
            assert!(table.live() < table.max_insertions);
            let target = table.scheduler.target(table.live());
            let placement = table
                .choose_slot_for_new_key(prepared.probe, target)
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
                    control::control_fingerprint_low(identity),
                    placement,
                ),
                (placement.level, placement.slot)
            );
            assert_eq!(
                table
                    .levels
                    .iter()
                    .map(|level| table.live_in(level) as usize)
                    .collect::<Vec<_>>(),
                scalar.level_occupancy()
            );
            assert_eq!(
                table.find_slot_indices_prepared(
                    &identity,
                    prepared,
                    control::control_fingerprint_low(identity),
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
            placement.level
        }
    }

    /// Removes `identity` from both.
    fn remove(&mut self, identity: u64) {
        let prepared = PreparedElasticRoute::new(identity);
        let location = self
            .table
            .find_slot_indices_prepared(
                &identity,
                prepared,
                control::control_fingerprint_low(identity),
            )
            .unwrap();
        assert_eq!(
            map::TableBackend::remove(&mut self.table, location),
            (identity, identity)
        );
        self.scalar.remove(identity);
        assert_eq!(
            self.table
                .levels
                .iter()
                .map(|level| self.table.live_in(level) as usize)
                .collect::<Vec<_>>(),
            self.scalar.level_occupancy()
        );
    }
}

/// An insert-only trace ends each batch as its current level turns low, so
/// it never places with that level low. Filling a batch and then removing
/// a key of the next level leaves the table inside the batch with the
/// current level exactly at its threshold and the next level above its
/// own.
#[test]
fn elastic_placement_matches_the_scalar_model_with_the_current_level_low() {
    let mut low_placements = 0;
    for &(n, reserve_exponent) in &[(64, 1), (128, 2)] {
        let mut trace = ExactTrace::new(n, reserve_exponent);
        let batch_ends = trace.table.scheduler.batch_ends.clone();
        let mut identity = 0;
        let mut level_of = Vec::new();
        for batch in 1..batch_ends.len() {
            let current = batch - 1;
            while trace.table.live() < batch_ends[batch] {
                level_of.push((identity, trace.insert(identity)));
                identity += 1;
            }
            let level = &trace.table.levels[current];
            let free = level.capacity() - trace.table.live_in(level) as usize;
            let threshold = level.half_reserve as usize;
            // Only a threshold of two or more tells itself from its half.
            if free != threshold || threshold < 2 {
                continue;
            }
            let other = level_of
                .iter()
                .position(|&(_, level)| level == batch)
                .unwrap();
            trace.remove(level_of.swap_remove(other).0);
            assert_eq!(
                trace.table.scheduler.target_at(trace.table.live()),
                BatchTarget::LevelPair(current)
            );
            let placed = trace.insert(identity);
            assert_eq!(placed, batch);
            level_of.push((identity, placed));
            identity += 1;
            low_placements += 1;
        }
    }
    assert!(low_placements > 0);
}

#[test]
fn settled_limit_is_zero_without_the_bounds_a_settled_insert_assumes() {
    type Table = ElasticTable<u64, u64, FixedHashBuilder>;
    let table = |slots| {
        Table::try_with_slots_and_reserve_fraction_and_hasher_in(
            slots,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap()
    };
    let shifted = table(32);
    let levels = &shifted.levels;
    assert_ne!(levels[0].index_shift(), GENERAL_REDUCTION);
    assert_ne!(shifted.membership.words, 0);
    assert_eq!(
        settled_limit(levels, levels.len(), shifted.membership, 7),
        7
    );
    // A batch past the last level pair.
    assert_eq!(
        settled_limit(levels, levels.len() + 1, shifted.membership, 7),
        0
    );
    // No filter word to record in.
    assert_eq!(
        settled_limit(levels, levels.len(), MembershipRegion::EMPTY, 7),
        0
    );
    // No level zero.
    assert_eq!(settled_limit(&levels[..0], 0, shifted.membership, 7), 0);
    let general = table(3);
    assert_eq!(general.levels[0].index_shift(), GENERAL_REDUCTION);
    assert_eq!(
        settled_limit(&general.levels, general.levels.len(), general.membership, 7),
        0
    );
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
            // The route tests and closes its own level's bit, one above the
            // level, and no other.
            let bit = 2_u64 << level;
            let step = route.as_step();
            assert!(step.is_closed(bit) && !step.is_closed(!bit));
            assert_eq!(step.close(0), bit);
            assert_eq!(step.sequence_index(), route.sequence_index());
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
    assert_eq!(map.table().levels[first_occupied.0].tombstones(), 1);
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
        map.table().live_in(level) as usize
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
fn caught_hash_panic_during_a_filter_refresh_keeps_every_entry_reachable() {
    const LIVE: u64 = 55;
    const CHURNED: u64 = LIVE;
    let armed = Arc::new(AtomicBool::new(false));
    let never = Arc::new(AtomicBool::new(false));
    let key_drops = Arc::new(AtomicUsize::new(0));
    let key = |id: u64| PanicHashKey {
        id,
        // The churned key is hashed by its own removal, so it stays unarmed.
        armed: if id == CHURNED {
            never.clone()
        } else {
            armed.clone()
        },
        drops: key_drops.clone(),
    };
    let mut map = FixedElasticHashMap::<PanicHashKey, u64>::with_capacity(56);
    let capacity = map.capacity();
    for id in 0..LIVE {
        map.insert(key(id), id);
    }
    let generation = map.epoch().generation;

    // Churn one key until a removal refreshes the filter, which hashes the
    // armed live keys.
    let mut unwound = false;
    for _ in 0..=2 * capacity {
        map.insert(key(CHURNED), CHURNED);
        armed.store(true, Ordering::SeqCst);
        let result = catch_unwind(AssertUnwindSafe(|| map.remove(&key(CHURNED))));
        armed.store(false, Ordering::SeqCst);
        if result.is_err() {
            unwound = true;
            break;
        }
    }
    assert!(unwound);
    // The refresh, not a rebuild, is what unwound.
    assert_eq!(map.epoch().generation, generation);

    assert_eq!(map.len() as u64, LIVE);
    assert!(map.get(&key(CHURNED)).is_none());
    for id in 0..LIVE {
        assert_eq!(map.get(&key(id)), Some(&id));
    }

    // The table keeps working: the next refresh re-records the filter.
    for _ in 0..=2 * capacity {
        map.insert(key(CHURNED), CHURNED);
        assert_eq!(map.remove(&key(CHURNED)), Some(CHURNED));
    }
    for id in 0..LIVE {
        assert_eq!(map.remove(&key(id)), Some(id));
    }
    assert!(map.is_empty());
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
        map.table().live_in(level) as usize
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

/// A rebuild that unwinds part way puts back levels whose settled inserts
/// stood uncounted when it began, and they still count.
#[test]
fn caught_hash_panic_during_a_rebuild_keeps_uncounted_settled_inserts() {
    let panic = Arc::new(AtomicBool::new(false));
    let never = Arc::new(AtomicBool::new(false));
    let key_drops = Arc::new(AtomicUsize::new(0));
    // Half the keys unwind, so the rebuild places some before it does.
    let key = |id: u64| PanicHashKey {
        id,
        armed: if id.is_multiple_of(2) {
            never.clone()
        } else {
            panic.clone()
        },
        drops: key_drops.clone(),
    };
    let mut map = FixedElasticHashMap::<PanicHashKey, u64>::with_capacity(32);
    for id in 0..16_u64 {
        map.insert(key(id), id);
    }
    let live_matches_controls = |map: &FixedElasticHashMap<PanicHashKey, u64>| {
        let table = map.table();
        table.levels.iter().all(|level| {
            table.live_in(level) as usize
                == (0..level.capacity())
                    .filter(|&slot| control::is_occupied(level.checked_control(slot)))
                    .count()
        })
    };
    assert_ne!(map.table().uncounted.pending(map.table().placed), 0);
    assert!(live_matches_controls(&map));

    panic.store(true, Ordering::SeqCst);
    let result = catch_unwind(AssertUnwindSafe(|| map.try_reserve(4_096)));
    assert!(result.is_err());
    panic.store(false, Ordering::SeqCst);

    assert_eq!(map.len(), 16);
    assert_ne!(map.table().uncounted.pending(map.table().placed), 0);
    assert!(live_matches_controls(&map));
    for id in 16..24_u64 {
        map.insert(key(id), id);
    }
    assert!(live_matches_controls(&map));
    for id in 0..24_u64 {
        assert_eq!(map.get(&key(id)), Some(&id));
    }
}

#[test]
fn level_counters_sit_ahead_of_their_control_bytes_without_overlap() {
    for capacity in [1, 2, 7, 56, 300, 1792, 5000] {
        let mut table =
            ElasticTable::<u64, u64, FixedHashBuilder>::with_capacity_and_reserve_and_hasher_in(
                capacity,
                ReserveFraction::DEFAULT,
                fixed_hasher(),
                Global,
            );
        let layout =
            elastic_arena_layout::<u64, u64>(table.total_slots, table.levels.len()).unwrap();
        let base = table.arena.as_ptr().addr();
        let mut control_end = base;
        let mut data_end = base + layout.data_base_off;
        for level in &table.levels {
            let counters = ptr::from_ref(level.counters()).addr();
            assert!(counters >= control_end);
            assert_eq!(counters % mem::align_of::<LevelCounters>(), 0);
            assert_eq!(
                counters + mem::size_of::<LevelCounters>(),
                level.ctrl_ptr.addr()
            );
            control_end = level.ctrl_ptr.addr() + level.capacity();
            assert!(level.data_ptr.addr() >= data_end);
            data_end =
                level.data_ptr.addr() + level.capacity() * mem::size_of::<SlotEntry<u64, u64>>();
        }
        assert!(control_end <= base + layout.data_base_off);
        assert!(data_end <= base + layout.membership.offset);

        // Filling every level leaves each count equal to its occupancy, so
        // no control byte or entry was written over a counter.
        for key in 0..capacity as u64 {
            let hash = table.hash_key(&key);
            table.insert(key, key, hash);
        }
        for level in &table.levels {
            let occupied = (0..level.capacity())
                // SAFETY: the slot is in bounds.
                .filter(|&slot| control::is_occupied(unsafe { level.control_at(slot) }))
                .count();
            assert_eq!(table.live_in(level) as usize, occupied);
            assert_eq!(level.tombstones(), 0);
        }
        for key in 0..capacity as u64 {
            let hash = table.hash_key(&key);
            assert!(table.find(&key, hash).is_some());
        }
    }
}

#[test]
fn elastic_metadata_is_appended_without_moving_control_or_data() {
    fn assert_layout<K, V>() {
        for &slots in &[0, 1, 7, 8, 31, 256] {
            let levels = if slots == 0 { 0 } else { 3 };
            let extent = slots + counter_bytes(levels);
            let (base, data_offset) = arena::layout_for_extents::<K, V>(extent, extent).unwrap();
            let extended = elastic_arena_layout::<K, V>(slots, levels).unwrap();
            assert_eq!(extended.data_base_off, data_offset);
            if slots == 0 {
                assert_eq!(extended.layout.size(), 0);
                assert_eq!(extended.membership.words, 0);
            } else {
                assert_eq!(extended.membership.offset, base.size());
                assert_eq!(
                    extended.membership.words,
                    slots.div_ceil(FILTER_SLOTS_PER_WORD)
                );
                assert!(extended.layout.size() > base.size());
            }
        }
    }

    assert_layout::<u64, u64>();
    assert_layout::<Zst, Zst>();
    assert_layout::<OverAligned, OverAligned>();
    assert!(mem::size_of::<TailWord>() <= 4 * FILTER_SLOTS_PER_WORD);

    let table =
        ElasticTable::<OverAligned, OverAligned, FixedHashBuilder>::with_capacity_and_reserve_and_hasher_in(
            64,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        );
    let layout =
        elastic_arena_layout::<OverAligned, OverAligned>(table.total_slots, table.levels.len())
            .unwrap();
    assert_eq!(
        table.membership_ptr().addr(),
        // SAFETY: the membership offset lies within the arena layout.
        unsafe { table.arena.as_ptr().add(layout.membership.offset) }.addr()
    );
    assert_eq!(
        table.membership_ptr().addr() % mem::align_of::<TailWord>(),
        0
    );
    for word in 0..table.membership.words {
        // SAFETY: `word < words` indexes an initialized metadata word.
        let metadata = unsafe { *table.membership_ptr().add(word) };
        assert_eq!(metadata.membership, 0);
        assert_eq!(metadata.level_bins, [NO_LEVELS_OCCUPIED; SUMMARY_BINS]);
    }
    assert_eq!(
        table.levels[0].data_ptr().addr() % mem::align_of::<OverAligned>(),
        0
    );
}

#[test]
fn batch_target_follows_the_live_count_in_both_directions() {
    let mut map: FixedElasticHashMap<usize, usize> = FixedElasticHashMap::with_capacity(1024);
    let quota = map.table().scheduler.batch_ends[0];
    assert!(quota > 0);

    for key in 0..quota {
        map.insert(key, key);
    }
    // The inserts so far were bootstrap placements; the next opens the
    // first level pair and moves the cached batch with it.
    assert_eq!(map.table().scheduler.current_batch_index, 0);
    map.insert(quota, quota);
    assert!(map.table().scheduler.current_batch_index > 0);
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
    test_support::assert_deletes_past_threshold_refresh_filter_from::<
        ElasticTable<u64, u64, FixedHashBuilder>,
    >(
        |table, key| {
            let prepared = PreparedElasticRoute::new(table.hash_builder.hash_one(key));
            table.route_filter(prepared).maybe_present
        },
        ElasticTable::stale_membership,
        |threshold| threshold,
        // A removal drops its key's bit unless another live key may hold
        // it.
        |admitted, departed| assert!(admitted < departed),
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

/// Independent restatement of a key's place in a tail of `words` words, as
/// its word, its membership bits and its summary bin, kept here so a change
/// to the derivation has to be deliberate.
fn metadata_place_from_signature(signature: u64, words: usize) -> (usize, u64, usize) {
    let lane_bits = u128::from(u64::BITS);
    let fraction = lane_bits.pow(u32::try_from(MEMBERSHIP_BITS).unwrap());
    let reduction =
        (u128::from(signature) * u128::try_from(words).unwrap() * fraction) >> u64::BITS;
    let mut bits = 0;
    let mut field = reduction % fraction;
    let mut top_field = 0;
    for _ in 0..MEMBERSHIP_BITS {
        top_field = field % lane_bits;
        bits |= 1_u64 << top_field;
        field /= lane_bits;
    }
    let bin = top_field / (lane_bits / u128::try_from(SUMMARY_BINS).unwrap());
    (
        usize::try_from(reduction / fraction).unwrap(),
        bits,
        usize::try_from(bin).unwrap(),
    )
}

#[test]
fn a_place_builds_its_bits_and_their_pairs_in_one_rotation() {
    // Every lane bit index, under a word index and without one.
    for reduction in (0..u64::from(u64::BITS)).flat_map(|bit| [bit, bit | (5 << 6)]) {
        let place = MetadataPlace { reduction };
        assert_eq!(
            place.bits_with_pair(),
            place.bits() | paired_bits(place.bits()),
            "reduction {reduction:#x}"
        );
        assert_eq!(paired_bits(paired_bits(place.bits())), place.bits());
    }
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
    assert_eq!(expand_level_mask(0), 0);
    assert_eq!(expand_level_mask(0b101), 0b101);
    assert_eq!(
        expand_level_mask(1 << (ROUTE_SUMMARY_LEVELS - 1)),
        u64::MAX << (ROUTE_SUMMARY_LEVELS - 1)
    );
    let level_limit = usize::try_from(probe::ELASTIC_LEVEL_LIMIT).unwrap();
    for level in 0..level_limit {
        let recorded = expand_level_mask(1 << summary_level(level));
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
        let prepared = PreparedElasticRoute::new(key);
        let mask = map.table().route_filter(prepared).level_mask();
        assert!(mask != 0, "key {key} has no level recorded");
        assert!(
            mask.count_ones() < u32::try_from(ROUTE_SUMMARY_LEVELS).unwrap(),
            "key {key} mask {mask:#x} must exclude at least one level"
        );
        assert_eq!(map.get(&key), Some(&key));
    }
    assert_eq!(map.get(&(key_count + 1)), None);
}

#[test]
fn metadata_place_matches_its_restatement() {
    for hash in (0..16_384_u64).map(|value| value.rotate_left(19) ^ value.rotate_left(51)) {
        let signature = PreparedElasticRoute::new(hash).signature();
        // The last two are the largest counts whose scale keeps every bit.
        let most = usize::MAX >> PLACE_FRACTION_BITS;
        for words in [1_usize, 3, 17, 257, 65_537, most - 1, most] {
            let place = MetadataPlace::new(signature, MetadataPlace::scale(words));
            assert!(place.word() < words);
            assert_eq!(
                (place.word(), place.bits(), place.summary_bin()),
                metadata_place_from_signature(signature, words),
                "signature {signature:#x} over {words} words"
            );
        }
    }
}

#[test]
fn elastic_controls_keep_the_public_hash_fingerprint() {
    let hash = 1_u64;
    let prepared = PreparedElasticRoute::new(hash);
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(64, IdentityBuildHasher);

    map.insert(hash, 7);
    let location = map
        .table()
        .find_slot_indices_prepared(&hash, prepared, control::control_fingerprint_low(hash))
        .unwrap();

    assert_eq!(
        map.table().levels[location.0].checked_control(location.1),
        control::control_fingerprint_low(hash)
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
        let prepared = PreparedElasticRoute::new(key);
        assert_ne!(
            map.table().route_filter(prepared).level_mask() & (1 << summary_level(level_index)),
            0,
            "key {key} at level {level_index}"
        );
        assert_eq!(map.get(&key), Some(&(key ^ 0x55)));
    }
    assert!(
        map.table()
            .levels
            .iter()
            .filter(|level| map.table().live_in(level) != 0)
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
    for word in 0..map.table().membership.words {
        assert_eq!(
            // SAFETY: `word < words` indexes an initialized metadata word.
            unsafe { (*map.table().membership_ptr().add(word)).level_bins },
            [NO_LEVELS_OCCUPIED; SUMMARY_BINS]
        );
    }
}

#[test]
fn membership_filter_holds_a_live_hash_and_forgets_a_lone_removed_one() {
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(64, IdentityBuildHasher);
    let inserted_hash = map.table().hash_builder.hash_one(7_u64);
    let prepared = PreparedElasticRoute::new(inserted_hash);
    assert!(!map.table().route_filter(prepared).maybe_present);

    assert_eq!(map.insert(7, 11), None);
    assert!(map.table().route_filter(prepared).maybe_present);

    assert_eq!(map.insert(7, 13), Some(11));
    assert_eq!(map.len(), 1);
    assert!(map.table().route_filter(prepared).maybe_present);

    // No other key is live, so none holds the removed key's bit.
    assert_eq!(map.remove(&7), Some(13));
    assert!(!map.table().route_filter(prepared).maybe_present);
    assert_eq!(map.get(&7), None);

    assert_eq!(map.insert(7, 17), None);
    assert!(map.table().route_filter(prepared).maybe_present);
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
        assert!(
            map.table()
                .route_filter(PreparedElasticRoute::new(key))
                .maybe_present
        );
    }
}

#[test]
fn prepared_membership_remains_valid_across_growth() {
    let key = 0xD1B5_4A32_D192_ED03_u64;
    let prepared = PreparedElasticRoute::new(key);
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(1, IdentityBuildHasher);

    map.insert(key, 7);
    assert!(map.table().route_filter(prepared).maybe_present);
    let old_slots = map.table().total_slots;

    map.reserve(1_024);
    assert!(map.table().total_slots > old_slots);
    assert!(map.table().route_filter(prepared).maybe_present);
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
        assert!(
            cloned
                .table()
                .route_filter(PreparedElasticRoute::new(hash))
                .maybe_present
        );
        assert_eq!(cloned.get(&key), Some(&(key ^ 0x55)));
    }

    cloned.clear();
    for key in 0_u64..96 {
        let hash = cloned.table().hash_builder.hash_one(key);
        assert!(
            !cloned
                .table()
                .route_filter(PreparedElasticRoute::new(hash))
                .maybe_present
        );
    }

    for key in 256_u64..384 {
        cloned.insert(key, key);
    }
    cloned.reserve(512);
    for key in 256_u64..384 {
        let hash = cloned.table().hash_builder.hash_one(key);
        assert!(
            cloned
                .table()
                .route_filter(PreparedElasticRoute::new(hash))
                .maybe_present
        );
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
        assert!(
            map.table()
                .route_filter(PreparedElasticRoute::new(hash))
                .maybe_present
        );
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
        assert!(
            map.table()
                .route_filter(PreparedElasticRoute::new(hash))
                .maybe_present
        );
        assert_eq!(map.get(&key), Some(&key));
    }

    map.drain().for_each(drop);
    assert!(map.is_empty());
    for key in 0_u64..64 {
        let hash = map.table().hash_builder.hash_one(key);
        assert!(
            !map.table()
                .route_filter(PreparedElasticRoute::new(hash))
                .maybe_present
        );
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
        assert!(
            map.table()
                .route_filter(PreparedElasticRoute::new(hash))
                .maybe_present
        );
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
    let fingerprint = control::control_fingerprint_low(0);
    let prepared = PreparedElasticRoute::new(0);
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
                    let counters = table.levels[level].counters_mut();
                    table.uncounted.count_one(&mut counters.len);
                    table.placed += 1;
                    *next_key += 1;
                }
            }
        }
    };
    block_every_route(&mut table, &mut next_key);
    assert!(table.live() < table.max_insertions);
    assert!(
        table
            .choose_slot_for_new_key(prepared.probe, BatchTarget::Bootstrap)
            .is_none()
    );
    assert!(
        table
            .choose_slot_on_other_targets(prepared.probe, BatchTarget::Bootstrap)
            .is_none()
    );

    let before = table.epoch.snapshot(table.live());
    let location = table.insert_for_vacant_entry(u64::MAX, 7, 0);
    let after = table.epoch.snapshot(table.live());
    assert_eq!(after.generation, before.generation + 1);
    assert_eq!(after.placement_recoveries, before.placement_recoveries + 1);
    assert_eq!(after.transition, EpochTransition::PlacementRecovery);
    assert_ne!(table.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG, 0);
    assert!(table.route_filter(prepared).maybe_present);
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
    assert!(table.live() < table.max_insertions);
    let before = table.epoch.snapshot(table.live());
    let location = table.insert_for_vacant_entry(u64::MAX - 1, 8, 0);
    let after = table.epoch.snapshot(table.live());
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
        && !table
            .levels
            .iter()
            .skip(1)
            .any(|level| table.live_in(level) > 0)
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
        table
            .levels
            .iter()
            .skip(1)
            .any(|level| table.live_in(level) > 0),
        "test must exercise lookup beyond level 0"
    );

    for key in 0..insertion_count {
        let hash = table.hash_builder.hash_one(key);
        let prepared = PreparedElasticRoute::new(hash);
        let fingerprint = control::control_fingerprint_low(hash);
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
    let prepared = PreparedElasticRoute::new(hash);
    let fingerprint = control::control_fingerprint_low(hash);
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
                    PreparedElasticRoute::new(hash),
                    control::control_fingerprint_low(hash),
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
                    PreparedElasticRoute::new(hash),
                    control::control_fingerprint_low(hash),
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

    let len = table.live();
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
    let live = table.live();
    table.max_insertions = live;
    table.placed = live;
    table.scheduler.rearm(membership::refresh_deletes(live));
    table.scheduler.settled_limit = live;
    table.scheduler.sync(live);
    let previous_slots = table.total_slots;

    let key = bootstrap_quota;
    let hash = table.hash_builder.hash_one(key);
    table.insert_for_vacant_entry(key, key, hash);

    assert!(table.total_slots > previous_slots);
    let len = table.live();
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
        map.table()
            .levels
            .iter()
            .skip(1)
            .any(|level| map.table().live_in(level) > 0),
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
    assert!(
        map.table()
            .levels
            .iter()
            .all(|level| map.table().live_in(level) == 0)
    );
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
    while !map
        .table()
        .levels
        .iter()
        .skip(1)
        .any(|level| map.table().live_in(level) > 0)
    {
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
        ELASTIC_PROBE_BUDGET_C as usize,
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
            || table.levels[LEVEL].free_slots(table.live_in(&table.levels[LEVEL]))
                == level_slots / 16
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
        let counters = table.levels[LEVEL].counters_mut();
        table.uncounted.count_one(&mut counters.len);
        table.placed += 1;
        next_key += 1;
    }
    assert!(
        (0..reachable).all(|index| {
            let slot = table.route_exact(LEVEL, key_hash, index).unwrap();
            !control::is_free(table.levels[LEVEL].checked_control(slot))
        }),
        "every reachable probe must be occupied"
    );

    let prepared = PreparedElasticRoute::new(key_hash);
    let placement = table
        .choose_slot_for_new_key(prepared.probe, BatchTarget::LevelPair(LEVEL))
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
        let word = PreparedElasticRoute::new(hash)
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
        let prepared = PreparedElasticRoute::new(map.table().hash_builder.hash_one(key));
        let filter = map.table().route_filter(prepared);
        assert!(!filter.maybe_present);
        assert_eq!(filter.level_mask(), 0);
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
            .rposition(|level| table.live_in(level) > 0)
            .unwrap();
        assert!(deepest < table.scheduled_levels as usize);
        if table.scheduled_levels != scheduled_levels {
            assert_eq!(table.scheduled_levels as usize, deepest + 1);
            assert_eq!(table.live_in(&table.levels[deepest]), 1);
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
    let len = table.live();
    for key in 0..keys {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(table.insert(key, key ^ 0xff, hash), Some(key));
        assert_eq!(table.find_value(&key, hash), Some(&(key ^ 0xff)));
    }
    assert_eq!(table.live(), len);
    let hash = table.hash_builder.hash_one(keys);
    assert_eq!(table.insert(keys, 1, hash), None);
    assert_eq!(table.live(), len + 1);
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
    table.probe_high_water |= EXCEPTIONAL_PLACEMENT_FLAG | WALK_UNRESOLVED_FLAG;
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
            let prepared = PreparedElasticRoute::new(hash);
            let fingerprint = control::control_fingerprint_low(hash);
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
                    filter.expanded_level_mask(),
                    fingerprint,
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
        let probe = PreparedElasticRoute::new(table.hash_builder.hash_one(key)).probe;
        if let Some((level, slot, control)) = table.settled_slot(probe) {
            // SAFETY: the settled search returns a slot of `level`.
            assert_eq!(control, unsafe { table.levels[level].control_at(slot) });
            let target = table.scheduler.target_at(table.live());
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
        let probe = PreparedElasticRoute::new(table.hash_builder.hash_one(key)).probe;
        for level in 0..table.levels.len() {
            for budget in [0, 1, 2, 7, 64] {
                let region = &table.levels[level];
                // SAFETY: `region` is `level`, and level zero reduces by
                // shift, so every level does.
                let shifted = unsafe { table.first_shifted_vacancy(probe, level, region, budget) };
                assert_eq!(shifted, table.first_vacancy_general(probe, level, budget));
                if let Ok(budget @ 1..) = u16::try_from(budget) {
                    // SAFETY: as above, and the budget is not zero.
                    let settled = unsafe {
                        first_settled_vacancy(
                            probe.sequence(table.fold_multiplier),
                            ptr::from_ref(region).cast_mut(),
                            settled_word(region.summary_bit(), budget),
                        )
                    }
                    .map(|found| {
                        assert!(ptr::eq(found.level, region));
                        assert_eq!(found.summary_bit, region.summary_bit());
                        // SAFETY: the search returns a slot of `region`.
                        assert_eq!(found.control, unsafe {
                            i32::from(region.control_at(found.slot).cast_signed())
                        });
                        found.slot
                    });
                    assert_eq!(settled, shifted.map(|(slot, _)| slot));
                }
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

/// What the settled insert and the end of a walk read from a table instead
/// of deriving: each level's constants, the bounds the settled limit stands
/// for, and the flag that leaves a walk unresolved.
fn assert_cached_state_matches<S>(table: &ElasticTable<u64, u64, S>) {
    for (index, level) in table.levels.iter().enumerate() {
        assert_eq!(level.summary_bit(), 2 << summary_level(index));
        assert_eq!(level.sequence_run, probe::elastic_level_run(index));
        assert_eq!(
            level.half_reserve as usize,
            table.reserve_fraction.floor_half_reserved(level.capacity())
        );
    }
    let shifted = table
        .levels
        .first()
        .is_some_and(|level| level.index_shift() != GENERAL_REDUCTION);
    let settled_limit = table.scheduler.settled_limit;
    assert_eq!(
        settled_limit,
        if shifted { table.max_insertions } else { 0 }
    );
    if settled_limit != 0 {
        assert!(table.scheduler.batch_ends.len() <= table.levels.len());
        assert_ne!(table.membership.words, 0);
    }
    let exceptional = table.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG != 0;
    assert_eq!(
        table.probe_high_water & WALK_UNRESOLVED_FLAG != 0,
        settled_limit == 0 || exceptional
    );
}

#[test]
fn every_table_shape_caches_the_state_its_fast_paths_read() {
    let slot_counts = if cfg!(miri) { 1..=40 } else { 1..=2_100 };
    let mut settling = 0;
    for exponent in 1..=6 {
        let reserve = ReserveFraction::from_exponent(exponent).unwrap();
        for slots in slot_counts.clone() {
            let Ok(table) =
                ElasticTable::<u64, u64, _>::try_with_slots_and_reserve_fraction_and_hasher_in(
                    slots,
                    reserve,
                    fixed_hasher(),
                    Global,
                )
            else {
                continue;
            };
            assert_cached_state_matches(&table);
            settling += usize::from(table.scheduler.settled_limit != 0);
        }
    }
    assert!(settling > 0);
}

#[test]
fn schedule_addresses_the_levels_of_every_table_it_serves() {
    type Table = ElasticTable<u64, u64, FixedHashBuilder>;
    fn check(table: &Table) -> bool {
        assert!(table.probe_schedule.addresses(&table.levels));
        assert_cached_state_matches(table);
        for level in &table.levels {
            for slot in [0, level.capacity() - 1] {
                // SAFETY: the control bytes are this table's and the slot is
                // in bounds; neither pointer is read.
                let (scheduled, direct) = unsafe {
                    (
                        ProbeSchedule::entry_at::<SlotEntry<u64, u64>>(
                            table.probe_schedule.entry_origin(),
                            level.ctrl_ptr,
                            slot,
                        ),
                        level.slot_ptr(slot),
                    )
                };
                assert_eq!(scheduled, direct);
            }
        }
        let first = &table.levels[0];
        for slot in [0, first.capacity() - 1] {
            assert_eq!(
                ProbeSchedule::direct_entry::<SlotEntry<u64, u64>>(
                    table.probe_schedule.direct_reach().2,
                    slot,
                ),
                // SAFETY: the slot is in bounds; the pointer is not read.
                unsafe { first.slot_ptr(slot) },
            );
        }
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
        // A clone's schedule addresses its own levels, not its source's.
        assert!(!cloned.probe_schedule.addresses(&table.levels));
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
            let probe = PreparedElasticRoute::new(hash).probe;
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
        // The copy's walks start where the source's do.
        assert_ne!(source.probe_schedule.whole_groups().0, 0);
        assert_eq!(
            copy.probe_schedule.whole_groups(),
            source.probe_schedule.whole_groups()
        );
        assert_eq!(
            copy.probe_schedule.whole_runs(),
            source.probe_schedule.whole_runs()
        );
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
                    let target = table.scheduler.target_at(table.live());
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

/// Free slots of the table's level `level`.
fn free_in<K: Eq + Hash, V, S: BuildHasher>(table: &ElasticTable<K, V, S>, level: usize) -> usize {
    let level = &table.levels[level];
    level.free_slots(table.live_in(level))
}

/// Each level's counters against its control bytes, the table's live count
/// against the levels', and every stored route summary's sentinel bit.
fn assert_counters_match_controls(table: &ElasticTable<u64, u64, FixedHashBuilder>) {
    let mut live = 0;
    for level in &table.levels {
        let (mut occupied, mut tombstones) = (0, 0);
        for slot in 0..level.capacity() {
            // SAFETY: `slot` is below the level's capacity.
            let control = unsafe { level.control_at(slot) };
            occupied += usize::from(!control::is_free(control));
            tombstones += usize::from(control == crate::raw::control::CTRL_TOMBSTONE);
        }
        assert_eq!(table.live_in(level) as usize, occupied);
        assert_eq!(level.tombstones() as usize, tombstones);
        live += occupied;
    }
    assert_eq!(table.live(), live);
    // A walk stops at the sentinel only while every stored summary keeps
    // the sentinel's bit clear.
    for word in 0..table.membership.words {
        // SAFETY: `word < words` indexes an initialized metadata word.
        let metadata = unsafe { *table.membership_ptr().add(word) };
        for bin in metadata.level_bins {
            assert_eq!(u64::from(bin) & SENTINEL_BIT, 0);
        }
    }
}

#[test]
fn settled_inserts_match_an_ordered_map_model() {
    const STEPS: u64 = if cfg!(miri) { 1_500 } else { 60_000 };
    let slot_counts: &[usize] = if cfg!(miri) { &[256] } else { &[1_024, 4_096] };
    for &slots in slot_counts {
        let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                slots,
                ReserveFraction::DEFAULT,
                fixed_hasher(),
                Global,
            )
            .unwrap();
        assert_ne!(table.levels[0].index_shift(), GENERAL_REDUCTION);
        let key_space = table.max_insertions as u64 * 2;
        let mut model = alloc::collections::BTreeMap::<u64, u64>::new();
        let mut state = 0x2545_f491_4f6c_dd1d_u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let (mut settled, mut reused) = (0, 0);
        for step in 0..STEPS {
            let roll = next() % 100;
            let key = next() % key_space;
            let hash = table.hash_builder.hash_one(key);
            if roll < 55 {
                if model.len() == table.max_insertions && !model.contains_key(&key) {
                    continue;
                }
                let fresh = !model.contains_key(&key);
                let settles = fresh
                    && table
                        .scheduler
                        .would_settle(table.placed, table.stale_membership());
                let tombstones = |table: &ElasticTable<u64, u64, FixedHashBuilder>| {
                    table.levels.iter().map(Level::tombstones).sum::<u32>()
                };
                let before = tombstones(&table);
                assert_eq!(table.insert(key, step, hash), model.insert(key, step));
                if settles {
                    settled += 1;
                    reused += usize::from(tombstones(&table) < before);
                    assert!(
                        table
                            .route_filter(PreparedElasticRoute::new(hash))
                            .maybe_present
                    );
                }
            } else if roll < 85 {
                let removed = table
                    .find_for_entry(&key, hash)
                    .ok()
                    .map(|location| table.remove(location).1);
                assert_eq!(removed, model.remove(&key));
            }
            assert_eq!(table.find_value(&key, hash), model.get(&key));
            assert_eq!(table.live(), model.len());
            if step % 512 == 0 {
                assert_counters_match_controls(&table);
                for key in 0..key_space {
                    let hash = table.hash_builder.hash_one(key);
                    assert_eq!(table.find_value(&key, hash), model.get(&key));
                }
            }
        }
        assert_counters_match_controls(&table);
        assert!(settled > 0);
        assert!(reused > 0);
    }
}

#[test]
fn settled_gate_follows_the_live_count_through_a_clear_that_panicked() {
    const CAPACITY: usize = if cfg!(miri) { 120 } else { 900 };
    let full = FixedElasticHashMap::<u64, u64>::with_capacity(CAPACITY)
        .table()
        .max_insertions;
    let mut settled = 0;
    // The drain stops with the live count in an earlier batch than the one
    // the table filled to.
    for panic_at in [full / 2, full - full / 8, full - 2] {
        let drops = Arc::new(AtomicUsize::new(0));
        let value = || PanicOnNthDrop {
            drops: drops.clone(),
            panic_at,
        };
        let mut map = ManuallyDrop::new(FixedElasticHashMap::<u64, PanicOnNthDrop>::with_capacity(
            CAPACITY,
        ));
        for key in 0..full as u64 - 1 {
            map.insert(key, value());
        }
        assert!(map.table().scheduler.current_batch_index > 0);

        let result = catch_unwind(AssertUnwindSafe(|| map.clear()));
        assert!(result.is_err());
        let table = map.table();
        assert_eq!(table.live(), full - 1 - panic_at - 1);
        // Every entry the clear took closed the gate behind it.
        assert!(!table.scheduler.settles(table.placed));
        assert_eq!(
            table
                .scheduler
                .would_settle(table.placed, table.stale_membership()),
            table.scheduler.covers(table.live())
        );

        let follow_ups = full as u64..full as u64 + if cfg!(miri) { 20 } else { 100 };
        for key in follow_ups {
            let table = map.table();
            assert!(!table.scheduler.settles(table.placed) || table.scheduler.covers(table.live()));
            assert_eq!(
                table
                    .scheduler
                    .would_settle(table.placed, table.stale_membership()),
                table.scheduler.covers(table.live())
            );
            let probe = PreparedElasticRoute::new(table.hash_builder.hash_one(key)).probe;
            let general = table
                .choose_slot_for_new_key(probe, table.scheduler.target_at(table.live()))
                .map(|placement| (placement.level, placement.slot));
            let settles = table
                .scheduler
                .would_settle(table.placed, table.stale_membership());
            map.insert(key, value());
            assert!(map.get(&key).is_some());
            if settles {
                // The insert itself took the slot the general placement
                // names.
                let table = map.table();
                let took = table.find(&key, table.hash_builder.hash_one(key));
                assert_eq!(took, general);
                settled += 1;
            }
        }

        map.clear();
        assert!(map.is_empty());
        // SAFETY: the map is not used again.
        unsafe { ManuallyDrop::drop(&mut map) };
    }
    assert!(settled > 0);
}

/// An insert settles exactly for a live count inside the cached batch and
/// under the insertion limit, and the gate is never open for another count.
fn assert_settled_gate(table: &ElasticTable<u64, u64, FixedHashBuilder>, shifted: bool) {
    let in_batch =
        shifted && table.live() < table.max_insertions && table.scheduler.covers(table.live());
    assert_eq!(
        table
            .scheduler
            .would_settle(table.placed, table.stale_membership()),
        in_batch
    );
    assert!(in_batch || !table.scheduler.settles(table.placed));
}

/// An open gate stands on the plan the table gives now, and ends no later
/// than that plan does.
fn assert_open_gate_is_the_plan(table: &ElasticTable<u64, u64, FixedHashBuilder>) {
    if !table.scheduler.settles(table.placed) {
        return;
    }
    let plan = table.settled_plan().expect("an open gate has a plan");
    assert_eq!(
        table.plan_words(plan.level, plan.budget, plan.fallback),
        // SAFETY: the gate is open.
        unsafe { table.open_words() }
    );
    assert!(table.scheduler.settled_end <= plan.end);
}

/// Past an insert the gate is open wherever the table has a plan, on that
/// plan, except where the insert was the last its plan held for.
fn assert_gate_past_an_insert(table: &ElasticTable<u64, u64, FixedHashBuilder>) {
    assert_open_gate_is_the_plan(table);
    assert!(
        table.scheduler.settles(table.placed)
            || table.scheduler.settled_end == table.placed
            || table.settled_plan().is_none()
    );
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
            assert_settled_gate(&table, shifted);
            settled_inserts += usize::from(table.scheduler.settles(table.placed));
            let hash = table.hash_builder.hash_one(key);
            assert_eq!(table.insert(key, key, hash), None);
        }
        assert!(!table.scheduler.settles(table.placed));
        assert_eq!(settled_inserts > table.max_insertions / 2, shifted);
        assert_eq!(settled_inserts == 0, !shifted);

        // Every removal shuts the gate. The insert after it reopens the gate
        // inside the cached batch and re-syncs the batch outside it.
        let full = table.max_insertions as u64;
        let mut reopened = 0;
        for key in 0..full {
            let hash = table.hash_builder.hash_one(key);
            let location = table.find_for_entry(&key, hash).ok().unwrap();
            assert_eq!(table.remove(location), (key, key));
            assert!(!table.scheduler.settles(table.placed));
            assert_settled_gate(&table, shifted);
            if key % 7 == 0 {
                let fresh = full + key;
                let hash = table.hash_builder.hash_one(fresh);
                assert_eq!(table.insert(fresh, fresh, hash), None);
                assert_settled_gate(&table, shifted);
                assert_gate_past_an_insert(&table);
                reopened += usize::from(table.scheduler.settles(table.placed));
            }
        }
        assert_eq!(reopened != 0, shifted);
    }
}

/// `take` against the search and the removal it fuses, on twin tables
/// through the same operations: present, absent and departed keys, on a
/// shape the walk resolves and on one it leaves to the general schedule,
/// past the removals that start maintenance.
#[test]
#[cfg_attr(miri, ignore)]
fn take_agrees_with_find_then_remove() {
    for (slots, shifted) in [(1_024, true), (1_000, false)] {
        let build = || {
            ElasticTable::<u64, u64, FixedHashBuilder>::
                try_with_slots_and_reserve_fraction_and_hasher_in(
                    slots,
                    ReserveFraction::DEFAULT,
                    fixed_hasher(),
                    Global,
                )
                .unwrap()
        };
        let (mut fused, mut split) = (build(), build());
        assert_eq!(fused.levels[0].index_shift() != GENERAL_REDUCTION, shifted);
        let capacity = fused.max_insertions as u64;
        let universe = capacity + capacity / 2;

        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut maintained = false;
        for step in 0..capacity * 12 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let key = (state >> 33) % universe;
            let hash = fused.hash_builder.hash_one(key);
            // Fill first, then remove more often than insert, then refill.
            let insert = match step / (capacity * 2) {
                0 | 3 => state >> 60 != 0,
                _ => state >> 62 == 0,
            };
            if insert {
                if fused.live() < fused.max_insertions && fused.find(&key, hash).is_none() {
                    assert_eq!(fused.insert(key, step, hash), None);
                    assert_eq!(split.insert(key, step, hash), None);
                }
            } else {
                let before = fused.stale_membership();
                let taken = fused.take(&key, hash);
                let removed = split
                    .find(&key, hash)
                    .map(|location| split.remove(location));
                assert_eq!(taken, removed);
                maintained |= taken.is_some() && fused.stale_membership() <= before;
            }
            assert_eq!(fused.live(), split.live());
            assert_eq!(fused.stale_membership(), split.stale_membership());
        }
        assert!(maintained, "removals never reached maintenance");

        assert_eq!(fused.epoch_snapshot(), split.epoch_snapshot());
        for (taken, removed) in fused.levels.iter().zip(&split.levels) {
            assert_eq!(fused.live_in(taken), split.live_in(removed));
            assert_eq!(taken.tombstones(), removed.tombstones());
        }
        for key in 0..universe {
            let hash = fused.hash_builder.hash_one(key);
            assert_eq!(fused.find(&key, hash), split.find(&key, hash));
            assert_eq!(
                fused.find_entry(&key, hash).map(|entry| entry.value),
                split.find_entry(&key, hash).map(|entry| entry.value)
            );
        }
    }
}

#[test]
fn settled_gate_closes_when_the_removal_count_starts_over() {
    let mut table =
        ElasticTable::<u64, u64, FixedHashBuilder>::try_with_slots_and_reserve_fraction_and_hasher_in(
            1_024,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
    let live = table.max_insertions as u64 / 2;
    for key in 0..live {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(table.insert(key, key, hash), None);
    }
    let hash = table.hash_builder.hash_one(0_u64);
    let location = table.find_for_entry(&0, hash).ok().unwrap();
    assert_eq!(table.remove(location), (0, 0));
    let hash = table.hash_builder.hash_one(live);
    assert_eq!(table.insert(live, live, hash), None);
    // The open gate counts the one removal the placed count holds.
    assert!(table.scheduler.settles(table.placed));
    assert_eq!(table.stale_membership(), 1);

    table.refresh_membership();
    assert_eq!(table.stale_membership(), 0);
    assert_eq!(table.live() as u64, live);
    assert!(!table.scheduler.settles(table.placed));
    assert_settled_gate(&table, true);
}

#[test]
fn reusing_a_tombstone_past_the_threshold_starts_a_cleanup_inside_the_batch() {
    let mut map = FixedElasticHashMap::<u64, u64>::with_capacity(1_024);
    // Stay in the bootstrap batch, which starts at zero: no removal can
    // take the live count out of it.
    let live = {
        let scheduler = &map.table().scheduler;
        assert_eq!(scheduler.current_batch_index, 0);
        scheduler.batch_end as u64 - 8
    };
    for key in 0..live {
        map.insert(key, key);
    }
    let threshold = {
        let level = &map.table().levels[0];
        assert_eq!(u64::from(map.table().live_in(level)), live);
        capacity::tombstone_cleanup_threshold(level.capacity()) as u64
    };
    let departed = threshold + 4;
    assert!(departed < live);
    for key in 0..departed {
        assert_eq!(map.remove(&key), Some(key));
    }
    assert!(map.table().levels[0].needs_cleanup());
    assert_eq!(map.epoch().generation, 0);

    // Insert until one lands on a tombstone. The level stays past its
    // threshold and the live count inside the batch throughout.
    let mut key = live;
    loop {
        let tombstones = map.table().levels[0].tombstones();
        map.insert(key, key);
        key += 1;
        let table = map.table();
        assert_eq!(map.epoch().generation, 0);
        assert_eq!(table.scheduler.current_batch_index, 0);
        if table.levels[0].tombstones() < tombstones {
            break;
        }
        assert!(key < live + 8, "no insert reused a tombstone");
    }
    assert!(map.table().levels[0].needs_cleanup());

    map.insert(key, key);
    let epoch = map.epoch();
    assert_eq!(epoch.generation, 1);
    assert_eq!(epoch.transition, EpochTransition::TombstoneCleanup);
    assert!(
        map.table()
            .levels
            .iter()
            .all(|level| level.tombstones() == 0)
    );
    for present in departed..=key {
        assert_eq!(map.get(&present), Some(&present));
    }
}

#[test]
fn a_scan_that_spends_the_delete_budget_refreshes_the_filter() {
    let mut map = FixedElasticHashMap::<u64, u64>::with_capacity(1_024);
    let live = map.capacity() as u64 / 2;
    for key in 0..live {
        map.insert(key, key);
    }
    let budget = membership::refresh_deletes(map.table().max_insertions);

    // Churn one key up to two removals short of the budget: the insert
    // retakes the tombstone, so no level nears its cleanup threshold.
    let churned = live;
    for _ in 0..budget - 2 {
        map.insert(churned, churned);
        assert_eq!(map.remove(&churned), Some(churned));
    }
    assert_eq!(map.table().stale_membership(), budget - 2);

    // The scan's removals spend the rest. No single removal runs
    // maintenance inside a scan, so the scan's end has to.
    map.retain(|key, _| *key >= 4);
    let table = map.table();
    assert!(!table.levels.iter().any(Level::needs_cleanup));
    assert_eq!(table.stale_membership(), 0);
    assert_eq!(map.epoch().generation, 0);
    assert_eq!(map.len() as u64, live - 4);
}

#[test]
#[should_panic(expected = "probe schedule outgrew its room")]
fn schedule_push_past_its_room_panics_instead_of_moving_the_routes() {
    let table =
        ElasticTable::<u64, u64, FixedHashBuilder>::try_with_slots_and_reserve_fraction_and_hasher_in(
            1_024,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
    let mut schedule = ProbeScheduleRoom::try_for_levels(table.levels.len())
        .unwrap()
        .schedule(&table.levels);
    for logical_probe_index in 1..LEVEL_PROBE_LIMIT[0] {
        schedule.push(&table.levels, 0, logical_probe_index);
    }
    assert!(schedule.addresses(&table.levels));
    // One past the last probe level zero's run has a slot for.
    schedule.push(&table.levels, 0, LEVEL_PROBE_LIMIT[0]);
}

#[test]
#[should_panic(expected = "probe schedule outgrew its room")]
fn schedule_push_past_every_route_panics_where_no_run_is_whole() {
    let mut table =
        ElasticTable::<u64, u64, FixedHashBuilder>::try_with_slots_and_reserve_fraction_and_hasher_in(
            1_024,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
    let last = table.levels.len() - 1;
    table.schedule_levels_through(last);
    table.extend_probe_schedule(QUERY_POSITION_CAP);
    assert_eq!(
        table.probe_schedule.routes().len(),
        table.probe_schedule.route_capacity()
    );
    assert_eq!(table.probe_schedule.whole_runs(), 0);
    table.probe_schedule.push(&table.levels, last, 0);
}

#[test]
fn removing_a_full_table_leaves_no_tombstone_for_lookups() {
    let mut map = FixedElasticHashMap::<u64, u64>::with_capacity(1_024);
    let live = map.capacity() as u64;
    for key in 0..live {
        map.insert(key, key);
    }
    assert_eq!(
        membership::refresh_deletes(map.table().max_insertions) as u64,
        live
    );
    for key in 0..live {
        assert_eq!(map.remove(&key), Some(key));
    }

    // The last removal spent the countdown, so maintenance ran with it.
    let table = map.table();
    assert_eq!(table.stale_membership(), 0);
    assert!(table.levels.iter().all(|level| level.tombstones() == 0));
    assert!((0..live).all(|key| {
        let prepared = PreparedElasticRoute::new(table.hash_builder.hash_one(key));
        !table.route_filter(prepared).maybe_present
    }));
}

#[test]
#[cfg_attr(miri, ignore)]
fn schedule_lookup_agrees_past_the_summary_width() {
    const SAMPLE_STRIDE: u64 = 4_099;
    const ABSENT_STRIDE: usize = 16;
    const SCATTER: u64 = 0x9E37_79B9_7F4A_7C15;
    const ABSENT: u64 = 1 << 63;
    // A thin reserve lets the fill reach the levels that share the
    // summary's last bit, and the ones past it.
    let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            1 << 18,
            ReserveFraction::from_exponent(17).unwrap(),
            fixed_hasher(),
            Global,
        )
        .unwrap();
    assert!(table.levels.len() > ROUTE_SUMMARY_LEVELS);
    let budget = table.max_insertions as u64;
    for key in 0..budget {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(table.insert(key, key, hash), None);
    }
    assert!(table.probe_schedule.addresses(&table.levels));
    // Otherwise every lookup below is the full scan.
    assert_eq!(table.probe_high_water & HIGH_WATER_FLAGS, 0);

    let saturated = ROUTE_SUMMARY_LEVELS - 1;
    let mut saturated_hits = 0;
    let mut hits_past_the_summary = 0;
    let mut deep_walked_misses = 0;
    let mut shallow_walked_misses = 0;
    let mut filtered_misses = 0;
    // A walk for an absent key the filter passes is the slow case, so the
    // absent keys are a sample.
    for index in (0..budget).chain((budget..2 * budget).step_by(ABSENT_STRIDE)) {
        // The absent keys are scattered: a run of consecutive ones folds
        // to places that interleave with the present run's, and then the
        // filter rejects nearly all of them.
        let key = if index < budget {
            index
        } else {
            index.wrapping_mul(SCATTER) | ABSENT
        };
        let hash = table.hash_builder.hash_one(key);
        let prepared = PreparedElasticRoute::new(hash);
        let fingerprint = control::control_fingerprint_low(hash);
        let scheduled = table.find_slot_indices_prepared(&key, prepared, fingerprint);
        assert_eq!(scheduled.is_some(), index < budget, "key {key}");
        let filter = table.route_filter(prepared);
        let mask = filter.expanded_level_mask();
        let deep_open = filter.maybe_present && mask >> saturated != 0;
        if filter.maybe_present {
            let walked = table.find_by_general_schedule(
                &key,
                prepared,
                mask,
                fingerprint,
                |level, slot, _| (level, slot),
            );
            assert_eq!(scheduled, walked, "key {key}");
        }
        let deep_hit = scheduled.is_some_and(|(level, _)| level >= saturated);
        if let Some((level, _)) = scheduled {
            assert_ne!(mask & (1 << level), 0, "key {key} level {level}");
            saturated_hits += usize::from(level == saturated);
            hits_past_the_summary += usize::from(level > saturated);
        } else if deep_open {
            deep_walked_misses += 1;
        } else if filter.maybe_present {
            shallow_walked_misses += 1;
        } else {
            filtered_misses += 1;
        }
        // The scan reads every slot, so it runs on the deep hits, the deep
        // walked misses and a sample of the rest.
        if deep_hit || deep_open || index % SAMPLE_STRIDE == 0 {
            let scanned =
                table.find_by_full_scan(&key, fingerprint, |level, slot, _| (level, slot));
            assert_eq!(scheduled, scanned, "key {key}");
        }
    }
    assert!(saturated_hits > 0 && hits_past_the_summary > 0);
    assert!(
        deep_walked_misses > 0 && shallow_walked_misses > 0 && filtered_misses > 0,
        "{deep_walked_misses} {shallow_walked_misses} {filtered_misses} {saturated_hits} \
         {hits_past_the_summary}"
    );
}

/// A settled insert against the general one, on twin tables through the
/// same inserts and removals, with an ordered map as the model: the plan
/// the gate opens on, through every case and budget the fill of a batch's
/// levels walks it through and every removal that closes it, puts each key
/// in the slot the paper's insertion case chooses afresh.
#[test]
#[cfg_attr(miri, ignore)]
fn settled_plan_places_every_key_where_the_general_insert_does() {
    use alloc::collections::BTreeMap;

    for slots in [1_024, 1 << 15] {
        let build = || {
            ElasticTable::<u64, u64, FixedHashBuilder>::
                try_with_slots_and_reserve_fraction_and_hasher_in(
                    slots,
                    ReserveFraction::DEFAULT,
                    fixed_hasher(),
                    Global,
                )
                .unwrap()
        };
        let (mut settled, mut general) = (build(), build());
        assert_ne!(settled.levels[0].index_shift(), GENERAL_REDUCTION);
        let mut model = BTreeMap::new();
        let capacity = settled.max_insertions as u64;
        let universe = capacity + capacity / 2;

        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let (mut through_gate, mut inserts) = (0_u64, 0_u64);
        for step in 0..capacity * 8 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let key = (state >> 33) % universe;
            let hash = settled.hash_builder.hash_one(key);
            // Fill, thin out, refill, then churn.
            let insert = match step / (capacity * 2) {
                0 | 2 => state >> 60 != 0,
                1 => state >> 62 == 0,
                _ => state >> 63 == 0,
            };
            if insert {
                if settled.live() == settled.max_insertions && !model.contains_key(&key) {
                    continue;
                }
                let absent = !model.contains_key(&key);
                through_gate += u64::from(absent && settled.scheduler.settles(settled.placed));
                inserts += u64::from(absent);
                let previous = model.insert(key, step);
                assert_eq!(settled.insert(key, step, hash), previous);
                if let Some(location) = general.find(&key, hash) {
                    assert_eq!(Some(general.replace_value(location, step)), previous);
                } else {
                    let prepared = PreparedElasticRoute::new(hash);
                    general.insert_for_vacant_entry_prepared(
                        key,
                        step,
                        prepared,
                        control::control_fingerprint_low(hash),
                    );
                }
                assert_open_gate_is_the_plan(&settled);
                assert_open_gate_is_the_plan(&general);
                if absent {
                    assert_gate_past_an_insert(&settled);
                    assert_gate_past_an_insert(&general);
                }
            } else {
                let removed = model.remove(&key);
                assert_eq!(settled.take(&key, hash).map(|(_, value)| value), removed);
                assert_eq!(general.take(&key, hash).map(|(_, value)| value), removed);
                assert!(!settled.scheduler.settles(settled.placed) || removed.is_none());
            }
            assert_eq!(settled.find(&key, hash), general.find(&key, hash));
            assert_eq!(settled.live(), model.len());
        }
        assert!(
            through_gate > inserts / 2,
            "{through_gate} of {inserts} inserts found the gate open"
        );

        assert_eq!(settled.epoch_snapshot(), general.epoch_snapshot());
        for (ours, theirs) in settled.levels.iter().zip(&general.levels) {
            assert_eq!(settled.live_in(ours), general.live_in(theirs));
            assert_eq!(ours.tombstones(), theirs.tombstones());
            assert_eq!(ours.scheduled_probes, theirs.scheduled_probes);
        }
        for key in 0..universe {
            let hash = settled.hash_builder.hash_one(key);
            assert_eq!(settled.find(&key, hash), general.find(&key, hash));
            assert_eq!(
                settled.find_entry(&key, hash).map(|entry| entry.value),
                model.get(&key).copied()
            );
        }
    }
}

/// Settled inserts count late into their level; the general insert counts
/// at once. Twin tables through the same inserts, removals, clears and
/// growth, one by each insert, read the same at every step: each level's
/// live count, which is also the count of its occupied control bytes, the
/// capacity, the epoch and every key's slot. So do copies taken while
/// inserts stand uncounted.
#[test]
fn late_counted_settled_inserts_read_as_counted_at_once() {
    const STEPS: u64 = if cfg!(miri) { 1_200 } else { 120_000 };
    type Table = ElasticTable<u64, u64, FixedHashBuilder>;
    let build = || {
        Table::try_with_slots_and_reserve_fraction_and_hasher_in(
            64,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap()
    };
    let (mut late, mut eager) = (build(), build());
    let mut model = alloc::collections::BTreeMap::<u64, u64>::new();
    let mut state = 0x853c_49e6_748f_ea9b_u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let uncounted = |table: &Table| table.uncounted.pending(table.placed);
    let (mut removed_under, mut cleared_under, mut copied_under) = (0_u32, 0_u32, 0_u32);
    let (mut grown, mut most_uncounted) = (0_u32, 0_u32);
    for step in 0..STEPS {
        let roll = next() % 1_000;
        // Past the capacity in the first half, so the tables grow; within
        // it in the second, so removals and reuse meet a full table.
        let key_space = if step < STEPS / 2 {
            late.max_insertions as u64 * 2
        } else {
            late.max_insertions as u64
        };
        let key = next() % key_space;
        let hash = late.hash_builder.hash_one(key);
        let slots = late.total_slots;
        if roll < 600 {
            let previous = model.insert(key, step);
            assert_eq!(late.insert(key, step, hash), previous);
            if let Some(location) = eager.find(&key, hash) {
                assert_eq!(Some(eager.replace_value(location, step)), previous);
            } else {
                eager.insert_for_vacant_entry_prepared(
                    key,
                    step,
                    PreparedElasticRoute::new(hash),
                    control::control_fingerprint_low(hash),
                );
            }
        } else if roll < 990 {
            removed_under += u32::from(uncounted(&late) != 0 && model.contains_key(&key));
            let removed = model.remove(&key);
            assert_eq!(late.take(&key, hash).map(|(_, value)| value), removed);
            assert_eq!(eager.take(&key, hash).map(|(_, value)| value), removed);
        } else if roll < 992 {
            cleared_under += u32::from(uncounted(&late) != 0);
            model.clear();
            late.clear();
            eager.clear();
        } else {
            copied_under += u32::from(uncounted(&late) != 0);
            let copy = late.clone_table();
            assert_eq!(uncounted(&copy), 0);
            assert_counters_match_controls(&copy);
            assert_eq!(copy.epoch_snapshot(), late.epoch_snapshot());
        }
        assert_eq!(uncounted(&eager), 0);
        most_uncounted = most_uncounted.max(uncounted(&late));
        grown += u32::from(late.total_slots > slots);
        assert_eq!(late.live(), model.len());
        assert_eq!(late.total_slots, eager.total_slots);
        assert_eq!(late.epoch_snapshot(), eager.epoch_snapshot());
        assert_eq!(late.find(&key, hash), eager.find(&key, hash));
        for (ours, theirs) in late.levels.iter().zip(&eager.levels) {
            assert_eq!(late.live_in(ours), eager.live_in(theirs));
            assert_eq!(ours.tombstones(), theirs.tombstones());
        }
        if step % 64 == 0 || step + 1 == STEPS {
            assert_counters_match_controls(&late);
            for (&key, &value) in &model {
                let hash = late.hash_builder.hash_one(key);
                let found = late.find(&key, hash);
                assert_eq!(found, eager.find(&key, hash));
                assert_eq!(
                    late.find_entry(&key, hash).map(|entry| entry.value),
                    Some(value)
                );
            }
        }
    }
    assert!(
        most_uncounted > 1,
        "no run of settled inserts stood uncounted"
    );
    assert!(removed_under > 0 && cleared_under > 0 && copied_under > 0);
    assert!(grown > 1, "the tables grew {grown} times");
}

#[test]
#[cfg_attr(miri, ignore)]
fn settled_fallback_ends_where_its_level_comes_down_to_a_quarter_free() {
    const BLOCK: usize = 64;
    type Table = ElasticTable<u64, u64, FixedHashBuilder>;

    let build = || {
        Table::try_with_slots_and_reserve_fraction_and_hasher_in(
            1 << 12,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap()
    };
    let (mut settled, mut general) = (build(), build());
    let hash_of = |key: u64| fixed_hasher().hash_one(key);
    let insert = |settled: &mut Table, general: &mut Table, key: u64| {
        let hash = hash_of(key);
        assert_eq!(settled.insert(key, key, hash), None);
        general.insert_for_vacant_entry_prepared(
            key,
            key,
            PreparedElasticRoute::new(hash),
            control::control_fingerprint_low(hash),
        );
        assert_eq!(settled.find(&key, hash), general.find(&key, hash));
        assert_gate_past_an_insert(settled);
        assert_gate_past_an_insert(general);
    };
    // What the pair's current level has free above half its reserve.
    let room = |table: &Table| free_in(table, 1) - table.levels[1].half_reserve as usize;
    let fallback_low = |table: &Table| free_in(table, 2) * 4 <= table.levels[2].capacity();

    // Far enough into the second pair of levels that its current level's
    // budget turns keys away.
    let mut next_key = 0_u64;
    while settled.scheduler.target_at(settled.live()) != BatchTarget::LevelPair(1)
        || room(&settled) > 8
    {
        insert(&mut settled, &mut general, next_key);
        next_key += 1;
    }
    assert!(!fallback_low(&settled));

    // Blocks of keys leave and as many arrive, so the batch never ends, and
    // they leave the current level only while it is near half its reserve,
    // so it stays as full while the keys it turns away fill the level after
    // it. The gate stays open through a block's arrivals.
    let mut live_keys: Vec<u64> = (0..next_key).collect();
    let mut fell_back = 0;
    let mut blocks_past_low = 0;
    while blocks_past_low < 8 {
        assert!(live_keys.len() < 1 << 16, "the fallback level never filled");
        blocks_past_low += usize::from(fallback_low(&settled));
        let mut left = 0;
        live_keys.retain(|&key| {
            let hash = hash_of(key);
            let from = usize::from(room(&settled) < 8 + BLOCK);
            let leaves = left < BLOCK
                && settled
                    .find(&key, hash)
                    .is_some_and(|(level, _)| level == from);
            if leaves {
                assert_eq!(settled.take(&key, hash), general.take(&key, hash));
                left += 1;
            }
            !leaves
        });
        assert_ne!(left, 0);
        for _ in 0..left {
            let before = settled.live_in(&settled.levels[2]);
            let through_fallback =
                settled.scheduler.settles(settled.placed) && !settled.settled_fallback.is_null();
            insert(&mut settled, &mut general, next_key);
            fell_back +=
                usize::from(through_fallback && settled.live_in(&settled.levels[2]) > before);
            live_keys.push(next_key);
            next_key += 1;
        }
        assert_eq!(
            settled.scheduler.target_at(settled.live()),
            BatchTarget::LevelPair(1)
        );
    }
    assert!(fell_back > 16, "{fell_back} keys fell back");

    for key in 0..next_key {
        let hash = hash_of(key);
        assert_eq!(settled.find(&key, hash), general.find(&key, hash));
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn settled_fallback_bound_holds_where_its_level_recrosses_a_quarter_free() {
    type Table = ElasticTable<u64, u64, FixedHashBuilder>;

    let build = || {
        Table::try_with_slots_and_reserve_fraction_and_hasher_in(
            1 << 12,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap()
    };
    let (mut settled, mut general) = (build(), build());
    let hash_of = |key: u64| fixed_hasher().hash_one(key);
    let insert = |settled: &mut Table, general: &mut Table, key: u64| {
        let hash = hash_of(key);
        assert_eq!(settled.insert(key, key, hash), None);
        general.insert_for_vacant_entry_prepared(
            key,
            key,
            PreparedElasticRoute::new(hash),
            control::control_fingerprint_low(hash),
        );
        assert_eq!(
            settled.find(&key, hash),
            general.find(&key, hash),
            "key {key}"
        );
        assert_gate_past_an_insert(settled);
    };
    // What the pair's current level has free above half its reserve, and
    // the level after it above a quarter of its slots.
    let room = |table: &Table| free_in(table, 1) - table.levels[1].half_reserve as usize;
    let margin = |table: &Table| free_in(table, 2).saturating_sub(table.levels[2].capacity() / 4);

    let mut next_key = 0_u64;
    while settled.scheduler.target_at(settled.live()) != BatchTarget::LevelPair(1)
        || room(&settled) > 8
    {
        insert(&mut settled, &mut general, next_key);
        next_key += 1;
    }

    // Keys leave the current level to keep it near half its reserve, the
    // level after it to keep it near a quarter free, and the first level to
    // keep the batch from ending, so the level after the current one comes
    // down to a quarter free again and again, under an open gate.
    let mut live_keys: Vec<u64> = (0..next_key).collect();
    let base_live = settled.live();
    let mut crossed_open = 0;
    for _ in 0..4_000 {
        let mut removed = 0_usize;
        live_keys.retain(|&key| {
            let hash = hash_of(key);
            let level = settled.find(&key, hash).unwrap().0;
            let leaves = (level == 1 && room(&settled) < 40)
                || (level == 2 && margin(&settled) < 2)
                || (level == 0 && settled.live() > base_live);
            if leaves {
                assert_eq!(settled.take(&key, hash), general.take(&key, hash));
                removed += 1;
            }
            !leaves
        });
        let was_above = margin(&settled) > 0;
        let mut open_through = true;
        for _ in 0..removed.max(8) {
            if room(&settled) <= 1 {
                break;
            }
            let open = settled.scheduler.settles(settled.placed);
            insert(&mut settled, &mut general, next_key);
            open_through &= open || settled.scheduler.settles(settled.placed);
            live_keys.push(next_key);
            next_key += 1;
        }
        crossed_open += usize::from(was_above && margin(&settled) == 0 && open_through);
        assert_eq!(
            settled.scheduler.target_at(settled.live()),
            BatchTarget::LevelPair(1)
        );
    }
    assert!(crossed_open > 4, "{crossed_open} crossings");
}

#[test]
fn settled_plan_stays_readable_past_a_replaced_value() {
    let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            1 << 8,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
    for key in 0..20_u64 {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(table.insert(key, key, hash), None);
    }
    assert!(table.scheduler.settles(table.placed));
    let hash = table.hash_builder.hash_one(3_u64);
    let location = table.find(&3, hash).unwrap();
    assert_eq!(map::TableBackend::replace_value(&mut table, location, 9), 3);
    // Replacing a value borrows the levels and leaves the gate open on the
    // plan the next inserts read.
    assert!(table.scheduler.settles(table.placed));
    for key in 100..110_u64 {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(table.insert(key, key, hash), None);
    }
    assert_eq!(table.find(&3, hash).map(|_| ()), Some(()));
}

#[test]
fn settled_plan_stays_readable_past_a_leaked_drain() {
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(256);
    for key in 0..20 {
        map.insert(key, key);
    }
    assert!(map.table().scheduler.settles(map.table().placed));
    // A drain tombstones the slot of each key it yields through a borrow of
    // the levels, and only its drop closes the gate.
    let mut drain = map.drain();
    let (taken, _) = drain.next().unwrap();
    mem::forget(drain);
    assert!(map.table().scheduler.settles(map.table().placed));
    for key in 100..110 {
        assert_eq!(map.insert(key, key), None);
    }
    for key in (0..20).chain(100..110) {
        assert_eq!(map.get(&key).is_some(), key != taken, "{key}");
    }
}

#[test]
fn rebuild_that_keeps_the_grouped_levels_writes_no_group_route_again() {
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            1 << 8,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
    let level_count = table.levels.len();
    let (whole, fitted) = table.probe_schedule.whole_groups();
    assert_eq!(whole, 0);
    assert_ne!(fitted, 0);
    assert!(level_count > schedule::GROUPED_LEVELS + 1);
    let unwritten = ProbeSchedule::group_appends();
    // A rebuild that first brings a grouped level in writes the groups'
    // runs from their start.
    for through in 0..schedule::GROUPED_LEVELS {
        table.schedule_levels_through(through);
        table.extend_probe_schedule(40 * (through as u128 + 1));
        assert!(table.probe_schedule.addresses(&table.levels));
        if through + 1 < schedule::GROUPED_LEVELS {
            assert_eq!(ProbeSchedule::group_appends(), unwritten);
        }
    }
    assert_eq!(table.probe_schedule.whole_groups().0, fitted);
    assert_ne!(ProbeSchedule::group_appends(), unwritten);
    for through in schedule::GROUPED_LEVELS..level_count {
        let held = ProbeSchedule::group_appends();
        // One that brings a deeper level in pushes the same routes of the
        // grouped levels, which the runs hold.
        table.schedule_levels_through(through);
        assert_eq!(ProbeSchedule::group_appends(), held);
        assert!(table.probe_schedule.addresses(&table.levels));
        // Only the routes past them are written.
        table.extend_probe_schedule(40 * (through as u128 + 1));
        assert!(table.probe_schedule.addresses(&table.levels));
    }
    assert_eq!(table.probe_schedule.whole_groups().0, fitted);
    let held = ProbeSchedule::group_appends();
    table.extend_probe_schedule(QUERY_POSITION_CAP);
    assert!(ProbeSchedule::group_appends() > held);
}

#[test]
fn rebuild_leaves_a_group_run_that_stopped_being_whole_as_it_is() {
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            1 << 8,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
    let fitted = table.probe_schedule.whole_groups().1;
    assert_ne!(fitted, 0);
    // Every route of the grouped levels is more than the groups' runs
    // have slots for.
    table.schedule_levels_through(schedule::GROUPED_LEVELS);
    table.extend_probe_schedule(QUERY_POSITION_CAP);
    let whole = table.probe_schedule.whole_groups().0;
    assert!(whole < fitted);
    assert!(table.probe_schedule.addresses(&table.levels));
    // The rebuild that brings the other levels in keeps the groups' runs.
    table.schedule_levels_through(table.levels.len() - 1);
    assert!(table.probe_schedule.whole_groups().0 <= whole);
    assert!(table.probe_schedule.addresses(&table.levels));
}

#[test]
fn clone_has_group_runs_only_where_its_source_has_one_whole() {
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            1 << 8,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
    let fitted = table.probe_schedule.whole_groups().1;
    assert_ne!(fitted, 0);
    table.schedule_levels_through(schedule::GROUPED_LEVELS - 2);
    table.extend_probe_schedule(40);
    // A source short of a grouped level gives its copy no group's run, and
    // the copy takes them when its own rebuild brings that level in.
    let held = ProbeSchedule::group_appends();
    let mut copy = table.clone_table();
    assert_eq!(copy.probe_schedule.whole_groups().0, 0);
    assert_eq!(ProbeSchedule::group_appends(), held);
    assert!(copy.probe_schedule.addresses(&copy.levels));
    copy.schedule_levels_through(copy.levels.len() - 1);
    assert_eq!(copy.probe_schedule.whole_groups().0, fitted);
    assert_ne!(ProbeSchedule::group_appends(), held);
    assert!(copy.probe_schedule.addresses(&copy.levels));
    // A source with whole groups gives its copy the same ones.
    table.schedule_levels_through(table.levels.len() - 1);
    assert_eq!(table.probe_schedule.whole_groups().0, fitted);
    let held = ProbeSchedule::group_appends();
    let copy = table.clone_table();
    assert_eq!(copy.probe_schedule.whole_groups().0, fitted);
    assert_ne!(ProbeSchedule::group_appends(), held);
    assert!(copy.probe_schedule.addresses(&copy.levels));
}

/// Model check of the walk starts: under every summary value, the routes
/// between a walk's start and its sentinel that the summary leaves open are
/// the pushed routes it leaves open, in the same order. The walk skips the
/// others and closes levels by what it probes, so it probes the same slots
/// from either start. Checked through a schedule's whole growth, where the
/// pushed routes take the runs' slots one level after another, and again
/// after the schedule is dropped and rebuilt.
#[test]
#[cfg_attr(miri, ignore)]
fn every_walk_start_leads_to_the_routes_its_summary_leaves_open() {
    for slots in [16, 64, 1_024, 1 << 15] {
        let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                slots,
                ReserveFraction::DEFAULT,
                IdentityBuildHasher,
                Global,
            )
            .unwrap();
        let level_count = table.levels.len();
        let assert_starts = |table: &ElasticTable<u64, u64, IdentityBuildHasher>| {
            let schedule = &table.probe_schedule;
            assert!(schedule.addresses(&table.levels));
            let mut groups = 0;
            for summary in SummaryBin::MIN..=SummaryBin::MAX {
                let closed = schedule::closed_levels(summary);
                let open = |route: &&PhiRoute| !route.as_step().is_closed(closed);
                let walked = schedule.walk_routes(summary);
                assert!(
                    walked
                        .iter()
                        .filter(open)
                        .eq(schedule.routes().iter().filter(open)),
                    "{slots} slots, summary {summary:#010b}"
                );
                // A summary that leaves at most one level open, and that a
                // level whose run is whole, has no route to skip.
                let open_levels = (0..level_count)
                    .filter(|&level| closed & (2 << level) == 0)
                    .collect::<Vec<_>>();
                let stored = summary & !NO_LEVELS_OCCUPIED == 0
                    && (level_count..ROUTE_SUMMARY_LEVELS).all(|level| summary & (2 << level) != 0);
                // So has one that leaves a group's levels open, and that
                // a group whose run is whole: the only walks of several
                // levels that do not start at the direct route.
                let grouped =
                    open_levels.len() > 1 && schedule.walk_start(summary) != schedule.walk_start(0);
                groups += u32::from(grouped);
                if stored
                    && (open_levels.is_empty()
                        || open_levels.len() == 1 && open_levels[0] < schedule.whole_runs()
                        || grouped)
                {
                    assert_eq!(walked.iter().filter(open).count(), walked.len());
                }
            }
            assert_eq!(groups, schedule.whole_groups().0);
            groups
        };

        let mut whole_runs_seen = alloc::vec![false; level_count + 1];
        let named = table.probe_schedule.named_levels();
        let fitted = table.probe_schedule.whole_groups().1;
        // Only a table with levels past the named ones has room for groups.
        assert_eq!(fitted != 0, named < level_count, "{slots} slots");
        for staged in [false, true] {
            let mut whole_groups_seen = alloc::vec![false; fitted as usize + 1];
            // Cleared, the schedule is empty and every run whole.
            table.probe_high_water &= HIGH_WATER_FLAGS;
            table.scheduled_levels = 0;
            table.probe_schedule.rewind(0);
            assert_eq!(table.probe_schedule.routes(), []);
            assert_eq!(table.probe_schedule.whole_runs(), named);
            assert_eq!(table.probe_schedule.whole_groups(), (0, fitted));
            let mut high_water = 0_u128;
            if staged {
                // Levels come into the schedule as placements reach them,
                // and the routes pushed so far are pushed again with the
                // new level's among them: first among the grouped levels'
                // own, which the groups have no runs for, then with those
                // all there.
                for (through, to, grouped) in
                    [(1, 40, 0), (schedule::GROUPED_LEVELS - 1, 120, fitted)]
                {
                    table.schedule_levels_through(through.min(level_count - 1));
                    assert_eq!(assert_starts(&table), grouped);
                    table.extend_probe_schedule(to);
                    assert_starts(&table);
                    high_water = to;
                }
            }
            table.schedule_levels_through(level_count - 1);
            assert_eq!(assert_starts(&table), fitted);
            while high_water < QUERY_POSITION_CAP {
                high_water = (high_water + high_water / 4 + 1).min(QUERY_POSITION_CAP);
                table.extend_probe_schedule(high_water);
                whole_groups_seen[assert_starts(&table) as usize] = true;
                whole_runs_seen[table.probe_schedule.whole_runs()] = true;
            }
            assert_eq!(
                table.probe_schedule.routes().len(),
                table.probe_schedule.route_capacity()
            );
            // Nor does the full schedule leave a group's run whole, and
            // each rebuild starts from all of them.
            assert!(
                whole_groups_seen[0] && whole_groups_seen[fitted as usize],
                "{slots} slots"
            );
        }
        // The full schedule leaves no run whole, and takes them over its
        // growth, not at once.
        let seen = whole_runs_seen.iter().filter(|&&seen| seen).count();
        assert!(
            whole_runs_seen[0] && seen >= 3.min(named + 1),
            "{slots} slots"
        );
    }
}

/// The walk starts of the summaries that leave only grouped levels open,
/// checked after each single route the schedule takes: the pushed routes
/// reach a group's run one slot at a time, and the run has to stop being
/// walked before the first of them lands in it. The sizes take in both
/// ways a run ends: full, and reached by the pushed routes while it has
/// room.
#[test]
#[cfg_attr(miri, ignore)]
fn group_runs_are_left_before_a_pushed_route_reaches_them() {
    for slots in [1 << 8, 1 << 11, 1 << 15] {
        let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                slots,
                ReserveFraction::DEFAULT,
                IdentityBuildHasher,
                Global,
            )
            .unwrap();
        let level_count = table.levels.len();
        table.probe_high_water &= HIGH_WATER_FLAGS;
        table.schedule_levels_through(level_count - 1);
        let fitted = table.probe_schedule.whole_groups().1;
        assert_ne!(fitted, 0, "{slots} slots");
        let mut pushed = 0;
        let mut whole_seen = alloc::vec![false; fitted as usize + 1];
        for high_water in 1..=QUERY_POSITION_CAP {
            table.extend_probe_schedule(high_water);
            let schedule = &table.probe_schedule;
            if schedule.routes().len() == pushed {
                continue;
            }
            // Positions are distinct, so one more position is one more
            // route.
            assert_eq!(schedule.routes().len(), pushed + 1);
            pushed += 1;
            let mut groups = 0;
            for open_levels in 0..1_u8 << 3 {
                let summary = NO_LEVELS_OCCUPIED & !(open_levels << 1);
                let closed = schedule::closed_levels(summary);
                let open = |route: &&PhiRoute| !route.as_step().is_closed(closed);
                let walked = schedule.walk_routes(summary);
                assert!(
                    walked
                        .iter()
                        .filter(open)
                        .eq(schedule.routes().iter().filter(open)),
                    "{slots} slots, {pushed} routes, summary {summary:#010b}"
                );
                if open_levels.count_ones() > 1
                    && schedule.walk_start(summary) != schedule.walk_start(0)
                {
                    groups += 1;
                    assert_eq!(walked.iter().filter(open).count(), walked.len());
                }
            }
            assert_eq!(groups, schedule.whole_groups().0);
            whole_seen[groups as usize] = true;
        }
        assert_eq!(pushed, table.probe_schedule.route_capacity());
        assert!(
            whole_seen[0] && whole_seen[fitted as usize],
            "{slots} slots"
        );
    }
}

#[test]
fn run_walk_steps_over_its_level_routes_and_stops_at_a_sentinel() {
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            8_193,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();
    let level_count = table.levels.len();
    table.schedule_levels_through(level_count - 1);
    table.extend_probe_schedule(1_024);
    let schedule = &table.probe_schedule;
    assert_eq!(schedule.named_levels(), ROUTE_SUMMARY_LEVELS - 1);
    assert_eq!(schedule.whole_runs(), schedule.named_levels());

    let walk = |summary: SummaryBin, level: Option<usize>| {
        let mut run = schedule.walk_start(summary).run().unwrap();
        let held = schedule
            .routes()
            .iter()
            .filter(|route| Some(usize::from(route.level())) == level);
        let mut steps = 0;
        for held in held {
            // SAFETY: the walk is ahead of the run's sentinel, which follows
            // every route of the level.
            let sequence_index = unsafe { run.step() };
            assert_eq!(sequence_index, held.as_step().sequence_index());
            // SAFETY: the walk has stepped onto a route of the schedule.
            assert_eq!(unsafe { *run.route() }, *held);
            steps += 1;
        }
        // SAFETY: as above; the level's last route is ahead of the sentinel.
        assert_eq!(unsafe { run.step() }, 0);
        // SAFETY: the sentinel is a route of the schedule.
        assert_eq!(unsafe { (*run.route()).level() }, SENTINEL_LEVEL);
        steps
    };
    assert_eq!(walk(NO_LEVELS_OCCUPIED, None), 0);
    for level in 0..ROUTE_SUMMARY_LEVELS - 1 {
        assert_ne!(walk(NO_LEVELS_OCCUPIED & !(2 << level), Some(level)), 0);
    }
    // Two open levels are no level's run, and here a group's: the walk
    // steps over the routes of the two and no other.
    let pair = NO_LEVELS_OCCUPIED & !0b110;
    assert!(
        schedule
            .walk_start(pair)
            .run()
            .is_err_and(|start| start != schedule.direct())
    );
    assert_eq!(
        schedule.walk_routes(pair),
        schedule
            .routes()
            .iter()
            .filter(|route| route.level() < 2)
            .copied()
            .collect::<Vec<_>>()
    );
}

type ComparesCountedMap = ElasticHashMap<ComparesCounted, u64, FixedHashBuilder>;

/// Clears the count of key compares and returns what it was.
fn take_key_compares() -> u64 {
    KEY_COMPARES.with(|compares| compares.replace(0))
}

/// Looks every key below `universe` up in both maps and asserts that they
/// find it in the same slot after the same key compares, and hold what
/// `model` does. Returns how many of the walks `started` would make start
/// at a run and how many at the direct route.
fn assert_twin_lookups_agree(
    started: &ComparesCountedMap,
    direct: &ComparesCountedMap,
    model: &alloc::collections::BTreeMap<u64, u64>,
    universe: u64,
) -> (u64, u64, u64) {
    let (started, direct) = (started.table(), direct.table());
    let (mut from_runs, mut from_groups, mut from_direct) = (0, 0, 0);
    for key in 0..universe {
        let counted = ComparesCounted::new(key, &started.hash_builder);
        let hash = started.hash_builder.hash_one(counted);
        take_key_compares();
        let found = started.find(&counted, hash);
        let ours = take_key_compares();
        assert_eq!(found, direct.find(&counted, hash));
        assert_eq!(ours, take_key_compares(), "key {key}");
        assert_eq!(
            started.find_entry(&counted, hash).map(|entry| entry.value),
            model.get(&key).copied()
        );
        let summary = started
            .route_filter(PreparedElasticRoute::new(hash))
            .summary();
        assert!(direct.probe_schedule.walk_start(summary).run().is_err());
        match started.probe_schedule.walk_start(summary).run() {
            Ok(_) => from_runs += 1,
            Err(start) if start == started.probe_schedule.direct() => from_direct += 1,
            Err(_) => from_groups += 1,
        }
    }
    (from_runs, from_groups, from_direct)
}

/// Twin maps take the same inserts and removals, with an ordered map as the
/// model: one starts each walk where its summary says, the other starts
/// every walk at the direct route. Through fills, removals that leave
/// tombstones, the rebuilds they bring and growth, both find every key in
/// the same slot after the same key compares, and neither finds an absent
/// one.
#[test]
#[cfg_attr(miri, ignore)]
fn walks_from_their_starts_probe_what_walks_from_the_direct_route_do() {
    let start_at_direct = |map: &mut ComparesCountedMap| {
        map.table_mut()
            .probe_schedule
            .start_walks_at_the_direct_route();
    };
    let mut cleanups = 0_u64;
    for capacity in [48, 900, 28_672] {
        let build = || ComparesCountedMap::with_capacity_and_hasher(capacity, fixed_hasher());
        let (mut started, mut direct) = (build(), build());
        let mut model = alloc::collections::BTreeMap::new();
        let universe = started.capacity() as u64;

        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let (mut from_runs, mut from_groups, mut from_direct) = (0_u64, 0_u64, 0_u64);
        let mut tombstones = 0_u64;
        for step in 0..universe * 8 {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let key = (state >> 33) % universe;
            let counted = ComparesCounted::new(key, started.hasher());
            // Fill, thin out, refill, then churn.
            let insert = match step / (universe * 2) {
                0 | 2 => state >> 60 != 0,
                1 => state >> 62 == 0,
                _ => state >> 63 == 0,
            };
            let generation = started.epoch().generation;
            take_key_compares();
            let ours = if insert {
                let previous = model.insert(key, step);
                assert_eq!(started.insert(counted, step), previous);
                let ours = take_key_compares();
                assert_eq!(direct.insert(counted, step), previous);
                ours
            } else {
                let removed = model.remove(&key);
                assert_eq!(started.remove(&counted), removed);
                let ours = take_key_compares();
                assert_eq!(direct.remove(&counted), removed);
                ours
            };
            assert_eq!(ours, take_key_compares(), "step {step}");
            start_at_direct(&mut direct);
            assert_eq!(started.len(), model.len());
            assert_eq!(started.epoch(), direct.epoch());
            let epoch = started.epoch();
            cleanups += u64::from(
                epoch.generation != generation
                    && epoch.transition == EpochTransition::TombstoneCleanup,
            );
            let levels = &started.table().levels;
            tombstones += u64::from(levels.iter().any(|level| level.tombstones() != 0));
            if (step + 1) % universe == 0 {
                let (runs, groups, direct) =
                    assert_twin_lookups_agree(&started, &direct, &model, universe);
                from_runs += runs;
                from_groups += groups;
                from_direct += direct;
            }
        }
        assert_eq!(started.capacity() as u64, universe);
        assert!(tombstones > universe, "{capacity}");
        assert!(
            from_runs > universe && from_groups + from_direct > universe / 8,
            "{capacity}: {from_runs} walks from runs, {from_groups} from groups, {from_direct} from \
             the direct route"
        );
        // Only a table with levels past the named ones has groups.
        assert_eq!(
            from_groups != 0,
            started.table().probe_schedule.whole_groups().1 != 0,
            "{capacity}: {from_groups} walks from groups"
        );

        // Then past the capacity, into a grown table.
        for key in universe..2 * universe {
            let counted = ComparesCounted::new(key, started.hasher());
            model.insert(key, key);
            assert_eq!(started.insert(counted, key), None);
            assert_eq!(direct.insert(counted, key), None);
            start_at_direct(&mut direct);
        }
        assert!(started.capacity() as u64 > universe);
        assert_twin_lookups_agree(&started, &direct, &model, 2 * universe);
    }
    assert_ne!(cleanups, 0);
}

#[test]
fn route_step_and_reach_read_what_each_route_holds() {
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
    assert_ne!(table.probe_schedule.routes(), []);

    let reads = |route: &PhiRoute| {
        let step = route.as_step();
        (step.close(0), step.sequence_index())
    };
    let mut route = table.probe_schedule.direct();
    for held in table.probe_schedule.routes() {
        // SAFETY: the walk is ahead of the sentinel, which follows every
        // pushed route.
        let step = unsafe { PhiRoute::step(&mut route) };
        assert!(ptr::eq(route, held));
        assert_eq!((step.close(0), step.sequence_index()), reads(held));
        assert!(step.is_closed(step.close(0)) && !step.is_closed(!step.close(0)));
        // SAFETY: `route` is a route of the schedule.
        let (index_shift, control) = unsafe { PhiRoute::reach(route) };
        assert_eq!(index_shift, held.index_shift());
        assert_eq!(control, held.control());
    }
    // SAFETY: as above; the last pushed route is ahead of the sentinel.
    let step = unsafe { PhiRoute::step(&mut route) };
    assert_eq!(step.close(0), SENTINEL_BIT);
    // SAFETY: the sentinel is a route of the schedule.
    assert_eq!(unsafe { (*route).level() }, SENTINEL_LEVEL);
}

#[test]
fn signed_control_sign_extends_every_byte() {
    let bytes: Vec<u8> = (0..=u8::MAX).collect();
    for (slot, &byte) in bytes.iter().enumerate() {
        // SAFETY: `slot` indexes `bytes`.
        let signed = unsafe { signed_control(bytes.as_ptr(), slot) };
        assert_eq!(signed, i32::from(byte.cast_signed()));
        assert_eq!(signed >= 0, control::is_free(byte));
        assert_eq!(signed.to_le_bytes()[0], byte);
    }
}

/// Splitmix64 of `index`: keys with no structure in any bit.
fn scattered(index: u64) -> u64 {
    let mut word = index.wrapping_add(1).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    word = (word ^ (word >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    word = (word ^ (word >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    word ^ (word >> 31)
}

/// A hasher with nothing in its low bits leaves the filter as selective as
/// one that fills them: a key's place comes from the top of its hash.
///
/// Two bounds hold for every family. A key passes only if its first bit is
/// set, and the keys of a full table set at most [`MEMBERSHIP_BITS`] bits
/// each, so the passes of uniformly placed absent keys are a count whose
/// mean is at most that share of the sample. And the passes of a family
/// without low bits and of the family with them are two such counts. A
/// count of independent passes has a variance of at most its mean, so six
/// deviations allow the square of an excess thirty-six times the mean, and
/// the square of a difference of two counts twice that. The families share
/// their high bits, so their counts sit closer than counts of independent
/// samples would; the bound asks for no more than it can derive.
#[test]
#[cfg_attr(miri, ignore)]
fn the_filter_keeps_its_rate_for_hashes_without_low_bits() {
    const CAPACITY: u64 = 28_672;
    const SAMPLE: u64 = 4 * CAPACITY;
    let passes = |low_bits: u32| {
        let key_at = |index: u64| scattered(index) & !((1 << low_bits) - 1);
        let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
            ElasticHashMap::with_capacity_and_hasher(
                usize::try_from(CAPACITY).unwrap(),
                IdentityBuildHasher,
            );
        for index in 0..CAPACITY {
            assert_eq!(map.insert(key_at(index), index), None);
        }
        let table = map.table();
        let lane_bits = u64::try_from(table.membership.words).unwrap() * u64::from(u64::BITS);
        let mean =
            (SAMPLE * CAPACITY * u64::try_from(MEMBERSHIP_BITS).unwrap()).div_ceil(lane_bits);
        let mut passes = 0_u64;
        for index in CAPACITY..CAPACITY + SAMPLE {
            let key = key_at(index);
            assert!(!map.contains_key(&key));
            let filter = table.route_filter(PreparedElasticRoute::new(key));
            passes += u64::from(filter.maybe_present);
        }
        let excess = passes.saturating_sub(mean);
        assert!(
            excess * excess <= 36 * mean,
            "{passes} of {SAMPLE} keys without their low {low_bits} bits pass, over a mean of \
             {mean}"
        );
        passes
    };
    let uniform = passes(0);
    for low_bits in [3, 6, 7] {
        let difference = passes(low_bits).abs_diff(uniform);
        assert!(
            difference * difference <= 72 * uniform,
            "keys without their low {low_bits} bits pass {difference} apart from {uniform}"
        );
    }
}

std::thread_local! {
    /// Key compares [`ComparesCounted`] made on this thread.
    static KEY_COMPARES: core::cell::Cell<u64> = const { core::cell::Cell::new(0) };
}

/// A key that counts its compares and hashes as the `u64` it holds. It
/// carries its control fingerprint, so a compare with a key of another
/// fingerprint, which the control byte should have ruled out, fails.
#[derive(Clone, Copy, Debug)]
struct ComparesCounted {
    key: u64,
    fingerprint: u8,
}

impl ComparesCounted {
    fn new(key: u64, hasher: &impl BuildHasher) -> Self {
        let unmarked = Self {
            key,
            fingerprint: 0,
        };
        Self {
            key,
            fingerprint: control::control_fingerprint_low(hasher.hash_one(unmarked)),
        }
    }
}

impl PartialEq for ComparesCounted {
    fn eq(&self, other: &Self) -> bool {
        assert_eq!(self.fingerprint, other.fingerprint);
        KEY_COMPARES.with(|compares| compares.set(compares.get() + 1));
        self.key == other.key
    }
}

impl Eq for ComparesCounted {}

impl Hash for ComparesCounted {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.key);
    }
}

/// Fills a table with the first keys of a family and looks up those and as
/// many more, absent ones, asserting that the compares against other keys
/// stay within what the family's own fingerprints explain.
///
/// A lookup probes each scheduled route at most once, and a probed slot
/// holds another key of the family, which shares the fingerprint with the
/// family's collision probability: the pairs of keys with equal
/// fingerprints, over all pairs. So the mean of the compares of as many
/// lookups as keys is at most the routes times the equal pairs over the
/// keys, and six deviations of a count with that mean allow the square of
/// an excess thirty-six times it. The routes overstate the probes a lookup
/// makes, so the bound catches compares that multiply past the family's
/// collisions, not a rate above the expected one, and a family whose keys
/// share one fingerprint is bound by the routes alone.
fn assert_compares_within_fingerprint_collisions<S: BuildHasher + Clone>(
    family: &str,
    hasher: &S,
    distinct_fingerprints: usize,
    key_at: impl Fn(u64) -> u64,
) {
    const CAPACITY: u64 = 28_672;
    let mut map: ElasticHashMap<ComparesCounted, u64, S> = ElasticHashMap::with_capacity_and_hasher(
        usize::try_from(CAPACITY).unwrap(),
        hasher.clone(),
    );
    let mut fingerprints = [0_u64; 1 << u8::BITS];
    for index in 0..CAPACITY {
        let key = ComparesCounted::new(key_at(index), hasher);
        fingerprints[usize::from(key.fingerprint)] += 1;
        assert_eq!(map.insert(key, index), None);
    }
    assert!(
        fingerprints.iter().filter(|&&keys| keys != 0).count() >= distinct_fingerprints,
        "{family}: fewer than {distinct_fingerprints} fingerprints"
    );
    let equal_pairs: u64 = fingerprints.iter().map(|keys| keys * keys).sum();
    let routes = u64::try_from(map.table().probe_schedule.routes().len()).unwrap() + 1;
    let mean = (routes * equal_pairs).div_ceil(CAPACITY);
    let within = |compares: u64, lookups: &str| {
        let excess = compares.saturating_sub(mean);
        assert!(
            excess * excess <= 36 * mean,
            "{family}: {compares} compares against other keys on {lookups}, over a mean of {mean}"
        );
    };

    KEY_COMPARES.with(|compares| compares.set(0));
    for index in 0..CAPACITY {
        assert_eq!(
            map.get(&ComparesCounted::new(key_at(index), hasher)),
            Some(&index)
        );
    }
    within(KEY_COMPARES.with(core::cell::Cell::get) - CAPACITY, "hits");

    KEY_COMPARES.with(|compares| compares.set(0));
    for index in CAPACITY..2 * CAPACITY {
        assert_eq!(map.get(&ComparesCounted::new(key_at(index), hasher)), None);
    }
    within(KEY_COMPARES.with(core::cell::Cell::get), "misses");
}

#[test]
#[cfg_attr(miri, ignore)]
fn compares_against_other_keys_stay_within_routes_times_fingerprint_collisions() {
    let fingerprints = 1_usize << (u8::BITS - 1);
    assert_compares_within_fingerprint_collisions(
        "hashed, consecutive",
        &fixed_hasher(),
        fingerprints,
        |index| index,
    );
    let identity = |family: &str, distinct_fingerprints: usize, key_at: &dyn Fn(u64) -> u64| {
        assert_compares_within_fingerprint_collisions(
            family,
            &IdentityBuildHasher,
            distinct_fingerprints,
            key_at,
        );
    };
    identity("consecutive", fingerprints, &|index| index);
    identity("odd multiples", fingerprints, &|index| {
        index.wrapping_mul(0x9E37_79B9_7F4A_7C15)
    });
    // A step with three low zero bits leaves the fingerprint four.
    identity("thousands", fingerprints >> 3, &|index| index * 1_000);
    for shift in [6_u32, 7, 16, 32, 48] {
        let distinct = fingerprints >> shift.min(u8::BITS - 1);
        identity("shifted", distinct, &|index| (index + 1) << shift);
    }
    for low_bits in [3_u32, 6, 7] {
        identity(
            "scattered, no low bits",
            fingerprints >> low_bits,
            &|index| scattered(index) & !((1 << low_bits) - 1),
        );
    }
}

#[test]
fn draining_a_map_leaves_no_level_a_tombstone() {
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(3_000);
    for key in 0..3_000 {
        map.insert(key, key);
    }
    for key in 0..1_000 {
        assert_eq!(map.remove(&key), Some(key));
    }
    assert_ne!(
        map.table()
            .levels
            .iter()
            .map(Level::tombstones)
            .sum::<u32>(),
        0
    );
    drop(map.drain());
    for level in &map.table().levels {
        assert_eq!(level.tombstones(), 0);
    }
    assert!(map.is_empty());
}

/// Places `stray` off the schedule in a table of `keys` and looks every key
/// up: each lookup returns the value where the table stores it, the stray
/// key's through the lookup off the schedule.
fn assert_lookup_off_the_schedule_returns_the_stored_value<K, V>(
    keys: impl IntoIterator<Item = K>,
    stray: K,
    value_of: impl Fn(K) -> V,
) where
    K: Eq + Hash + Copy,
{
    let mut table =
        ElasticTable::<K, V, FixedHashBuilder>::try_with_slots_and_reserve_fraction_and_hasher_in(
            1_024,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
    assert_ne!(table.levels[0].index_shift(), GENERAL_REDUCTION);
    let mut placed = Vec::new();
    for key in keys {
        let hash = table.hash_builder.hash_one(key);
        placed.push((key, table.insert_for_vacant_entry(key, value_of(key), hash)));
    }
    let hash = table.hash_builder.hash_one(stray);
    let prepared = PreparedElasticRoute::new(hash);
    let fingerprint = control::control_fingerprint_low(hash);
    placed.push((
        stray,
        table.place_exceptional_entry(stray, value_of(stray), prepared, fingerprint),
    ));
    assert!(matches!(
        table.walk_schedule(
            &stray,
            prepared,
            fingerprint,
            table.route_filter(prepared),
            |_, _, _, _| ()
        ),
        ScheduleSearch::Unresolved
    ));
    for (key, (level, slot)) in placed {
        let hash = table.hash_builder.hash_one(key);
        let found = TableBackend::find_value(&table, &key, hash).unwrap();
        // SAFETY: the insert returned the slot it filled.
        let stored = unsafe { &table.levels[level].get_ref(slot).value };
        assert!(ptr::eq(found, stored));
    }
}

#[test]
fn lookup_off_the_schedule_returns_the_stored_value() {
    assert_lookup_off_the_schedule_returns_the_stored_value(0..600_u64, u64::MAX, |key| key);
}

#[test]
fn lookup_off_the_schedule_returns_a_zero_sized_value() {
    assert_lookup_off_the_schedule_returns_the_stored_value(0..600_u64, u64::MAX, |_| ());
}

#[test]
fn lookup_off_the_schedule_returns_a_value_aligned_past_its_key() {
    assert!(align_of::<u64>() > align_of::<u8>());
    assert_lookup_off_the_schedule_returns_the_stored_value(0..200_u8, u8::MAX, u64::from);
}

/// Where the placement walk puts a new key with `probe`: the first free
/// slot of the batch's insertion case, then of every other target's in
/// order, each level searched whatever its counts say of its fill.
fn walked_placement(
    table: &ElasticTable<u64, u64, FixedHashBuilder>,
    probe: PreparedElasticProbe,
) -> Option<(usize, usize)> {
    let search = |level: usize, budget: u64| {
        // SAFETY: the level is the table's, which reduces by shift.
        unsafe { table.first_shifted_vacancy(probe, level, &table.levels[level], budget) }
    };
    let target = table.scheduler.target_at(table.live());
    let pairs = table.levels.len().saturating_sub(1);
    let others = core::iter::once(BatchTarget::Bootstrap)
        .chain((0..pairs).map(BatchTarget::LevelPair))
        .filter(|&candidate| candidate != target);
    core::iter::once(target)
        .chain(others)
        .find_map(|candidate| table.choose_slot_with::<false>(candidate, search))
        .map(|placement| (placement.level, placement.slot))
}

/// Removes a key and inserts it again, over and over, in a table at
/// `live` keys, and checks each insert against [`walked_placement`].
/// Returns the inserts that found the gate's plan gone for a full level and
/// those that settled.
fn assert_churn_places_where_the_walk_does(live: u64, pairs: u64) -> (u64, u64) {
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(896);
    assert_eq!(map.table().max_insertions, 896);
    assert_ne!(map.table().levels[0].index_shift(), GENERAL_REDUCTION);
    for key in 0..live {
        map.insert(key, key);
    }
    let (mut full, mut settled, mut rebuilt) = (0, 0, 0);
    let mut draw = 1_u64;
    for _ in 0..pairs {
        draw = draw
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let key = (draw >> 33) % live;
        assert_eq!(map.remove(&key), Some(key));
        let table = map.table();
        let hash = table.hash_builder.hash_one(key);
        let probe = PreparedElasticRoute::new(hash).probe;
        let case = table.settled_case(table.scheduler.target_at(table.live()));
        if case.is_some_and(|(case, ..)| table.live_in(case.region) == case.region.capacity) {
            assert_eq!(table.settled_plan(), None);
            full += 1;
        }
        let expected = walked_placement(table, probe);
        let generation = table.epoch.snapshot(table.live()).generation;
        settled += u64::from(table.settled_slot(probe).is_some());
        assert_eq!(map.insert(key, key), None);
        let table = map.table();
        if table.epoch.snapshot(table.live()).generation == generation {
            assert_eq!(table.find(&key, hash), expected);
        } else {
            rebuilt += 1;
        }
        assert_eq!(map.get(&key), Some(&key));
    }
    assert!(rebuilt * 100 < pairs);
    (full, settled)
}

#[test]
fn churn_at_the_insertion_limit_places_where_the_walk_does() {
    let pairs = if cfg!(miri) { 400 } else { 8_000 };
    let (full, settled) = assert_churn_places_where_the_walk_does(896, pairs);
    assert_ne!(full, 0);
    assert_ne!(settled, 0);
}

#[test]
fn churn_below_the_insertion_limit_places_where_the_walk_does() {
    let pairs = if cfg!(miri) { 400 } else { 8_000 };
    let (_, settled) = assert_churn_places_where_the_walk_does(600, pairs);
    assert!(settled * 10 > pairs * 9);
}

/// Keys that share one probe sequence fill the bootstrap level's probes
/// long before the level, so the keys after them fail the batch's target
/// and another target places them, in an insert and in a rebuild alike.
#[test]
fn rebuild_places_a_key_its_target_fails_on_another_target() {
    let mut table = ElasticTable::<u64, u64, ConstHashBuilder>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            4_096,
            ReserveFraction::DEFAULT,
            ConstHashBuilder,
            Global,
        )
        .unwrap();
    assert_ne!(table.levels[0].index_shift(), GENERAL_REDUCTION);
    let keys = LEVEL_PROBE_LIMIT[0] + 40;
    assert!(keys < table.scheduler.batch_ends[0] as u64);
    for key in 0..keys {
        assert_eq!(table.insert(key, key, 0), None);
    }
    let off_target = |table: &ElasticTable<u64, u64, ConstHashBuilder>| {
        table.levels[1..]
            .iter()
            .map(|level| table.live_in(level))
            .sum::<u32>()
    };
    assert_eq!(off_target(&table), 40);
    assert_eq!(table.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG, 0);

    table.resize(4_096);
    assert_eq!(off_target(&table), 40);
    assert_eq!(table.probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG, 0);
    assert_eq!(table.epoch.snapshot(table.live()).placement_recoveries, 0);
    for key in 0..keys {
        assert_eq!(TableBackend::find_value(&table, &key, 0), Some(&key));
    }
}

/// A key hashed by `hash` alone, so keys of one hash share every probe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SharedProbeKey {
    hash: u64,
    id: u64,
}

impl Hash for SharedProbeKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u64(self.hash);
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_recovery_rebuild_tries_every_target_before_placing_off_the_probes() {
    const SHARED: u64 = 0x9e37_79b9_7f4a_7c15;
    // Keys of their own probes: enough to hold slots the shared probes
    // reach, few enough that the shared keys run out of slots before the
    // table's budget. The asserts on the rebuilt copy below hold the count
    // to that.
    const SPREAD: u64 = 44;
    let spread_hash = |id: u64| {
        let mut hash = id.wrapping_add(SHARED);
        hash = (hash ^ (hash >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        hash = (hash ^ (hash >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        hash ^ (hash >> 31)
    };
    let shared = |id: u64| SharedProbeKey { hash: SHARED, id };
    let mut map: ElasticHashMap<SharedProbeKey, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(256, IdentityBuildHasher);
    let slots = map.table().total_slots;
    // A rebuild moves the keys of their own probes.
    for id in 0..SPREAD {
        map.insert(
            SharedProbeKey {
                hash: spread_hash(id),
                id,
            },
            id,
        );
    }
    // Keys of the shared hash, until no target has a slot for the next.
    let prepared = PreparedElasticRoute::new(SHARED);
    let no_slot = |table: &ElasticTable<SharedProbeKey, u64, IdentityBuildHasher>| {
        let target = table.scheduler.target_at(table.live());
        table
            .choose_slot_for_new_key(prepared.probe, target)
            .is_none()
            && table
                .choose_slot_on_other_targets(prepared.probe, target)
                .is_none()
    };
    let mut next = SPREAD;
    while !no_slot(map.table()) {
        map.insert(shared(next), next);
        next += 1;
    }
    assert!(map.len() < map.capacity());
    assert_eq!(map.table().probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG, 0);

    // What the rebuild leaves the next key: no slot on the active target,
    // one on another.
    let mut rebuilt = map.clone();
    let table = rebuilt.table_mut();
    table.resize_with_transition(table.total_slots, EpochTransition::PlacementRecovery);
    let target = table.scheduler.target(table.live());
    assert!(
        table
            .choose_slot_for_new_key(prepared.probe, target)
            .is_none()
    );
    assert!(
        table
            .choose_slot_on_other_targets(prepared.probe, target)
            .is_some()
    );

    let before = map.epoch();
    assert_eq!(map.insert(shared(next), next), None);
    let after = map.epoch();
    assert_eq!(after.placement_recoveries, before.placement_recoveries + 1);
    assert_eq!(after.transition, EpochTransition::PlacementRecovery);
    assert_eq!(map.table().total_slots, slots);
    assert_eq!(
        map.table().probe_high_water & EXCEPTIONAL_PLACEMENT_FLAG,
        0,
        "the key was placed off its probes with a slot left on them"
    );
    for id in SPREAD..=next {
        assert_eq!(map.get(&shared(id)), Some(&id));
    }
    for id in 0..SPREAD {
        let key = SharedProbeKey {
            hash: spread_hash(id),
            id,
        };
        assert_eq!(map.get(&key), Some(&id));
    }
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_removal_finds_a_key_placed_off_its_probes() {
    let shared = |id: u64| SharedProbeKey {
        hash: 0x9e37_79b9_7f4a_7c15,
        id,
    };
    let mut map: ElasticHashMap<SharedProbeKey, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(256, IdentityBuildHasher);
    let keys = map.capacity() as u64;
    // One hash for every key: its probes run out of slots before the
    // table's budget does, and the rest are placed off them.
    for id in 0..keys {
        assert_eq!(map.insert(shared(id), !id), None);
    }
    assert!(map.table().walk_ends_unresolved());

    assert_eq!(map.remove(&shared(keys)), None);
    assert_eq!(map.remove_entry(&shared(keys)), None);
    // Last placed first, so the keys off the probes go while the table
    // still leaves its walks unresolved.
    for id in (0..keys).rev() {
        if id % 2 == 0 {
            assert_eq!(map.remove(&shared(id)), Some(!id));
        } else {
            assert_eq!(map.remove_entry(&shared(id)), Some((shared(id), !id)));
        }
        assert_eq!(map.get(&shared(id)), None);
        assert_eq!(map.len() as u64, id);
    }
    assert_eq!(map.remove(&shared(0)), None);
}

#[test]
fn a_removal_takes_an_entry_placed_off_the_schedule() {
    let mut table =
        ElasticTable::<u64, u64, FixedHashBuilder>::try_with_slots_and_reserve_fraction_and_hasher_in(
            1_024,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
    for key in 0..200_u64 {
        let hash = table.hash_builder.hash_one(key);
        table.insert_for_vacant_entry(key, !key, hash);
    }
    let strays = [u64::MAX, u64::MAX - 1];
    for stray in strays {
        let hash = table.hash_builder.hash_one(stray);
        let fingerprint = control::control_fingerprint_low(hash);
        table.place_exceptional_entry(stray, !stray, PreparedElasticRoute::new(hash), fingerprint);
    }
    assert!(table.walk_ends_unresolved());

    let [by_entry, by_value] = strays;
    let hash = table.hash_builder.hash_one(by_entry);
    assert_eq!(table.take(&by_entry, hash), Some((by_entry, !by_entry)));
    assert_eq!(table.take(&by_entry, hash), None);
    let hash = table.hash_builder.hash_one(by_value);
    assert_eq!(table.take_value(&by_value, hash), Some(!by_value));
    assert_eq!(table.take_value(&by_value, hash), None);
    assert_eq!(table.live(), 200);
    for key in 0..200_u64 {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(TableBackend::find_value(&table, &key, hash), Some(&!key));
    }
}

/// A key's lone bit goes with it; a bit two keys set stays for the one that
/// is left, and so does a bit whose pair is another live key's own bit.
#[test]
fn a_removal_keeps_a_bit_whose_pair_is_set() {
    let new_map = || -> FixedElasticHashMap<u64, u64> { FixedElasticHashMap::with_capacity(64) };
    let passes = |map: &FixedElasticHashMap<u64, u64>, key: u64| {
        let prepared = PreparedElasticRoute::new(map.table().hash_builder.hash_one(key));
        map.table().route_filter(prepared).maybe_present
    };
    let empty = new_map();
    let place = |key: u64| {
        let prepared = PreparedElasticRoute::new(empty.table().hash_builder.hash_one(key));
        let place = empty.table().route_filter(prepared).read.place;
        (place.word(), place.bits())
    };
    // Two keys on one bit, and a third whose own bit is their pair.
    let mut places = Vec::new();
    let (first, second) = (0_u64..10_000)
        .find_map(|second| {
            let first = places.iter().position(|&seen| seen == place(second));
            places.push(place(second));
            first.map(|first| (first as u64, second))
        })
        .unwrap();
    let (word, bit) = place(first);
    let opposite = (0_u64..100_000)
        .find(|&key| place(key) == (word, paired_bits(bit)))
        .unwrap();

    let mut map = new_map();
    map.insert(first, 1);
    assert_eq!(map.remove(&first), Some(1));
    assert!(!passes(&map, first));

    map.insert(first, 1);
    map.insert(second, 2);
    assert_eq!(map.remove(&first), Some(1));
    assert!(passes(&map, second));
    assert_eq!(map.get(&second), Some(&2));
    assert_eq!(map.remove(&second), Some(2));
    assert_eq!(map.get(&second), None);

    let mut map = new_map();
    map.insert(first, 1);
    map.insert(opposite, 3);
    assert_eq!(map.remove(&first), Some(1));
    assert!(passes(&map, opposite));
    assert_eq!(map.get(&opposite), Some(&3));
    map.insert(first, 1);
    assert_eq!(map.remove(&opposite), Some(3));
    assert!(passes(&map, first));
    assert_eq!(map.get(&first), Some(&1));
}

#[test]
#[cfg_attr(miri, ignore)]
fn a_removal_forgets_only_a_bit_no_live_key_holds() {
    const KEYS: usize = 600;
    // Scattered keys: the fixed hasher spreads a run of consecutive
    // integers evenly, and evenly spread keys share no bit.
    let key_of = |id: u64| {
        let mixed = (id ^ (id >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        mixed ^ (mixed >> 27)
    };
    let mut map: FixedElasticHashMap<u64, u64> = FixedElasticHashMap::with_capacity(512);
    let passes = |map: &FixedElasticHashMap<u64, u64>, key: u64| {
        let prepared = PreparedElasticRoute::new(map.table().hash_builder.hash_one(key));
        map.table().route_filter(prepared).maybe_present
    };
    let mut live = [false; KEYS];
    let mut forgotten = 0_usize;
    let mut kept = 0_usize;
    let mut state = 1_u64;
    for _ in 0..6_000 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let id = (state >> 33) % KEYS as u64;
        let key = key_of(id);
        let slot = usize::try_from(id).unwrap();
        if live[slot] {
            assert_eq!(map.remove(&key), Some(id));
            if passes(&map, key) {
                kept += 1;
            } else {
                forgotten += 1;
            }
        } else {
            assert_eq!(map.insert(key, id), None);
        }
        live[slot] = !live[slot];
        for probe in 0..KEYS as u64 {
            let present = live[usize::try_from(probe).unwrap()];
            assert!(
                !present || passes(&map, key_of(probe)),
                "the filter lost live key {probe}"
            );
            assert_eq!(map.get(&key_of(probe)).is_some(), present);
        }
    }
    assert!(forgotten > 0, "no removal cleared its key's bit");
    assert!(kept > 0, "no removal met a bit it had to keep");
}

/// A general insert the batch's own case places leaves the gate ending
/// where it stood, while the table stays on the plan the gate opened on:
/// with removals outstanding the bound is one on the placed count, which
/// still holds them.
#[test]
fn a_general_insert_on_the_open_plan_keeps_the_gate_end_past_removals() {
    const SLOTS: usize = if cfg!(miri) { 256 } else { 1_024 };
    let mut table = ElasticTable::<u64, u64, FixedHashBuilder>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            SLOTS,
            ReserveFraction::DEFAULT,
            fixed_hasher(),
            Global,
        )
        .unwrap();
    let capacity = table.max_insertions as u64;
    let universe = capacity + capacity / 2;
    let mut model = alloc::collections::BTreeMap::<u64, u64>::new();
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let mut kept_past_removals = 0;
    for step in 0..capacity * 8 {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        let key = (state >> 33) % universe;
        let hash = table.hash_builder.hash_one(key);
        // Fill, thin out, refill, then churn.
        let insert = match step / (capacity * 2) {
            0 | 2 => state >> 60 != 0,
            1 => state >> 62 == 0,
            _ => state >> 63 == 0,
        };
        if !insert {
            let removed = table.take(&key, hash).map(|(_, value)| value);
            assert_eq!(removed, model.remove(&key));
            continue;
        }
        if model.contains_key(&key) || model.len() == table.max_insertions {
            continue;
        }
        let prepared = PreparedElasticRoute::new(hash);
        let end = table.scheduler.settled_end;
        let open = table
            .scheduler
            .settles(table.placed)
            // SAFETY: the gate is open.
            .then(|| unsafe { table.open_words() });
        let on_case = table
            .choose_slot_for_insert(prepared.probe, table.scheduler.cached_target())
            .is_some();

        table.insert_for_vacant_entry_prepared(
            key,
            step,
            prepared,
            control::control_fingerprint_low(hash),
        );
        model.insert(key, step);
        assert_eq!(table.find_value(&key, hash), Some(&step));
        assert_eq!(table.live(), model.len());
        assert_open_gate_is_the_plan(&table);

        let same_plan = table
            .settled_case(table.scheduler.cached_target())
            .is_some_and(|(case, budget, fallback)| {
                Some(table.plan_words(case.level, budget, fallback)) == open
            });
        if on_case && same_plan && table.placed < end && table.scheduler.covers(table.live()) {
            assert_eq!(table.scheduler.settled_end, end, "step {step}");
            // The placed count alone is past the batch the live count is in.
            let removals = table.stale_membership();
            kept_past_removals += usize::from(!table.scheduler.covers(table.placed + removals));
        }
    }
    for (key, value) in &model {
        let hash = table.hash_builder.hash_one(key);
        assert_eq!(table.find_value(key, hash), Some(value));
    }
    assert_counters_match_controls(&table);
    assert!(kept_past_removals > 0);
}

/// A level holding more tombstones than half its slots, and no more than
/// its cleanup threshold, takes an insert into one of them as any other:
/// the cached batch still covers the live count and no cleanup follows.
#[test]
fn reusing_a_tombstone_under_the_threshold_keeps_the_batch() {
    let mut map = FixedElasticHashMap::<u64, u64>::with_capacity(1_024);
    let live = {
        let scheduler = &map.table().scheduler;
        assert_eq!(scheduler.current_batch_index, 0);
        scheduler.batch_end as u64 - 8
    };
    for key in 0..live {
        map.insert(key, key);
    }
    let (half, threshold) = {
        let level = &map.table().levels[0];
        assert_eq!(u64::from(map.table().live_in(level)), live);
        (
            level.capacity() as u64 / 2,
            capacity::tombstone_cleanup_threshold(level.capacity()) as u64,
        )
    };
    // Two reused tombstones still leave the level over half.
    let departed = half + 3;
    assert!(departed <= threshold && departed < live);
    for key in 0..departed {
        assert_eq!(map.remove(&key), Some(key));
    }

    let mut key = live;
    for _ in 0..2 {
        loop {
            let tombstones = map.table().levels[0].tombstones();
            map.insert(key, key);
            key += 1;
            if map.table().levels[0].tombstones() < tombstones {
                break;
            }
            assert!(key < live + departed, "no insert reused a tombstone");
        }
        let table = map.table();
        assert!(u64::from(table.levels[0].tombstones()) > half);
        assert!(!table.levels[0].needs_cleanup());
        assert!(table.scheduler.covers(table.live()));
    }
    assert_eq!(map.epoch().generation, 0);
    for present in departed..key {
        assert_eq!(map.get(&present), Some(&present));
    }
}

/// Past the last batch's end the last batch stays the active one.
#[test]
fn a_live_count_at_or_past_the_last_batch_end_stays_in_the_last_batch() {
    let mut scheduler = BatchScheduler::new(&[4, 6, 2], 0, 0);
    assert_eq!(scheduler.target(3), BatchTarget::Bootstrap);
    assert_eq!(scheduler.target(11), BatchTarget::LevelPair(1));
    for len in [12, 13, usize::MAX] {
        assert_eq!(scheduler.target(len), BatchTarget::LevelPair(1), "{len}");
    }
    assert_eq!(scheduler.target(4), BatchTarget::LevelPair(0));
}
