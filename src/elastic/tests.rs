use super::*;

use core::hash::{BuildHasher, Hasher};
use core::mem::ManuallyDrop;
use core::num::{NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize};
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use crate::exact::reference::{ScalarElastic, ScalarElasticLimits};
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
        assert!(matches!(
            BatchScheduler::on_insert(table.len, table.total_slots, table.max_insertions),
            InsertAction::Continue
        ));
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
        assert_eq!(placement.phi, expected.phi);
        assert_eq!(
            placement.phi,
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
            query.found_position <= placement.phi,
            "lookup order visits phi={} no later than placement phi={}",
            query.found_position,
            placement.phi
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
    assert_eq!(MAX_CASE1_LOGICAL_PROBES, 7_688);
    assert_eq!(
        PaperConfig::new(MAX_ELASTIC_SLOTS, ReserveFraction::DEFAULT.exponent())
            .unwrap()
            .elastic_plan()
            .level_count(),
        u32::BITS as usize
    );
    #[cfg(target_pointer_width = "64")]
    {
        assert!(
            ElasticGeometry::for_insert_budget(MAX_ELASTIC_SLOTS, ReserveFraction::DEFAULT,)
                .is_none()
        );
        let result = ElasticTable::<u64, u64, IdentityBuildHasher>::
            try_with_slots_and_reserve_fraction_and_hasher_in(
                MAX_ELASTIC_SLOTS + 1,
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
    table.extend_probe_schedule(QUERY_POSITION_CAP);
    assert!(
        table
            .probe_schedule
            .iter()
            .all(|route| route.counter_base != H11_COUNTER_BASE)
    );
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
    let initial_ptr = table.probe_schedule.as_ptr();
    let initial_capacity = table.probe_schedule.capacity();

    table.extend_probe_schedule(QUERY_POSITION_CAP);

    assert_eq!(table.probe_schedule.as_ptr(), initial_ptr);
    assert_eq!(table.probe_schedule.capacity(), initial_capacity);
    assert_eq!(table.probe_schedule.len(), initial_capacity);
}

#[test]
fn query_schedule_caches_each_routes_exact_level_bound() {
    let mut table = ElasticTable::<u64, u64, IdentityBuildHasher>::
        try_with_slots_and_reserve_fraction_and_hasher_in(
            8_193,
            ReserveFraction::DEFAULT,
            IdentityBuildHasher,
            Global,
        )
        .unwrap();

    table.extend_probe_schedule(QUERY_POSITION_CAP);

    for route in &table.probe_schedule {
        assert_eq!(
            route.range_upper as usize,
            table.levels[route.level()].capacity()
        );
    }
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

#[test]
fn clear_marks_each_slot_empty_before_dropping_its_value() {
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
                .find(|&slot| control::is_occupied(level.control_at(slot)))
                .map(|slot| (level_index, slot))
        })
        .unwrap();

    let result = catch_unwind(AssertUnwindSafe(|| map.clear()));
    assert!(result.is_err());
    assert_eq!(
        map.table().levels[first_occupied.0].control_at(first_occupied.1),
        CTRL_EMPTY
    );
    let live_controls = map
        .table()
        .levels
        .iter()
        .map(|level| {
            (0..level.capacity())
                .filter(|&slot| control::is_occupied(level.control_at(slot)))
                .count()
        })
        .sum::<usize>();
    assert_eq!(map.len(), live_controls);
    assert!(map.table().levels.iter().all(|level| {
        level.len as usize
            == (0..level.capacity())
                .filter(|&slot| control::is_occupied(level.control_at(slot)))
                .count()
    }));

    map.clear();
    assert!(map.is_empty());
    assert_eq!(drops.load(Ordering::SeqCst), 3);
    unsafe { ManuallyDrop::drop(&mut map) };
}

#[test]
fn caught_hash_panic_during_try_resize_leaves_counters_valid() {
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
                .filter(|&slot| control::is_occupied(level.control_at(slot)))
                .count()
        })
        .sum::<usize>();
    assert_eq!(map.len(), live_controls);
    assert!(map.table().levels.iter().all(|level| {
        level.len as usize
            == (0..level.capacity())
                .filter(|&slot| control::is_occupied(level.control_at(slot)))
                .count()
    }));
    assert_eq!(drops.load(Ordering::SeqCst), 1);

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
    assert!(mem::size_of::<ElasticMetadataWord>() <= 2 * membership::SLOTS_PER_WORD);

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
        unsafe { table.arena.as_ptr().add(layout.membership.offset) }.addr()
    );
    assert_eq!(
        table.membership_ptr().addr() % mem::align_of::<ElasticMetadataWord>(),
        0
    );
    for word in 0..table.membership.words {
        let metadata = unsafe { *table.membership_ptr().add(word) };
        assert_eq!(metadata.membership, 0);
        assert_eq!(metadata.route_bins, [0; 4]);
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
    (1_u64 << first) | (1_u64 << second)
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
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(1 << 20, IdentityBuildHasher);
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
    assert_ne!(
        control::control_fingerprint(hash),
        control::control_fingerprint(PreparedElasticRoute::new(hash).signature())
    );
    let prepared = PreparedElasticKey::new(hash);
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(64, IdentityBuildHasher);

    map.insert(hash, 7);
    let location = map
        .table()
        .find_slot_indices_prepared(&hash, prepared, control::control_fingerprint(hash))
        .unwrap();

    assert_eq!(
        map.table().levels[location.0].control_at(location.1),
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

    for key in 0..key_count {
        let location = map
            .table()
            .levels
            .iter()
            .enumerate()
            .find_map(|(level_index, level)| {
                (0..level.capacity()).find_map(|slot| {
                    (control::is_occupied(level.control_at(slot))
                        && unsafe { level.get_ref(slot) }.key == key)
                        .then_some((level_index, slot))
                })
            })
            .unwrap();
        let prepared = PreparedElasticKey::new(key);
        assert_ne!(
            map.table().route_filter(prepared).level_mask & (1_u32 << summary_level(location.0)),
            0,
            "key {key} at level {}",
            location.0
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
            unsafe { (*map.table().membership_ptr().add(word)).route_bins },
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
    let mut map: ElasticHashMap<u64, u64, IdentityBuildHasher> =
        ElasticHashMap::with_capacity_and_hasher(2_048, IdentityBuildHasher);
    for key in 0..1_024_u64 {
        map.insert(key, key);
    }
    for key in 0..1_024_u64 {
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

    for logical_index in 0..UNIFORM_SEARCH_CAP {
        let paper_probe = u128::from(logical_index) + 1;
        if probe::elastic_phi(1, paper_probe).unwrap() > QUERY_POSITION_CAP {
            break;
        }
        let slot = table.route_exact(0, 0, logical_index).unwrap();
        if control::is_free(table.levels[0].control_at(slot)) {
            table.levels[0].write_with_control(
                slot,
                SlotEntry {
                    key: next_key,
                    value: next_key,
                },
                fingerprint,
            );
            table.levels[0].len += 1;
            table.len += 1;
            next_key += 1;
        }
    }
    assert!(
        table
            .choose_slot_for_new_key(prepared.route.probe, BatchTarget::Bootstrap)
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
        table.insert_unique(key, key ^ 0xa5a5);
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
        let resolved = unsafe { table.slot_ref(location.0, location.1) };
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
        table.insert_unique(key, key);
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
    let rebuild_geometry = ElasticGeometry::for_slots(rebuild_slots, table.reserve_fraction);
    let bootstrap_quota = rebuild_geometry.batch_plan[0];

    for key in 0..bootstrap_quota {
        table.insert_unique(key, key);
    }
    table.max_insertions = table.len;
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
