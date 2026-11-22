//! Test-only fixtures shared by both backend test modules.

use core::hash::{BuildHasher, Hash, Hasher};
use core::mem::ManuallyDrop;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;
use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::ReserveFraction;
use crate::map::{HashMap, TableBackend};
use crate::membership;
use crate::raw::control::{self, CTRL_TOMBSTONE};

/// Hashes a `u64` to itself, so test keys double as their own hashes.
#[derive(Clone, Copy, Default)]
pub(crate) struct IdentityBuildHasher;

/// Seeded foldhash state for every test that hashes real keys: the same key
/// stream on every run, so probabilistic bounds and placement-dependent
/// assertions either hold or fail deterministically instead of flaking with
/// the process's random seed.
pub(crate) use foldhash::fast::FixedState as FixedHashBuilder;
pub(crate) const FIXED_HASH_SEED: u64 = 0xD1B5_4A32_D192_ED03;

pub(crate) fn fixed_hasher() -> FixedHashBuilder {
    FixedHashBuilder::with_seed(FIXED_HASH_SEED)
}

/// `with_capacity` for maps over [`FixedHashBuilder`]. The inherent
/// constructors exist only for the default hasher; when that bound fails,
/// resolution falls through to this trait, so tests read like production code.
pub(crate) trait Deterministic: Sized {
    fn with_capacity(capacity: usize) -> Self;
}

impl<K, V, P> Deterministic for HashMap<K, V, P>
where
    P: TableBackend<K, V, Hasher = FixedHashBuilder, Alloc = Global>,
{
    fn with_capacity(capacity: usize) -> Self {
        Self::with_capacity_and_hasher(capacity, fixed_hasher())
    }
}

/// `ElasticHashMap` over [`FixedHashBuilder`]. Spelled as its own alias so
/// `FixedElasticHashMap::with_capacity(n)` resolves to [`Deterministic`]; with
/// the public alias's default hasher parameter the inherent constructor wins.
pub(crate) type FixedElasticHashMap<K, V> = crate::ElasticHashMap<K, V, FixedHashBuilder>;

pub(crate) struct IdentityHasher(u64);

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

/// Fails every allocation while `fail` is set and counts the calls that reach
/// the global allocator.
#[derive(Clone)]
pub(crate) struct ToggleAllocator {
    pub(crate) fail: Arc<AtomicBool>,
    pub(crate) allocations: Arc<AtomicUsize>,
    pub(crate) deallocations: Arc<AtomicUsize>,
}

impl ToggleAllocator {
    pub(crate) fn new(fail: Arc<AtomicBool>) -> Self {
        Self {
            fail,
            allocations: Arc::default(),
            deallocations: Arc::default(),
        }
    }
}

// SAFETY: forwards to `Global`, so blocks stay valid across clones and moves;
// the failure toggle only refuses allocations.
unsafe impl Allocator for ToggleAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if self.fail.load(Ordering::SeqCst) {
            Err(AllocError)
        } else {
            let allocation = Global.allocate(layout)?;
            self.allocations.fetch_add(1, Ordering::SeqCst);
            Ok(allocation)
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        self.deallocations.fetch_add(1, Ordering::SeqCst);
        // SAFETY: `ptr` came from `allocate`, i.e. from `Global`, with `layout`.
        unsafe { Global.deallocate(ptr, layout) };
    }
}

/// Counts every drop.
pub(crate) struct CountDrop(pub(crate) Arc<AtomicUsize>);

impl Drop for CountDrop {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Counts every drop and panics on the first one.
pub(crate) struct PanicOnFirstDrop(pub(crate) Arc<AtomicUsize>);

impl Drop for PanicOnFirstDrop {
    fn drop(&mut self) {
        assert!(
            self.0.fetch_add(1, Ordering::SeqCst) != 0,
            "first value drop"
        );
    }
}

/// Key whose `Hash` panics while `armed` is set; counts every drop.
pub(crate) struct PanicHashKey {
    pub(crate) id: u64,
    pub(crate) armed: Arc<AtomicBool>,
    pub(crate) drops: Arc<AtomicUsize>,
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

/// Churn past the refresh threshold must re-record the filter from the live
/// entries: departed keys stop passing the gate, live keys still do.
///
/// `gate_passes` reports whether the backend's filter still admits `key`;
/// `stale_membership` reads the backend's count of deletes since the last
/// refresh; the refresh runs with delete number `refresh_at(threshold)`.
/// Until then the filter admits every departed key.
pub(crate) fn assert_deletes_past_threshold_refresh_filter<P>(
    gate_passes: impl Fn(&P, u64) -> bool,
    stale_membership: impl Fn(&P) -> usize,
    refresh_at: impl Fn(u64) -> u64,
) where
    P: TableBackend<u64, u64, Hasher = FixedHashBuilder, Alloc = Global>,
{
    assert_deletes_past_threshold_refresh_filter_from(
        gate_passes,
        stale_membership,
        refresh_at,
        |admitted, departed| assert_eq!(admitted, departed),
    );
}

/// [`assert_deletes_past_threshold_refresh_filter`] for a filter that may
/// drop a key as it departs: `admitted_before_refresh` checks how many of
/// the departed keys the filter admits before the refresh, of how many
/// departed.
pub(crate) fn assert_deletes_past_threshold_refresh_filter_from<P>(
    gate_passes: impl Fn(&P, u64) -> bool,
    stale_membership: impl Fn(&P) -> usize,
    refresh_at: impl Fn(u64) -> u64,
    admitted_before_refresh: impl Fn(usize, usize),
) where
    P: TableBackend<u64, u64, Hasher = FixedHashBuilder, Alloc = Global>,
{
    let mut map: HashMap<u64, u64, P> = Deterministic::with_capacity(2_048);
    let live = map.capacity() as u64;
    let threshold = membership::refresh_deletes(map.capacity()) as u64;
    let refresh_at = refresh_at(threshold);
    for key in 0..live {
        map.insert(key, key);
    }

    // A third of the keys: enough to matter, below every cleanup threshold.
    let departed = (0..live).filter(|key| key % 3 == 0).collect::<Vec<_>>();
    for &key in &departed {
        assert_eq!(map.remove(&key), Some(key));
    }
    let admitted = departed
        .iter()
        .filter(|&&key| gate_passes(map.table(), key))
        .count();
    admitted_before_refresh(admitted, departed.len());
    assert_eq!(stale_membership(map.table()) as u64, departed.len() as u64);
    assert_eq!(map.epoch().generation, 0);

    // Cycling one fresh key re-takes the tombstone it left, so tombstones
    // stay flat and no cleanup rebuild can run before the threshold.
    let churn = live;
    let mut cycles = 0_u64;
    loop {
        map.insert(churn, churn);
        assert_eq!(map.remove(&churn), Some(churn));
        cycles += 1;
        if stale_membership(map.table()) == 0 {
            break;
        }
        assert!(cycles < refresh_at, "refresh never ran");
    }
    assert_eq!(cycles + departed.len() as u64, refresh_at);
    assert_eq!(map.epoch().generation, 0, "no rebuild ran");
    assert_eq!(stale_membership(map.table()), 0, "refresh resets the count");
    assert_eq!(map.len() as u64, live - departed.len() as u64);
    // The epoch still counts every delete, on either side of the refresh.
    let epoch = map.epoch();
    assert!(epoch.had_delete);
    assert_eq!(
        epoch.distinct_insertions as u64,
        map.len() as u64 + refresh_at
    );
    map.insert(churn, churn);
    assert_eq!(map.remove(&churn), Some(churn));
    assert_eq!(
        map.epoch().distinct_insertions as u64,
        map.len() as u64 + refresh_at + 1
    );

    // Live keys are still recorded and found; departed keys mostly are not.
    for key in (0..live).filter(|key| key % 3 != 0) {
        assert!(gate_passes(map.table(), key));
        assert_eq!(map.get(&key), Some(&key));
    }
    let false_positives = departed
        .iter()
        .filter(|&&key| gate_passes(map.table(), key))
        .count();
    assert!(
        false_positives * 4 < departed.len(),
        "{false_positives} of {} departed keys still pass",
        departed.len()
    );
    assert!(false_positives <= admitted);

    // Clearing every entry and refreshing empties the filter completely.
    map.retain(|_, _| false);
    for _ in 0..=threshold {
        if stale_membership(map.table()) == 0 {
            break;
        }
        map.insert(churn, churn);
        map.remove(&churn);
    }
    assert_eq!(stale_membership(map.table()), 0);
    assert!((0..live).all(|key| !gate_passes(map.table(), key)));
}

/// A key whose `Hash` panics during a filter refresh, or a refresh that finds
/// no scratch memory, must leave every live key reachable and the refresh
/// owed, so it runs once neither stands in its way.
///
/// `gate_passes` reports whether the backend's filter admits a key hash.
/// `stale_membership` reads the backend's count of deletes since the last
/// refresh. A refresh that ran would have zeroed it, so a count still at the
/// threshold is a refresh still owed.
pub(crate) fn assert_interrupted_refresh_keeps_live_keys_reachable<P>(
    gate_passes: impl Fn(&P, u64) -> bool,
    stale_membership: impl Fn(&P) -> usize,
) where
    P: TableBackend<PanicHashKey, u64, Hasher = FixedHashBuilder, Alloc = ToggleAllocator>,
{
    let armed = Arc::new(AtomicBool::new(false));
    let never = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let fail = Arc::new(AtomicBool::new(false));
    let mut map: HashMap<PanicHashKey, u64, P> = HashMap::with_capacity_and_reserve_and_hasher_in(
        56,
        ReserveFraction::DEFAULT,
        fixed_hasher(),
        ToggleAllocator::new(Arc::clone(&fail)),
    );
    let live = map.capacity() as u64 - 1;
    let churn = live;
    let threshold = membership::refresh_deletes(map.capacity());
    let key = |id: u64| PanicHashKey {
        id,
        // The churned key is hashed by its own removal, so it never arms.
        armed: Arc::clone(if id == churn { &never } else { &armed }),
        drops: Arc::clone(&drops),
    };
    for id in 0..live {
        assert_eq!(map.insert(key(id), id), None);
    }
    let generation = map.epoch().generation;
    let assert_live_keys_reachable = |map: &HashMap<PanicHashKey, u64, P>| {
        assert_eq!(map.len() as u64, live);
        assert_eq!(map.iter().count() as u64, live);
        assert!(!map.contains_key(&key(churn)));
        for id in 0..live {
            assert_eq!(map.get(&key(id)), Some(&id), "key {id}");
        }
    };

    // Cycling one key re-takes its tombstone, so only the stale count grows
    // and the removal that passes the threshold refreshes the filter, which
    // hashes the armed live keys.
    let mut unwound = false;
    for _ in 0..=threshold {
        let stale = stale_membership(map.table());
        assert_eq!(map.insert(key(churn), churn), None);
        armed.store(true, Ordering::SeqCst);
        let removed = catch_unwind(AssertUnwindSafe(|| map.remove(&key(churn))));
        armed.store(false, Ordering::SeqCst);
        if removed.is_err() {
            unwound = true;
            break;
        }
        assert_eq!(stale_membership(map.table()), stale + 1);
    }
    assert!(unwound, "no refresh hashed a live key");
    assert_eq!(map.epoch().generation, generation, "a rebuild ran");
    assert_live_keys_reachable(&map);
    // The unwound refresh left the filter recording every live key.
    for id in 0..live {
        let hash = map.hasher().hash_one(key(id));
        assert!(gate_passes(map.table(), hash), "key {id} unrecorded");
    }
    assert!(stale_membership(map.table()) >= threshold);

    // Without scratch memory the refresh is skipped and stays owed.
    assert_eq!(map.insert(key(churn), churn), None);
    fail.store(true, Ordering::SeqCst);
    assert_eq!(map.remove(&key(churn)), Some(churn));
    fail.store(false, Ordering::SeqCst);
    assert_live_keys_reachable(&map);
    assert!(stale_membership(map.table()) >= threshold);

    // The owed refresh runs at the next settling delete.
    assert_eq!(map.insert(key(churn), churn), None);
    assert_eq!(map.remove(&key(churn)), Some(churn));
    assert_eq!(stale_membership(map.table()), 0);
    assert_eq!(map.epoch().generation, generation, "a rebuild ran");
    assert_live_keys_reachable(&map);

    for id in 0..live {
        assert_eq!(map.remove(&key(id)), Some(id));
    }
    assert!(map.is_empty());
    for id in 0..live {
        assert_eq!(map.insert(key(id), id + 1), None);
        assert_eq!(map.get(&key(id)), Some(&(id + 1)));
    }
}

/// `clear` turns each slot into a tombstone before its value drops, so a
/// value whose drop panics leaves the table counting and reaching exactly
/// the entries not yet dropped, and a second `clear` finishes the job.
///
/// `controls` lists the backend's control bytes in slot order;
/// `assert_counts_match_controls` checks its counts against them.
pub(crate) fn assert_clear_tombstones_each_slot_before_dropping_its_value<P>(
    controls: impl Fn(&P) -> Vec<u8>,
    assert_counts_match_controls: impl Fn(&P),
) where
    P: TableBackend<u64, PanicOnFirstDrop, Hasher = FixedHashBuilder, Alloc = Global>,
{
    let drops = Arc::new(AtomicUsize::new(0));
    let mut map: ManuallyDrop<HashMap<u64, PanicOnFirstDrop, P>> =
        ManuallyDrop::new(Deterministic::with_capacity(32));
    for key in 0..3 {
        map.insert(key, PanicOnFirstDrop(Arc::clone(&drops)));
    }
    let first_occupied = controls(map.table())
        .into_iter()
        .position(control::is_occupied)
        .unwrap();

    assert!(catch_unwind(AssertUnwindSafe(|| map.clear())).is_err());
    let after = controls(map.table());
    assert_eq!(after[first_occupied], CTRL_TOMBSTONE);
    let tombstone = after.iter().rposition(|&c| c == CTRL_TOMBSTONE);
    assert_eq!(tombstone, Some(first_occupied), "one tombstone");
    assert_eq!(
        map.len(),
        after.iter().filter(|&&c| control::is_occupied(c)).count()
    );
    assert_counts_match_controls(map.table());

    map.clear();
    assert!(map.is_empty());
    assert_eq!(drops.load(Ordering::SeqCst), 3);
    // SAFETY: `map` is not used after this drop.
    unsafe { ManuallyDrop::drop(&mut map) };
}

/// A key whose `Hash` panics while a resize rehashes it leaves the table
/// as it was: every entry counted, reachable and undropped. The table then
/// takes an insert and a resize, and drops every value once.
///
/// `assert_counts_match_controls` checks the backend's counts against its
/// occupied control bytes.
pub(crate) fn assert_hash_panic_during_resize_keeps_every_entry<P>(
    assert_counts_match_controls: impl Fn(&P),
) where
    P: TableBackend<PanicHashKey, CountDrop, Hasher = FixedHashBuilder, Alloc = Global>,
{
    const LIVE: u64 = 16;
    let armed = Arc::new(AtomicBool::new(false));
    let drops = Arc::new(AtomicUsize::new(0));
    let key_drops = Arc::new(AtomicUsize::new(0));
    let key = |id: u64| PanicHashKey {
        id,
        armed: Arc::clone(&armed),
        drops: Arc::clone(&key_drops),
    };
    let mut map: HashMap<PanicHashKey, CountDrop, P> = Deterministic::with_capacity(32);
    for id in 0..LIVE {
        assert!(map.insert(key(id), CountDrop(Arc::clone(&drops))).is_none());
    }
    let capacity = map.capacity();

    armed.store(true, Ordering::SeqCst);
    let result = catch_unwind(AssertUnwindSafe(|| map.try_reserve(4_096)));
    armed.store(false, Ordering::SeqCst);
    assert!(result.is_err());
    assert_eq!(map.capacity(), capacity);
    assert_eq!(map.len() as u64, LIVE);
    assert_counts_match_controls(map.table());
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(key_drops.load(Ordering::SeqCst), 0);
    for id in 0..LIVE {
        assert!(map.contains_key(&key(id)), "key {id}");
    }

    assert!(
        map.insert(key(100), CountDrop(Arc::clone(&drops)))
            .is_none()
    );
    assert_counts_match_controls(map.table());
    map.try_reserve(4_096).unwrap();
    for id in (0..LIVE).chain([100]) {
        assert!(map.contains_key(&key(id)), "key {id}");
    }
    drop(map);
    assert_eq!(drops.load(Ordering::SeqCst) as u64, LIVE + 1);
}

/// Work-queue churn at fixed capacity: pop the first key in iteration order,
/// push a fresh one. Popping in slot order drains the first level while fresh
/// keys overflow deeper, so placements eventually exhaust their prescribed
/// candidates. Each exhaustion must end in a rebuild that restores paper
/// placement, never in a permanent full-scan mode.
///
/// `exceptional` reports whether the backend is in its full-scan fallback.
pub(crate) fn assert_pop_first_churn_restores_paper_placement<P>(exceptional: impl Fn(&P) -> bool)
where
    P: TableBackend<u64, u64, Hasher = FixedHashBuilder, Alloc = Global>,
{
    let mut map: HashMap<u64, u64, P> = Deterministic::with_capacity(2_048);
    let capacity = map.capacity();
    let mut live = std::collections::HashSet::new();
    let mut next_key = 0_u64;
    while map.len() < capacity {
        map.insert(next_key, next_key);
        live.insert(next_key);
        next_key += 1;
    }

    for _ in 0..capacity * 8 {
        let first = *map.keys().next().unwrap();
        assert_eq!(map.remove(&first), Some(first));
        live.remove(&first);
        map.insert(next_key, next_key);
        live.insert(next_key);
        next_key += 1;
        assert!(
            !exceptional(map.table()),
            "churn left the full-scan fallback on"
        );
    }

    assert_eq!(map.capacity(), capacity);
    assert_eq!(map.len(), live.len());
    assert!(live.iter().all(|key| map.get(key) == Some(key)));
}
