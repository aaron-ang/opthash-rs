//! Test-only fixtures shared by both backend test modules.

use core::hash::{BuildHasher, Hash, Hasher};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::sync::Arc;
use alloc::vec::Vec;
use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};

use crate::common::DefaultHashBuilder;
use crate::common::membership;
use crate::map::{HashMap, TableBackend};

/// Hashes a `u64` to itself, so test keys double as their own hashes.
#[derive(Clone, Copy, Default)]
pub(crate) struct IdentityBuildHasher;

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
/// refresh.
pub(crate) fn assert_deletes_past_threshold_refresh_filter<P>(
    gate_passes: impl Fn(&P, u64) -> bool,
    stale_membership: impl Fn(&P) -> usize,
) where
    P: TableBackend<u64, u64, Hasher = DefaultHashBuilder, Alloc = Global>,
{
    let mut map: HashMap<u64, u64, P> = HashMap::with_capacity(2_048);
    let live = map.capacity() as u64;
    let threshold = membership::refresh_deletes(map.capacity()) as u64;
    for key in 0..live {
        map.insert(key, key);
    }

    // A third of the keys: enough to matter, below every cleanup threshold.
    let departed = (0..live).filter(|key| key % 3 == 0).collect::<Vec<_>>();
    for &key in &departed {
        assert_eq!(map.remove(&key), Some(key));
    }
    assert!(departed.iter().all(|&key| gate_passes(map.table(), key)));
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
        assert!(cycles <= threshold, "refresh never ran");
    }
    assert_eq!(cycles + departed.len() as u64, threshold + 1);
    assert_eq!(map.epoch().generation, 0, "no rebuild ran");
    assert_eq!(stale_membership(map.table()), 0, "refresh resets the count");

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
