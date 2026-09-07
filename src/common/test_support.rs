//! Test-only fixtures shared by both backend test modules.

use core::hash::{BuildHasher, Hash, Hasher};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use alloc::sync::Arc;
use allocator_api2::alloc::{AllocError, Allocator, Global, Layout};

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
