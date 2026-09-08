//! Allocation accounting for the memory harness: a counting global allocator
//! and the snapshot arithmetic that turns two readings into per-map costs.
//!
//! Bytes are the layouts requested from the system allocator, not usable size
//! or RSS. Counters are process-global; callers keep the measured window
//! single-threaded so nothing unrelated enters it.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationSnapshot {
    pub live_bytes: usize,
    /// High-water mark of `live_bytes` since the last [`CountingAllocator::reset_peak`].
    pub peak_live_bytes: usize,
    pub live_allocations: usize,
    pub allocation_calls: usize,
    pub allocated_bytes: usize,
}

/// Difference between two snapshots, attributed to `live_entries` map entries.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationMeasurement {
    pub live_entries: usize,
    pub live_bytes: usize,
    /// Extra bytes the window held at its highest point above the starting
    /// live total; equals `live_bytes` for a single allocation, larger when a
    /// resize copies old storage into new.
    pub peak_live_bytes: usize,
    pub live_allocations: usize,
    pub allocation_calls: usize,
    pub allocated_bytes: usize,
}

pub struct AllocationCounters {
    live_bytes: AtomicUsize,
    peak_live_bytes: AtomicUsize,
    live_allocations: AtomicUsize,
    allocation_calls: AtomicUsize,
    allocated_bytes: AtomicUsize,
}

impl AllocationCounters {
    pub const fn new() -> Self {
        Self {
            live_bytes: AtomicUsize::new(0),
            peak_live_bytes: AtomicUsize::new(0),
            live_allocations: AtomicUsize::new(0),
            allocation_calls: AtomicUsize::new(0),
            allocated_bytes: AtomicUsize::new(0),
        }
    }
}

pub struct CountingAllocator {
    counters: &'static AllocationCounters,
}

impl CountingAllocator {
    pub const fn new(counters: &'static AllocationCounters) -> Self {
        Self { counters }
    }

    pub fn snapshot(&self) -> AllocationSnapshot {
        let c = self.counters;
        AllocationSnapshot {
            live_bytes: c.live_bytes.load(Ordering::Relaxed),
            peak_live_bytes: c.peak_live_bytes.load(Ordering::Relaxed),
            live_allocations: c.live_allocations.load(Ordering::Relaxed),
            allocation_calls: c.allocation_calls.load(Ordering::Relaxed),
            allocated_bytes: c.allocated_bytes.load(Ordering::Relaxed),
        }
    }

    /// Start a new peak window at the current live total. Call before the
    /// `before` snapshot of a measurement.
    pub fn reset_peak(&self) {
        let live = self.counters.live_bytes.load(Ordering::Relaxed);
        self.counters.peak_live_bytes.store(live, Ordering::Relaxed);
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let c = self.counters;
            let live = c.live_bytes.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            c.peak_live_bytes.fetch_max(live, Ordering::Relaxed);
            c.live_allocations.fetch_add(1, Ordering::Relaxed);
            c.allocation_calls.fetch_add(1, Ordering::Relaxed);
            c.allocated_bytes
                .fetch_add(layout.size(), Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        self.counters
            .live_bytes
            .fetch_sub(layout.size(), Ordering::Relaxed);
        self.counters
            .live_allocations
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl AllocationMeasurement {
    /// `before` must be taken right after [`CountingAllocator::reset_peak`].
    pub fn between(
        before: AllocationSnapshot,
        after: AllocationSnapshot,
        live_entries: usize,
    ) -> Self {
        assert!(
            live_entries > 0,
            "allocation measurement needs live entries"
        );
        let delta = |field: fn(&AllocationSnapshot) -> usize, what: &str| {
            field(&after)
                .checked_sub(field(&before))
                .unwrap_or_else(|| panic!("{what} moved backwards across the measured window"))
        };
        Self {
            live_entries,
            live_bytes: delta(|s| s.live_bytes, "live bytes"),
            peak_live_bytes: after
                .peak_live_bytes
                .checked_sub(before.live_bytes)
                .expect("peak window started above the live total"),
            live_allocations: delta(|s| s.live_allocations, "live allocations"),
            allocation_calls: delta(|s| s.allocation_calls, "allocation calls"),
            allocated_bytes: delta(|s| s.allocated_bytes, "allocated bytes"),
        }
    }

    /// `count` spread over the measured entries.
    #[allow(clippy::cast_precision_loss)]
    pub fn per_entry(self, count: usize) -> f64 {
        count as f64 / self.live_entries as f64
    }
}
