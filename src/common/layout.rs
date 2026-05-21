use std::marker::PhantomData;
use std::ptr::{self, NonNull};

use allocator_api2::alloc::{Allocator, Global, Layout, handle_alloc_error};
use allocator_api2::boxed::Box;
use allocator_api2::vec::Vec;

use super::TryReserveError;
use super::bitmask::BitMask;
use super::config::GROUP_SIZE;
use super::math::round_up_to_group;
use super::simd::{CTRL_EMPTY, eq_mask_16, free_mask_16};

/// Fallibly allocates a zero-filled `Box<[T], A>` in `alloc`.
pub(crate) fn try_zeroed_boxed_slice_in<T: Default + Clone, A: Allocator>(
    len: usize,
    alloc: A,
) -> Result<Box<[T], A>, TryReserveError> {
    let mut buf: Vec<T, A> = Vec::new_in(alloc);
    buf.try_reserve_exact(len)
        .map_err(|_| TryReserveError::AllocError)?;
    buf.resize(len, T::default());
    Ok(buf.into_boxed_slice())
}

/// Alignment for the control-byte region. Matches 64-byte cache lines so
/// the first group is line-aligned and groups pack 4-per-line without splits.
const CONTROL_ALIGN: usize = 64;

pub(crate) struct Entry<K, V> {
    pub(crate) key: K,
    pub(crate) value: V,
}

/// A flat hash table: one allocation holds slots then control bytes.
///
/// ```text
/// [slots: capacity * sizeof(T)] [padding for 16-byte alignment] [controls: group_count * 16]
/// ```
///
/// `data_ptr` points to the start of the slots array. Control bytes live at
/// a fixed offset after the slots, accessed via `ctrl_ptr()`.
pub(crate) struct RawTable<T, A: Allocator = Global> {
    data_ptr: NonNull<u8>,
    ctrl_ptr: NonNull<u8>,
    capacity: usize,
    group_count: usize,
    alloc: A,
    _marker: PhantomData<T>,
}

// SAFETY: RawTable<T, A> owns its allocation exclusively; data_ptr is not aliased.
// Sending across threads is sound when T: Send and A: Send. Sync requires T: Sync
// because shared &RawTable<T, A> can hand out shared &T via get_ref.
unsafe impl<T: Send, A: Allocator + Send> Send for RawTable<T, A> {}
unsafe impl<T: Sync, A: Allocator + Sync> Sync for RawTable<T, A> {}

impl<T, A: Allocator> std::fmt::Debug for RawTable<T, A> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawTable")
            .field("capacity", &self.capacity)
            .field("group_count", &self.group_count)
            .finish_non_exhaustive()
    }
}

impl<T, A: Allocator> Drop for RawTable<T, A> {
    fn drop(&mut self) {
        if self.capacity > 0 {
            let (layout, _) = Self::unified_layout(self.capacity, self.group_count);
            unsafe { self.alloc.deallocate(self.data_ptr, layout) };
        }
    }
}

impl<T, A: Allocator> RawTable<T, A> {
    pub fn new_in(capacity: usize, alloc: A) -> Self {
        if capacity == 0 {
            return Self::empty_in(alloc);
        }

        let capacity = round_up_to_group(capacity);
        let group_count = capacity / GROUP_SIZE;
        let (layout, ctrl_offset) = Self::unified_layout(capacity, group_count);

        let data_ptr = alloc
            .allocate_zeroed(layout)
            .unwrap_or_else(|_| handle_alloc_error(layout))
            .cast::<u8>();
        // SAFETY: `ctrl_offset` is within the allocation produced for `layout`.
        let ctrl_ptr = unsafe { NonNull::new_unchecked(data_ptr.as_ptr().add(ctrl_offset)) };

        Self {
            data_ptr,
            ctrl_ptr,
            capacity,
            group_count,
            alloc,
            _marker: PhantomData,
        }
    }

    /// Fallible counterpart to [`RawTable::new_in`]. Returns `Err(())` on layout
    /// overflow or allocator failure; used by `try_reserve`.
    pub fn try_new_in(capacity: usize, alloc: A) -> Result<Self, ()> {
        if capacity == 0 {
            return Ok(Self::empty_in(alloc));
        }

        let capacity = round_up_to_group(capacity);
        let group_count = capacity / GROUP_SIZE;
        let (layout, ctrl_offset) = Self::try_unified_layout(capacity, group_count).ok_or(())?;

        let data_ptr = alloc.allocate_zeroed(layout).map_err(|_| ())?.cast::<u8>();
        // SAFETY: `ctrl_offset` is within the allocation produced for `layout`.
        let ctrl_ptr = unsafe { NonNull::new_unchecked(data_ptr.as_ptr().add(ctrl_offset)) };

        Ok(Self {
            data_ptr,
            ctrl_ptr,
            capacity,
            group_count,
            alloc,
            _marker: PhantomData,
        })
    }

    #[inline]
    fn empty_in(alloc: A) -> Self {
        Self {
            data_ptr: NonNull::dangling(),
            ctrl_ptr: NonNull::dangling(),
            capacity: 0,
            group_count: 0,
            alloc,
            _marker: PhantomData,
        }
    }

    /// Layout: `[slots (T-aligned)] [padding] [controls (64-aligned)]`.
    fn unified_layout(capacity: usize, group_count: usize) -> (Layout, usize) {
        Self::try_unified_layout(capacity, group_count).expect("layout overflow")
    }

    fn try_unified_layout(capacity: usize, group_count: usize) -> Option<(Layout, usize)> {
        let slots_layout = Layout::array::<T>(capacity).ok()?;
        let ctrl_bytes = group_count.checked_mul(GROUP_SIZE)?;
        let controls_layout = Layout::from_size_align(ctrl_bytes, CONTROL_ALIGN).ok()?;
        let (combined, ctrl_offset) = slots_layout.extend(controls_layout).ok()?;
        Some((combined.pad_to_align(), ctrl_offset))
    }

    #[inline]
    fn slots_ptr(&self) -> *mut T {
        self.data_ptr.as_ptr().cast::<T>()
    }

    /// Raw pointer to slot `idx` without reborrowing `&self`. Lets callers
    /// project to disjoint `&mut V` from multiple slots without going
    /// through `&mut RawTable` (which would alias under Stacked Borrows).
    ///
    /// # Safety
    ///
    /// `this` must point to a live `RawTable`. `idx` must be `< capacity()`.
    #[inline]
    pub(crate) unsafe fn slot_ptr_raw(this: *mut Self, idx: usize) -> *mut T {
        let data_field: *mut NonNull<u8> = unsafe { &raw mut (*this).data_ptr };
        let base: *mut u8 = unsafe { data_field.read() }.as_ptr();
        unsafe { base.cast::<T>().add(idx) }
    }

    #[inline]
    fn ctrl_ptr(&self) -> *mut u8 {
        self.ctrl_ptr.as_ptr()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    #[inline]
    pub fn group_count(&self) -> usize {
        self.group_count
    }

    #[inline]
    pub fn group_data_ptr(&self, group_idx: usize) -> *const u8 {
        debug_assert!(
            group_idx < self.group_count,
            "group_data_ptr: group_idx {group_idx} >= group_count {}",
            self.group_count
        );
        unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) }
    }

    /// Prefetch the cache line containing slot `idx`. Call before a probable
    /// `get_ref(idx)` to overlap memory latency with the fingerprint scan.
    ///
    /// # Safety
    ///
    /// `self.capacity > 0` and `idx < self.capacity`. On empty tables
    /// `data_ptr` is `NonNull::dangling()`; pointer arithmetic on a dangling
    /// ptr is UB regardless of whether the result is dereferenced.
    #[inline]
    pub(crate) unsafe fn prefetch_slot(&self, idx: usize) {
        debug_assert!(self.capacity > 0, "prefetch_slot: empty table");
        debug_assert!(
            idx < self.capacity,
            "prefetch_slot: idx {idx} >= capacity {}",
            self.capacity
        );
        // SAFETY: caller upholds `capacity > 0` and `idx < capacity`.
        unsafe {
            super::simd::prefetch_read(self.slots_ptr().add(idx).cast::<u8>());
        }
    }

    #[inline]
    pub fn control_at(&self, idx: usize) -> u8 {
        debug_assert!(
            idx < self.capacity,
            "control_at: idx {idx} >= capacity {}",
            self.capacity
        );
        unsafe { *self.ctrl_ptr().add(idx) }
    }

    #[inline]
    pub fn write(&mut self, idx: usize, value: T) {
        debug_assert!(
            idx < self.capacity,
            "write: idx {idx} >= capacity {}",
            self.capacity
        );
        unsafe { self.slots_ptr().add(idx).write(value) };
    }

    #[inline]
    pub fn write_with_control(&mut self, idx: usize, value: T, control: u8) {
        self.write(idx, value);
        self.set_control(idx, control);
    }

    #[inline]
    pub fn set_control(&mut self, idx: usize, new_control: u8) {
        debug_assert!(
            idx < self.capacity,
            "set_control: idx {idx} >= capacity {}",
            self.capacity
        );
        unsafe { *self.ctrl_ptr().add(idx) = new_control };
    }

    #[inline]
    pub fn mark_tombstone(&mut self, idx: usize) {
        self.set_control(idx, super::control::CTRL_TOMBSTONE);
    }

    /// Erase `idx`. Returns `true` if tombstone set; `false` if slot reset to `EMPTY`
    /// because the group already terminated probing — avoids load-factor inflation.
    #[inline]
    pub fn erase(&mut self, idx: usize) -> bool {
        let group_idx = idx / GROUP_SIZE;
        let ptr = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        let group_has_empty = unsafe { eq_mask_16(ptr, CTRL_EMPTY).any() };
        if group_has_empty {
            self.set_control(idx, CTRL_EMPTY);
            false
        } else {
            self.set_control(idx, super::control::CTRL_TOMBSTONE);
            true
        }
    }

    #[inline]
    pub fn clear_all_controls(&mut self) {
        if self.group_count == 0 {
            return;
        }
        unsafe {
            ptr::write_bytes(self.ctrl_ptr(), 0, self.group_count * GROUP_SIZE);
        }
    }

    #[inline]
    pub unsafe fn get_ref(&self, idx: usize) -> &T {
        debug_assert!(
            idx < self.capacity,
            "get_ref: idx {idx} >= capacity {}",
            self.capacity
        );
        unsafe { &*self.slots_ptr().add(idx) }
    }

    #[inline]
    pub unsafe fn get_mut(&mut self, idx: usize) -> &mut T {
        debug_assert!(
            idx < self.capacity,
            "get_mut: idx {idx} >= capacity {}",
            self.capacity
        );
        unsafe { &mut *self.slots_ptr().add(idx) }
    }

    #[inline]
    pub unsafe fn take(&mut self, idx: usize) -> T {
        debug_assert!(
            idx < self.capacity,
            "take: idx {idx} >= capacity {}",
            self.capacity
        );
        unsafe { self.slots_ptr().add(idx).read() }
    }

    #[inline]
    pub unsafe fn drop_in_place(&mut self, idx: usize) {
        debug_assert!(
            idx < self.capacity,
            "drop_in_place: idx {idx} >= capacity {}",
            self.capacity
        );
        unsafe { ptr::drop_in_place(self.slots_ptr().add(idx)) }
    }

    #[inline]
    pub fn group_match_mask(&self, group_idx: usize, target: u8) -> BitMask {
        debug_assert!(
            group_idx < self.group_count,
            "group_match_mask: group_idx {group_idx} >= group_count {}",
            self.group_count
        );
        let ptr = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        unsafe { eq_mask_16(ptr, target) }
    }

    #[inline]
    pub fn group_free_mask(&self, group_idx: usize) -> BitMask {
        debug_assert!(
            group_idx < self.group_count,
            "group_free_mask: group_idx {group_idx} >= group_count {}",
            self.group_count
        );
        let ptr = unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) };
        unsafe { free_mask_16(ptr) }
    }

    #[inline]
    pub fn first_free_in_group(&self, group_idx: usize) -> Option<usize> {
        let offset = self.group_free_mask(group_idx).lowest()?;
        let slot_idx = group_idx * GROUP_SIZE + offset;
        if slot_idx < self.capacity {
            Some(slot_idx)
        } else {
            None
        }
    }
}
