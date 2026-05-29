use std::ptr;

use allocator_api2::alloc::{Allocator, Layout};

use super::bitmask::BitMask;
use super::config::{CACHE_LINE, GROUP_SIZE};
use super::control::{CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use super::error::TryReserveError;
use super::iter::RegionIter;
use super::simd;

/// Owns one zeroed allocation backing a map's ctrl bytes + slot data.
/// No `Drop` impl — derived maps orchestrate teardown by calling
/// [`ArenaSlots::drop_values`] on each descriptor before [`Arena::deallocate`].
pub(crate) struct Arena {
    ptr: ptr::NonNull<u8>,
    layout: Layout,
}

impl Arena {
    /// Sentinel placeholder for moved-from / zero-capacity maps.
    /// Layout size is 0 so `deallocate` is a no-op.
    #[inline]
    pub(crate) const fn empty() -> Self {
        Self {
            ptr: ptr::NonNull::dangling(),
            layout: unsafe { Layout::from_size_align_unchecked(0, 1) },
        }
    }

    /// Allocates uninit memory, zeroing only the first `ctrl_bytes`. Slots
    /// past that are written-then-read, so skipping their memset cuts
    /// setup work + cache pollution. Size-0 layouts return dangling.
    pub(crate) fn try_allocate_with_ctrl_zeroed<A: Allocator>(
        layout: Layout,
        ctrl_bytes: usize,
        alloc: &A,
    ) -> Result<Self, TryReserveError> {
        if layout.size() == 0 {
            return Ok(Self::empty());
        }
        let ptr = alloc
            .allocate(layout)
            .map_err(|_| TryReserveError::AllocError)?
            .cast::<u8>();
        if ctrl_bytes > 0 {
            unsafe { ptr::write_bytes(ptr.as_ptr(), 0, ctrl_bytes) };
        }
        Ok(Self { ptr, layout })
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Frees the backing allocation. Caller must have already run any
    /// destructors for values living inside.
    pub(crate) fn deallocate<A: Allocator>(self, alloc: &A) {
        if self.layout.size() == 0 {
            return;
        }
        unsafe { alloc.deallocate(self.ptr, self.layout) };
    }
}

/// Combined ctrl+data layout for an arena whose ctrl section holds
/// `total_ctrl` bytes and data section holds `total_ctrl` slots.
/// Returns `(layout, data_offset_within_arena)`.
pub(crate) fn layout_for<K, V>(total_ctrl: usize) -> Result<(Layout, usize), TryReserveError> {
    let total_ctrl = total_ctrl.max(1);
    let ctrl_layout =
        Layout::from_size_align(total_ctrl, CACHE_LINE).map_err(|_| TryReserveError::AllocError)?;
    let data_layout =
        Layout::array::<SlotEntry<K, V>>(total_ctrl).map_err(|_| TryReserveError::AllocError)?;
    let (arena_layout, data_base_off) = ctrl_layout
        .extend(data_layout)
        .map_err(|_| TryReserveError::AllocError)?;
    Ok((arena_layout.pad_to_align(), data_base_off))
}

/// O(N²) alias check for [`get_disjoint_mut`]-style APIs: panics if two
/// `Some` locations collide. `T: PartialEq` so it works for both raw
/// `(level_idx, slot_idx)` tuples and richer `SlotLocation` enums.
#[inline]
pub(crate) fn check_disjoint_aliasing<T: PartialEq, const N: usize>(locations: &[Option<T>; N]) {
    for (i, li) in locations.iter().enumerate() {
        let Some(li) = li else { continue };
        for other in &locations[i + 1..] {
            assert!(
                other.as_ref() != Some(li),
                "get_disjoint_mut: duplicate keys resolve to the same entry",
            );
        }
    }
}

/// Drop-guard: deallocates the arena on drop, so `V::drop` panics in the
/// map's Drop still free the allocation.
pub(crate) struct DeallocGuard<'a, A: Allocator> {
    arena: Option<Arena>,
    alloc: &'a A,
}

impl<'a, A: Allocator> DeallocGuard<'a, A> {
    #[inline]
    pub(crate) fn new(arena: Arena, alloc: &'a A) -> Self {
        Self {
            arena: Some(arena),
            alloc,
        }
    }
}

impl<A: Allocator> Drop for DeallocGuard<'_, A> {
    fn drop(&mut self) {
        if let Some(arena) = self.arena.take() {
            arena.deallocate(self.alloc);
        }
    }
}

/// One slot's `(key, value)` pair. Co-located so `read`/`drop_in_place`
/// touches both in one shot.
pub(crate) struct SlotEntry<K, V> {
    pub(crate) key: K,
    pub(crate) value: V,
}

impl<K: Clone, V: Clone> Clone for SlotEntry<K, V> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            value: self.value.clone(),
        }
    }
}

/// Clone one arena region's slots in panic-safe order: clone → write →
/// stamp OCCUPIED ctrl. A panic mid-loop leaves `dst` with OCCUPIED only
/// on fully-written slots. TOMBSTONE bytes copied in a second pass.
pub(crate) fn clone_region_panic_safe<K: Clone, V: Clone>(
    src_ctrl: *const u8,
    dst_ctrl: *mut u8,
    src_slots: *const SlotEntry<K, V>,
    dst_slots: *mut SlotEntry<K, V>,
    capacity: usize,
) {
    for idx in 0..capacity {
        let ctrl = unsafe { *src_ctrl.add(idx) };
        if ctrl.is_occupied() {
            let cloned = unsafe { (*src_slots.add(idx)).clone() };
            unsafe { dst_slots.add(idx).write(cloned) };
            unsafe { *dst_ctrl.add(idx) = ctrl };
        }
    }
    for idx in 0..capacity {
        let ctrl = unsafe { *src_ctrl.add(idx) };
        if ctrl == CTRL_TOMBSTONE {
            unsafe { *dst_ctrl.add(idx) = CTRL_TOMBSTONE };
        }
    }
}

/// Per-region view of a map's arena. Descriptors borrow into the arena
/// allocation, parameterized by slot type `T`.
pub(crate) trait ArenaSlots<T> {
    fn ctrl_ptr(&self) -> *mut u8;
    fn data_ptr(&self) -> *mut T;
    fn capacity(&self) -> usize;

    #[inline]
    fn group_ctrl(&self, group_idx: usize) -> *const u8 {
        unsafe { self.ctrl_ptr().add(group_idx * GROUP_SIZE) }
    }

    #[inline]
    fn control_at(&self, idx: usize) -> u8 {
        unsafe { *self.ctrl_ptr().add(idx) }
    }

    #[inline]
    fn set_control(&self, idx: usize, ctrl: u8) {
        unsafe { *self.ctrl_ptr().add(idx) = ctrl }
    }

    #[inline]
    fn mark_tombstone(&self, idx: usize) {
        self.set_control(idx, CTRL_TOMBSTONE);
    }

    /// Wipe every ctrl byte in this region to FREE.
    /// Caller is responsible for having dropped occupied values first.
    #[inline]
    fn clear_all_controls(&self) {
        if self.capacity() == 0 {
            return;
        }
        unsafe { ptr::write_bytes(self.ctrl_ptr(), 0, self.capacity()) }
    }

    #[inline]
    fn write_with_control(&self, idx: usize, entry: T, ctrl: u8) {
        unsafe { self.data_ptr().add(idx).write(entry) }
        self.set_control(idx, ctrl);
    }

    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    #[inline]
    unsafe fn get_ref(&self, idx: usize) -> &T {
        unsafe { &*self.data_ptr().add(idx) }
    }

    /// `&mut self` is a type-level proof of exclusive access — without it,
    /// two calls with the same `idx` could hand out aliasing `&mut T` (UB).
    ///
    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    #[inline]
    unsafe fn get_mut(&mut self, idx: usize) -> &mut T {
        unsafe { &mut *self.data_ptr().add(idx) }
    }

    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    /// The slot must not be read again before being re-written.
    #[inline]
    unsafe fn take(&self, idx: usize) -> T {
        unsafe { self.data_ptr().add(idx).read() }
    }

    #[inline]
    fn group_match_mask(&self, group_idx: usize, target: u8) -> BitMask {
        unsafe { simd::eq_mask_16(self.group_ctrl(group_idx), target) }
    }

    #[inline]
    fn group_free_mask(&self, group_idx: usize) -> BitMask {
        unsafe { simd::free_mask_16(self.group_ctrl(group_idx)) }
    }

    #[inline]
    fn first_free_in_group(&self, group_idx: usize) -> Option<usize> {
        let offset = self.group_free_mask(group_idx).lowest()?;
        let slot_idx = group_idx * GROUP_SIZE + offset;
        if slot_idx < self.capacity() {
            Some(slot_idx)
        } else {
            None
        }
    }

    /// `Iterator<usize>` over occupied slot indices in this single region.
    #[inline]
    fn occupied(&self) -> RegionIter<'_, T, Self>
    where
        Self: Sized,
    {
        RegionIter::new(std::slice::from_ref(self))
    }

    /// Drop every value in occupied slots. Call before [`Arena::deallocate`].
    fn drop_values(&self) {
        if self.capacity() == 0 {
            return;
        }
        let ctrl = self.ctrl_ptr();
        let slots = self.data_ptr();
        for idx in 0..self.capacity() {
            if unsafe { (*ctrl.add(idx)).is_occupied() } {
                unsafe { ptr::drop_in_place(slots.add(idx)) }
            }
        }
    }

    /// Drop every value + reset all ctrls to FREE in one pass. Clears each
    /// ctrl *before* the drop so a panicking `Drop` leaves no OCCUPIED
    /// behind to double-drop. Tombstones cleared too.
    fn drop_values_and_clear(&self) {
        if self.capacity() == 0 {
            return;
        }
        let ctrl = self.ctrl_ptr();
        let slots = self.data_ptr();
        for idx in 0..self.capacity() {
            unsafe {
                let prev = *ctrl.add(idx);
                *ctrl.add(idx) = CTRL_EMPTY;
                if prev.is_occupied() {
                    ptr::drop_in_place(slots.add(idx));
                }
            }
        }
    }
}
