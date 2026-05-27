use std::marker::PhantomData;
use std::ptr;

use allocator_api2::alloc::Layout;

use super::bitmask::BitMask;
use super::config::GROUP_SIZE;
use super::control::{CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use super::simd;
use super::{Allocator, TryReserveError};

/// Owns one zeroed allocation that backs a map's control bytes + slot data.
///
/// This struct intentionally has no `Drop` impl.
/// Each derived map `Drop` orchestrates the teardown order
/// by calling [`ArenaSlots::drop_values`] on each descriptor before [`Arena::deallocate`].
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

    /// Allocates uninit memory, zeroing only the first `ctrl_bytes`.
    /// Slots live past that and are written-then-read,
    /// so skipping their memset cuts setup work + cache pollution.
    /// Size-0 layouts return a dangling pointer.
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

/// One stored entry in the arena's data section. K and V live next to each
/// other so a `read` / `drop_in_place` touches both in one shot.
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

/// Scan position for [`ArenaSlots::scan_next`]: next group + cached mask of
/// the in-progress group. Construct a fresh one before switching descriptors.
#[derive(Debug, Clone)]
pub(crate) struct OccupiedCursor {
    pub(crate) next_group_slot: usize,
    pub(crate) current_group_slot: usize,
    pub(crate) current_mask: BitMask,
}

impl OccupiedCursor {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            next_group_slot: 0,
            current_group_slot: 0,
            current_mask: BitMask(0),
        }
    }
}

/// Per-region view of a map's arena.
/// `&Arena` args are borrow-proof only; LLVM elides them.
pub(crate) trait ArenaSlots<K, V> {
    fn ctrl_ptr(&self) -> *mut u8;
    fn data_ptr(&self) -> *mut SlotEntry<K, V>;
    fn capacity(&self) -> usize;

    #[inline]
    fn ctrl(&self, _arena: &Arena) -> *mut u8 {
        self.ctrl_ptr()
    }

    #[inline]
    fn slots(&self, _arena: &Arena) -> *mut SlotEntry<K, V> {
        self.data_ptr()
    }

    #[inline]
    fn group_ctrl(&self, arena: &Arena, group_idx: usize) -> *const u8 {
        unsafe { self.ctrl(arena).add(group_idx * GROUP_SIZE) }
    }

    #[inline]
    fn control_at(&self, arena: &Arena, idx: usize) -> u8 {
        unsafe { *self.ctrl(arena).add(idx) }
    }

    #[inline]
    fn set_control(&self, arena: &Arena, idx: usize, ctrl: u8) {
        unsafe { *self.ctrl(arena).add(idx) = ctrl }
    }

    #[inline]
    fn mark_tombstone(&self, arena: &Arena, idx: usize) {
        self.set_control(arena, idx, CTRL_TOMBSTONE);
    }

    /// Wipe every ctrl byte in this region to FREE.
    /// Caller is responsible for having dropped occupied values first.
    #[inline]
    fn clear_all_controls(&self, arena: &Arena) {
        if self.capacity() == 0 {
            return;
        }
        unsafe { ptr::write_bytes(self.ctrl(arena), 0, self.capacity()) }
    }

    #[inline]
    fn write_with_control(&self, arena: &Arena, idx: usize, entry: SlotEntry<K, V>, ctrl: u8) {
        unsafe { self.slots(arena).add(idx).write(entry) }
        self.set_control(arena, idx, ctrl);
    }

    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    #[inline]
    unsafe fn get_ref(&self, arena: &Arena, idx: usize) -> &SlotEntry<K, V> {
        unsafe { &*self.slots(arena).add(idx) }
    }

    /// Takes `&mut self` as a type-level proof of exclusive access — the
    /// descriptor itself is not mutated. Without `&mut`, two calls with
    /// the same `idx` could hand out aliasing `&mut SlotEntry` (UB).
    ///
    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    #[inline]
    unsafe fn get_mut(&mut self, arena: &Arena, idx: usize) -> &mut SlotEntry<K, V> {
        unsafe { &mut *self.slots(arena).add(idx) }
    }

    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    /// The slot must not be read again before being re-written.
    #[inline]
    unsafe fn take(&self, arena: &Arena, idx: usize) -> SlotEntry<K, V> {
        unsafe { self.slots(arena).add(idx).read() }
    }

    #[inline]
    fn group_match_mask(&self, arena: &Arena, group_idx: usize, target: u8) -> BitMask {
        unsafe { simd::eq_mask_16(self.group_ctrl(arena, group_idx), target) }
    }

    #[inline]
    fn group_free_mask(&self, arena: &Arena, group_idx: usize) -> BitMask {
        unsafe { simd::free_mask_16(self.group_ctrl(arena, group_idx)) }
    }

    #[inline]
    fn first_free_in_group(&self, arena: &Arena, group_idx: usize) -> Option<usize> {
        let offset = self.group_free_mask(arena, group_idx).lowest()?;
        let slot_idx = group_idx * GROUP_SIZE + offset;
        if slot_idx < self.capacity() {
            Some(slot_idx)
        } else {
            None
        }
    }

    /// Yields the next occupied slot index, advancing `cursor`. Use directly
    /// when one cursor must persist across region transitions; otherwise
    /// prefer [`Self::occupied`] which owns its cursor.
    fn scan_next(&self, arena: &Arena, cursor: &mut OccupiedCursor) -> Option<usize> {
        loop {
            if let Some(bit) = cursor.current_mask.next() {
                return Some(cursor.current_group_slot + bit);
            }
            if cursor.next_group_slot >= self.capacity() {
                return None;
            }
            let group_idx = cursor.next_group_slot / GROUP_SIZE;
            let group_ptr = self.group_ctrl(arena, group_idx);
            let mut mask = unsafe { simd::occupied_mask_16(group_ptr) };
            let group_end = cursor.next_group_slot + GROUP_SIZE;
            if group_end > self.capacity() {
                mask = mask.truncate_to(self.capacity() - cursor.next_group_slot);
            }
            cursor.current_mask = mask;
            cursor.current_group_slot = cursor.next_group_slot;
            cursor.next_group_slot = group_end;
        }
    }

    /// Returns an iterator over occupied slot indices in this region, with
    /// the scan cursor owned internally. Callers that scan one region in
    /// one shot should use this instead of plumbing an [`OccupiedCursor`].
    fn occupied<'a>(&'a self, arena: &'a Arena) -> OccupiedIter<'a, K, V, Self>
    where
        Self: Sized,
    {
        OccupiedIter {
            descriptor: self,
            arena,
            cursor: OccupiedCursor::new(),
            _marker: PhantomData,
        }
    }

    /// Drop every K,V stored in occupied slots.
    /// Caller must call this before [`Arena::deallocate`] to avoid leaks.
    fn drop_values(&self, arena: &Arena) {
        if self.capacity() == 0 {
            return;
        }
        let ctrl = self.ctrl(arena);
        let slots = self.slots(arena);
        for idx in 0..self.capacity() {
            if unsafe { (*ctrl.add(idx)).is_occupied() } {
                unsafe { ptr::drop_in_place(slots.add(idx)) }
            }
        }
    }

    /// Drop every K,V + reset all ctrls to FREE in one pass. Clears each
    /// ctrl *before* the drop so a panicking `Drop` leaves no OCCUPIED
    /// behind to double-drop. Tombstones cleared too.
    fn drop_values_and_clear(&self, arena: &Arena) {
        if self.capacity() == 0 {
            return;
        }
        let ctrl = self.ctrl(arena);
        let slots = self.slots(arena);
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

/// Iterator over occupied slot indices in one arena region. Wraps an
/// [`OccupiedCursor`] so callers don't have to plumb one through.
pub(crate) struct OccupiedIter<'a, K, V, D: ArenaSlots<K, V> + ?Sized> {
    descriptor: &'a D,
    arena: &'a Arena,
    cursor: OccupiedCursor,
    _marker: PhantomData<*const (K, V)>,
}

impl<K, V, D: ArenaSlots<K, V> + ?Sized> Iterator for OccupiedIter<'_, K, V, D> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        self.descriptor.scan_next(self.arena, &mut self.cursor)
    }
}
