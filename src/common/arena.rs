use std::marker::PhantomData;
use std::ptr;

use allocator_api2::alloc::Layout;

use super::bitmask::BitMask;
use super::config::{CACHE_LINE, GROUP_SIZE};
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

/// Drop-guard wrapper: deallocates the arena on drop. Used by map `Drop`
/// impls so `V::drop` panics don't unwind past `arena.deallocate`.
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
/// The arena owns the allocation; descriptors borrow into it.
pub(crate) trait ArenaSlots<K, V> {
    fn ctrl_ptr(&self) -> *mut u8;
    fn data_ptr(&self) -> *mut SlotEntry<K, V>;
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
    fn write_with_control(&self, idx: usize, entry: SlotEntry<K, V>, ctrl: u8) {
        unsafe { self.data_ptr().add(idx).write(entry) }
        self.set_control(idx, ctrl);
    }

    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    #[inline]
    unsafe fn get_ref(&self, idx: usize) -> &SlotEntry<K, V> {
        unsafe { &*self.data_ptr().add(idx) }
    }

    /// Takes `&mut self` as a type-level proof of exclusive access — the
    /// descriptor itself is not mutated. Without `&mut`, two calls with
    /// the same `idx` could hand out aliasing `&mut SlotEntry` (UB).
    ///
    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    #[inline]
    unsafe fn get_mut(&mut self, idx: usize) -> &mut SlotEntry<K, V> {
        unsafe { &mut *self.data_ptr().add(idx) }
    }

    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    /// The slot must not be read again before being re-written.
    #[inline]
    unsafe fn take(&self, idx: usize) -> SlotEntry<K, V> {
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

    /// Yields the next occupied slot index, advancing `cursor`. Use directly
    /// when one cursor must persist across region transitions; otherwise
    /// prefer [`Self::occupied`] which owns its cursor.
    #[inline]
    fn scan_next(&self, cursor: &mut OccupiedCursor) -> Option<usize> {
        loop {
            if let Some(bit) = cursor.current_mask.next() {
                return Some(cursor.current_group_slot + bit);
            }
            if cursor.next_group_slot >= self.capacity() {
                return None;
            }
            let group_idx = cursor.next_group_slot / GROUP_SIZE;
            let group_ptr = self.group_ctrl(group_idx);
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
    #[inline]
    fn occupied(&self) -> OccupiedIter<'_, K, V, Self>
    where
        Self: Sized,
    {
        OccupiedIter {
            descriptor: self,
            cursor: OccupiedCursor::new(),
            _marker: PhantomData,
        }
    }

    /// Drop every K,V stored in occupied slots.
    /// Caller must call this before [`Arena::deallocate`] to avoid leaks.
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

    /// Drop every K,V + reset all ctrls to FREE in one pass. Clears each
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

/// Iterator over occupied slot indices in one arena region. Wraps an
/// [`OccupiedCursor`] so callers don't have to plumb one through.
pub(crate) struct OccupiedIter<'a, K, V, D: ArenaSlots<K, V> + ?Sized> {
    descriptor: &'a D,
    cursor: OccupiedCursor,
    _marker: PhantomData<*const (K, V)>,
}

impl<K, V, D: ArenaSlots<K, V> + ?Sized> Iterator for OccupiedIter<'_, K, V, D> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        self.descriptor.scan_next(&mut self.cursor)
    }
}
