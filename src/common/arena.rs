use std::marker::PhantomData;
use std::ptr;

use allocator_api2::alloc::Layout;

use super::bitmask::BitMask;
use super::config::{CACHE_LINE, GROUP_SIZE};
use super::control::{CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use super::simd;
use super::{Allocator, TryReserveError};

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

    /// Scanner over occupied slots in this single region. `Iterator<usize>`
    /// for simple walks; `next_handle()` for richer access.
    #[inline]
    fn occupied(&self) -> IterRange<'_, T, Self>
    where
        Self: Sized,
    {
        IterRange::new(std::slice::from_ref(self))
    }

    /// Drop every slot value in occupied slots.
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

/// Initial slot offset that becomes `0` after the first
/// `wrapping_add(GROUP_SIZE)` on group load.
pub(crate) const CURRENT_SLOT_INIT: usize = 0_usize.wrapping_sub(GROUP_SIZE);

/// Pointer-walk cursor over one region. Shared scan logic between
/// [`IterRange`] / [`IterRangeMut`] and inline holders that need a phase
/// machine (e.g. funnel iters spanning levels + special arrays).
pub(crate) struct ScanCursor {
    /// Ptr to the next group's first ctrl byte (or `end_ctrl` if done).
    next_ctrl: *const u8,
    /// One-past-end of the current region's ctrl bytes.
    end_ctrl: *const u8,
    /// Slot offset of the currently-loaded group. See [`CURRENT_SLOT_INIT`].
    current_group_slot: usize,
    current_mask: BitMask,
}

impl ScanCursor {
    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
            next_ctrl: ptr::null(),
            end_ctrl: ptr::null(),
            current_group_slot: CURRENT_SLOT_INIT,
            current_mask: BitMask(0),
        }
    }

    /// Set ctrl pointers + reset state for a new region.
    #[inline]
    pub(crate) fn set_region<T, D: ArenaSlots<T> + ?Sized>(&mut self, region: &D) {
        self.next_ctrl = region.ctrl_ptr();
        // SAFETY: `ctrl_ptr() + capacity()` is one-past-end of the ctrl bytes.
        self.end_ctrl = unsafe { region.ctrl_ptr().add(region.capacity()) };
        self.current_group_slot = CURRENT_SLOT_INIT;
        self.current_mask = BitMask(0);
    }

    /// Advance one step in the current region.
    #[inline]
    pub(crate) fn step(&mut self) -> Option<usize> {
        loop {
            if let Some(bit) = self.current_mask.next() {
                return Some(self.current_group_slot.wrapping_add(bit));
            }
            if self.next_ctrl >= self.end_ctrl {
                return None;
            }
            self.current_group_slot = self.current_group_slot.wrapping_add(GROUP_SIZE);
            // SAFETY: `next_ctrl < end_ctrl` ⇒ within the region's ctrl bytes.
            self.current_mask = unsafe { simd::occupied_mask_16(self.next_ctrl) };
            self.next_ctrl = unsafe { self.next_ctrl.add(GROUP_SIZE) };
        }
    }
}

impl Clone for ScanCursor {
    fn clone(&self) -> Self {
        Self {
            next_ctrl: self.next_ctrl,
            end_ctrl: self.end_ctrl,
            current_group_slot: self.current_group_slot,
            current_mask: self.current_mask.clone(),
        }
    }
}

/// Shared scanner over a slice of `D` descriptors. Pointer-walking
/// internals: `next_ctrl` advances by `GROUP_SIZE` per group; `end_ctrl`
/// bounds the current region.
///
/// Read-only — yielded [`SlotHandle`]s are sound to call `as_ref` on
/// only. For mutating scans use [`IterRangeMut`].
pub(crate) struct IterRange<'a, T, D: ArenaSlots<T>> {
    levels: *const D,
    levels_len: usize,
    level_idx: usize,
    cursor: ScanCursor,
    _marker: PhantomData<(&'a [D], *const T)>,
}

// SAFETY: shared borrow of `[D]` is `Send` iff `D: Sync`; same here.
unsafe impl<T: Sync, D: ArenaSlots<T> + Sync> Send for IterRange<'_, T, D> {}
unsafe impl<T: Sync, D: ArenaSlots<T> + Sync> Sync for IterRange<'_, T, D> {}

impl<'a, T, D: ArenaSlots<T>> IterRange<'a, T, D> {
    #[inline]
    pub(crate) fn new(slice: &'a [D]) -> Self {
        let mut me = Self {
            levels: slice.as_ptr(),
            levels_len: slice.len(),
            level_idx: 0,
            cursor: ScanCursor::empty(),
            _marker: PhantomData,
        };
        if me.levels_len > 0 {
            // SAFETY: levels_len > 0.
            me.cursor.set_region(unsafe { &*me.levels });
        }
        me
    }

    #[inline]
    pub(crate) fn next_handle(&mut self) -> Option<SlotHandle<'a, T, D>> {
        loop {
            if let Some(idx) = self.cursor.step() {
                // SAFETY: `level_idx < levels_len` (cursor.step returned).
                let level_ptr = unsafe { self.levels.add(self.level_idx) }.cast_mut();
                return Some(SlotHandle {
                    descriptor: level_ptr,
                    idx,
                    _marker: PhantomData,
                });
            }
            self.level_idx += 1;
            if self.level_idx >= self.levels_len {
                return None;
            }
            // SAFETY: level_idx < levels_len.
            self.cursor
                .set_region(unsafe { &*self.levels.add(self.level_idx) });
        }
    }
}

impl<T, D: ArenaSlots<T>> Clone for IterRange<'_, T, D> {
    fn clone(&self) -> Self {
        Self {
            levels: self.levels,
            levels_len: self.levels_len,
            level_idx: self.level_idx,
            cursor: self.cursor.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T, D: ArenaSlots<T>> Iterator for IterRange<'_, T, D> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        loop {
            if let Some(idx) = self.cursor.step() {
                return Some(idx);
            }
            self.level_idx += 1;
            if self.level_idx >= self.levels_len {
                return None;
            }
            self.cursor
                .set_region(unsafe { &*self.levels.add(self.level_idx) });
        }
    }
}

/// Mut sibling of [`IterRange`]. Holds exclusive ptrs into `[D]`; yielded
/// [`SlotHandle`]s permit `as_mut` / `read` / `tombstone`. Not `Clone` —
/// would alias `&mut`.
pub(crate) struct IterRangeMut<'a, T, D: ArenaSlots<T>> {
    levels: *mut D,
    levels_len: usize,
    level_idx: usize,
    cursor: ScanCursor,
    _marker: PhantomData<(&'a mut [D], *mut T)>,
}

// SAFETY: exclusive borrow of `[D]` is `Send` iff `D: Send`.
unsafe impl<T: Send, D: ArenaSlots<T> + Send> Send for IterRangeMut<'_, T, D> {}
unsafe impl<T: Sync, D: ArenaSlots<T> + Sync> Sync for IterRangeMut<'_, T, D> {}

impl<'a, T, D: ArenaSlots<T>> IterRangeMut<'a, T, D> {
    #[inline]
    pub(crate) fn new(slice: &'a mut [D]) -> Self {
        let mut me = Self {
            levels: slice.as_mut_ptr(),
            levels_len: slice.len(),
            level_idx: 0,
            cursor: ScanCursor::empty(),
            _marker: PhantomData,
        };
        if me.levels_len > 0 {
            // SAFETY: levels_len > 0.
            me.cursor.set_region(unsafe { &*me.levels });
        }
        me
    }

    #[inline]
    pub(crate) fn next_handle(&mut self) -> Option<SlotHandle<'a, T, D>> {
        loop {
            if let Some(idx) = self.cursor.step() {
                // SAFETY: `level_idx < levels_len` (cursor.step returned).
                let level_ptr = unsafe { self.levels.add(self.level_idx) };
                return Some(SlotHandle {
                    descriptor: level_ptr,
                    idx,
                    _marker: PhantomData,
                });
            }
            self.level_idx += 1;
            if self.level_idx >= self.levels_len {
                return None;
            }
            // SAFETY: level_idx < levels_len.
            self.cursor
                .set_region(unsafe { &*self.levels.add(self.level_idx) });
        }
    }
}

/// Handle to one occupied slot (descriptor pointer + index). Same scanner
/// backs shared / mut / owning iters via the access method picked by the
/// caller. All access methods are `unsafe` — handle is only safe to
/// construct via a scanner over a confirmed-occupied slot.
pub(crate) struct SlotHandle<'a, T, D: ArenaSlots<T>> {
    descriptor: *mut D,
    idx: usize,
    _marker: PhantomData<(&'a mut D, *mut T)>,
}

impl<'a, T, D: ArenaSlots<T>> SlotHandle<'a, T, D> {
    /// Raw descriptor pointer. Caller uses it to mutate per-region state
    /// (e.g. `level.len -= 1`) without going through the handle.
    #[inline]
    pub(crate) fn descriptor_ptr(&self) -> *mut D {
        self.descriptor
    }

    /// Returns a reference tied to the scanner's `'a` (not the handle's
    /// borrow) so callers can hold multiple `&T` across iteration.
    ///
    /// SAFETY: caller ensures no `&mut` to this slot is live.
    #[inline]
    pub(crate) unsafe fn as_ref(&self) -> &'a T {
        unsafe { &*(*self.descriptor).data_ptr().add(self.idx) }
    }

    /// Reference is tied to the handle's `&mut`, so only one live `&mut`
    /// per slot exists at a time.
    ///
    /// SAFETY: caller ensures no other reference to this slot is live.
    #[inline]
    pub(crate) unsafe fn as_mut(&mut self) -> &mut T {
        unsafe { (*self.descriptor).get_mut(self.idx) }
    }

    /// Moves the entry out, leaving the slot logically uninit. Consumes
    /// the handle.
    ///
    /// SAFETY: caller must clear the ctrl byte before the map's Drop runs
    /// (via [`Self::tombstone`] or `clear_all_controls`) — otherwise
    /// double-drop.
    #[inline]
    pub(crate) unsafe fn read(self) -> T {
        unsafe { (*self.descriptor).take(self.idx) }
    }

    /// Mark slot ctrl as TOMBSTONE. Use before [`Self::read`] for panic
    /// safety so an aborted move leaves no OCCUPIED ctrl behind.
    #[inline]
    pub(crate) unsafe fn tombstone(&self) {
        unsafe { (*self.descriptor).mark_tombstone(self.idx) }
    }
}
