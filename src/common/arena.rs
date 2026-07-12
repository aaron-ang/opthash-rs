use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::ptr;

use allocator_api2::alloc::{Allocator, Layout};

use super::config::{CACHE_LINE, GROUP_SIZE};
use super::control::{CTRL_EMPTY, CTRL_TOMBSTONE, ControlByte};
use super::error::TryReserveError;
use super::simd;

/// Owns one allocation backing a map's ctrl bytes + slot data.
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

    /// Size of the already-stored allocator layout backing this arena.
    #[inline]
    pub(crate) fn layout_size(&self) -> usize {
        self.layout.size()
    }

    /// Frees the backing allocation. Caller must have already run any
    /// destructors for values living inside.
    pub(crate) fn deallocate<A: Allocator>(self, alloc: &A) {
        if self.layout.size() == 0 {
            return;
        }
        unsafe { alloc.deallocate(self.ptr, self.layout) };
    }

    /// Tear down the arena from a map's `Drop`: swap it out, drop live values via
    /// `drop_values`, free the allocation. A [`DeallocGuard`] still frees on an
    /// unwinding value `Drop` — `Arena` has none of its own.
    #[inline]
    pub(crate) fn drop_table<A: Allocator>(&mut self, alloc: &A, drop_values: impl FnOnce()) {
        let arena = mem::replace(self, Arena::empty());
        let guard = DeallocGuard::new(arena, alloc);
        drop_values();
        drop(guard);
    }
}

/// Combined ctrl+data layout for an arena whose ctrl section holds
/// `total_ctrl` bytes and data section holds `total_ctrl` slots.
/// Returns `(layout, data_offset_within_arena)`.
pub(crate) fn layout_for<K, V>(total_ctrl: usize) -> Result<(Layout, usize), TryReserveError> {
    layout_for_extents::<K, V>(total_ctrl, total_ctrl)
}

/// Combined ctrl+data layout with independently sized control and slot extents.
pub(crate) fn layout_for_extents<K, V>(
    ctrl_bytes: usize,
    data_slots: usize,
) -> Result<(Layout, usize), TryReserveError> {
    if ctrl_bytes == 0 && data_slots == 0 {
        let layout = unsafe { Layout::from_size_align_unchecked(0, CACHE_LINE) };
        return Ok((layout, 0));
    }
    let ctrl_layout =
        Layout::from_size_align(ctrl_bytes, CACHE_LINE).map_err(|_| TryReserveError::AllocError)?;
    let data_layout =
        Layout::array::<SlotEntry<K, V>>(data_slots).map_err(|_| TryReserveError::AllocError)?;
    let (arena_layout, data_base_off) = ctrl_layout
        .extend(data_layout)
        .map_err(|_| TryReserveError::AllocError)?;
    Ok((arena_layout.pad_to_align(), data_base_off))
}

/// Hands out each arena region's `(ctrl_ptr, data_ptr)` in layout order,
/// advancing the ctrl + data offsets with checked arithmetic — a `u32`
/// overflow yields `CapacityOverflow`, never a wrapped pointer.
pub(crate) struct LayoutCursor<T> {
    base: *mut u8,
    ctrl_off: u32,
    data_off: u32,
    slot_size: u32,
    _marker: PhantomData<fn() -> T>,
}

impl<T> LayoutCursor<T> {
    /// `data_base_off` is the data section's byte offset (from [`layout_for`]).
    pub(crate) fn new(base: *mut u8, data_base_off: usize) -> Result<Self, TryReserveError> {
        Ok(Self {
            base,
            ctrl_off: 0,
            data_off: u32::try_from(data_base_off)
                .map_err(|_| TryReserveError::CapacityOverflow)?,
            slot_size: u32::try_from(mem::size_of::<T>())
                .map_err(|_| TryReserveError::CapacityOverflow)?,
            _marker: PhantomData,
        })
    }

    /// Current region's `(ctrl_ptr, data_ptr)`, then advances past its `cap`
    /// ctrl bytes + `cap * slot_size` data bytes.
    ///
    /// # Safety
    /// `base` must point at a [`layout_for`] arena covering every reserved
    /// region, in order.
    pub(crate) unsafe fn reserve(
        &mut self,
        cap: u32,
    ) -> Result<(*mut u8, *mut MaybeUninit<T>), TryReserveError> {
        // Both offsets computed before committing, so overflow leaves the
        // cursor unchanged.
        let next_ctrl_off = self
            .ctrl_off
            .checked_add(cap)
            .ok_or(TryReserveError::CapacityOverflow)?;
        let data_bytes = cap
            .checked_mul(self.slot_size)
            .ok_or(TryReserveError::CapacityOverflow)?;
        let next_data_off = self
            .data_off
            .checked_add(data_bytes)
            .ok_or(TryReserveError::CapacityOverflow)?;

        // SAFETY: offsets stay within the caller's arena layout.
        let ctrl_ptr = unsafe { self.base.add(self.ctrl_off as usize) };
        let data_ptr = unsafe {
            self.base
                .add(self.data_off as usize)
                .cast::<MaybeUninit<T>>()
        };
        self.ctrl_off = next_ctrl_off;
        self.data_off = next_data_off;
        Ok((ctrl_ptr, data_ptr))
    }
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

/// A map's complete set of arena regions, for panic-safe teardown. Each
/// backend's region collection implements it so [`ArenaDropGuard`] can drop
/// every region's live values from one place.
pub(crate) trait RegionSet {
    /// Drops the value in every occupied slot across all regions.
    fn drop_all_values(&mut self);
}

/// Owns a half-built (clone) or being-rehashed (resize) arena and its regions.
/// If a `clone`/`insert` unwinds, [`Drop`] drops the regions' live values then
/// deallocates — `Arena` has no `Drop`, so this is what prevents the leak. On
/// the success path call [`disarm`](Self::disarm) to reclaim both.
pub(crate) struct ArenaDropGuard<RS: RegionSet, A: Allocator> {
    arena: Option<Arena>,
    regions: Option<RS>,
    alloc: A,
}

impl<RS: RegionSet, A: Allocator> ArenaDropGuard<RS, A> {
    #[inline]
    pub(crate) fn new(arena: Arena, regions: RS, alloc: A) -> Self {
        Self {
            arena: Some(arena),
            regions: Some(regions),
            alloc,
        }
    }

    /// Mutable access to the guarded regions (the clone/drain loop writes here).
    #[inline]
    pub(crate) fn regions_mut(&mut self) -> &mut RS {
        self.regions.as_mut().unwrap()
    }

    /// Success path: reclaim `(arena, regions)`; the guard's `Drop` no-ops.
    #[inline]
    pub(crate) fn disarm(mut self) -> (Arena, RS) {
        (self.arena.take().unwrap(), self.regions.take().unwrap())
    }
}

impl<RS: RegionSet, A: Allocator> Drop for ArenaDropGuard<RS, A> {
    fn drop(&mut self) {
        if let Some(arena) = self.arena.take() {
            // Deallocate even if a value's `Drop` unwinds out of
            // `drop_all_values` — otherwise the arena would leak.
            let _dealloc = DeallocGuard::new(arena, &self.alloc);
            if let Some(mut regions) = self.regions.take() {
                regions.drop_all_values();
            }
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

/// Per-region view of a map's arena. Descriptors borrow into the arena
/// allocation, parameterized by slot type `T`.
pub(crate) trait ArenaSlots<T> {
    fn ctrl_ptr(&self) -> *mut u8;
    fn data_ptr(&self) -> *mut MaybeUninit<T>;
    fn capacity(&self) -> usize;

    #[inline]
    fn slot_ptr(&self, idx: usize) -> *mut T {
        debug_assert!(idx < self.capacity());
        unsafe { self.data_ptr().add(idx).cast::<T>() }
    }

    #[inline]
    fn control_at(&self, idx: usize) -> u8 {
        debug_assert!(idx < self.capacity());
        unsafe { *self.ctrl_ptr().add(idx) }
    }

    #[inline]
    fn set_control(&mut self, idx: usize, ctrl: u8) {
        debug_assert!(idx < self.capacity());
        unsafe { *self.ctrl_ptr().add(idx) = ctrl }
    }

    #[inline]
    fn mark_tombstone(&mut self, idx: usize) {
        self.set_control(idx, CTRL_TOMBSTONE);
    }

    /// Wipe every ctrl byte in this region to FREE.
    /// Caller is responsible for having dropped occupied values first.
    #[inline]
    fn clear_all_controls(&mut self) {
        if self.capacity() == 0 {
            return;
        }
        unsafe { ptr::write_bytes(self.ctrl_ptr(), 0, self.capacity()) }
    }

    #[inline]
    fn write_with_control(&mut self, idx: usize, entry: T, ctrl: u8) {
        debug_assert!(self.control_at(idx).is_free());
        unsafe { self.slot_ptr(idx).write(entry) }
        self.set_control(idx, ctrl);
    }

    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    #[inline]
    unsafe fn get_ref(&self, idx: usize) -> &T {
        debug_assert!(idx < self.capacity());
        debug_assert!(self.control_at(idx).is_occupied());
        unsafe { &*self.slot_ptr(idx) }
    }

    /// `&mut self` is a type-level proof of exclusive access — without it,
    /// two calls with the same `idx` could hand out aliasing `&mut T` (UB).
    ///
    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    #[inline]
    unsafe fn get_mut(&mut self, idx: usize) -> &mut T {
        debug_assert!(idx < self.capacity());
        debug_assert!(self.control_at(idx).is_occupied());
        unsafe { &mut *self.slot_ptr(idx) }
    }

    /// SAFETY: caller ensures `idx` is in-bounds and the slot is initialized.
    /// The slot must not be read again before being re-written.
    #[inline]
    unsafe fn take(&mut self, idx: usize) -> T {
        debug_assert!(idx < self.capacity());
        debug_assert!(self.control_at(idx).is_occupied());
        unsafe { self.slot_ptr(idx).read() }
    }

    /// Drop every value in occupied slots. Call before [`Arena::deallocate`].
    fn drop_values(&mut self) {
        if self.capacity() == 0 {
            return;
        }
        let ctrl = self.ctrl_ptr();
        for idx in 0..self.capacity() {
            if unsafe { (*ctrl.add(idx)).is_occupied() } {
                unsafe { ptr::drop_in_place(self.slot_ptr(idx)) }
            }
        }
    }

    /// Clone every occupied slot of `src` into `self` in panic-safe order: clone
    /// → write → stamp OCCUPIED. A panic mid-loop leaves `self` OCCUPIED only on
    /// fully-written slots; TOMBSTONE bytes follow in a second pass. `self` must
    /// match `src`'s capacity.
    fn clone_region_from(&mut self, src: &Self)
    where
        Self: Sized,
        T: Clone,
    {
        let capacity = src.capacity();
        debug_assert_eq!(capacity, self.capacity(), "clone dst must match src");
        let src_ctrl = src.ctrl_ptr();
        let dst_ctrl = self.ctrl_ptr();
        let src_slots = src.data_ptr();
        let dst_slots = self.data_ptr();
        for idx in 0..capacity {
            let ctrl = unsafe { *src_ctrl.add(idx) };
            if ctrl.is_occupied() {
                let cloned = unsafe { (*src_slots.add(idx)).assume_init_ref() }.clone();
                unsafe { dst_slots.add(idx).write(MaybeUninit::new(cloned)) };
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

    /// Reset controls for every occupied slot and invoke `visit` with that
    /// slot's pointer after its control byte has been cleared.
    #[inline]
    fn clear_occupied_slots_with<F: FnMut(*mut T)>(&mut self, mut visit: F) {
        if self.capacity() == 0 {
            return;
        }
        let ctrl = self.ctrl_ptr();
        let full_groups = self.capacity() / GROUP_SIZE;
        for group_idx in 0..full_groups {
            let group_start = group_idx * GROUP_SIZE;
            let group_ctrl = unsafe { ctrl.add(group_start) };
            for offset in unsafe { simd::occupied_mask_group(group_ctrl) } {
                let idx = group_start + offset;
                unsafe {
                    *ctrl.add(idx) = CTRL_EMPTY;
                    visit(self.slot_ptr(idx));
                }
            }
            unsafe { ptr::write_bytes(group_ctrl, CTRL_EMPTY, GROUP_SIZE) };
        }
        for idx in full_groups * GROUP_SIZE..self.capacity() {
            unsafe {
                let prev = *ctrl.add(idx);
                *ctrl.add(idx) = CTRL_EMPTY;
                if prev.is_occupied() {
                    visit(self.slot_ptr(idx));
                }
            }
        }
    }

    /// Move every occupied value out and reset all controls to EMPTY.
    /// The current ctrl byte is cleared before `f` runs, so a panic cannot
    /// leave the moved-out slot marked occupied.
    fn drain_values_and_clear<F: FnMut(T)>(&mut self, mut f: F) {
        self.clear_occupied_slots_with(|slot| unsafe { f(slot.read()) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_ctrl_layout_does_not_allocate() {
        let (layout, data_offset) = layout_for::<u64, u64>(0).unwrap();
        assert_eq!(layout.size(), 0);
        assert_eq!(data_offset, 0);
    }
}
