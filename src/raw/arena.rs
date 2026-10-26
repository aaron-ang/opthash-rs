use core::marker::PhantomData;
use core::mem::{self, MaybeUninit};
use core::ptr;

use allocator_api2::alloc::{Allocator, Layout};

use super::config::CACHE_LINE;
use super::control::{self, CTRL_TOMBSTONE};
use super::iter::OccupiedIndices;
use crate::error::TryReserveError;

/// Owns one allocation backing a map's ctrl bytes + slot data.
/// No `Drop` impl — derived maps orchestrate teardown by calling
/// [`drop_values`] on its descriptors before [`Arena::deallocate`].
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
            // SAFETY: align 1 is a power of two and size 0 cannot overflow.
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
        debug_assert!(ctrl_bytes <= layout.size(), "ctrl prefix exceeds layout");
        if ctrl_bytes > 0 {
            // SAFETY: `ptr` is a fresh allocation of `layout`, whose ctrl
            // prefix spans `ctrl_bytes` by construction in `layout_for*`.
            unsafe { ptr::write_bytes(ptr.as_ptr(), 0, ctrl_bytes) };
        }
        Ok(Self { ptr, layout })
    }

    #[inline]
    pub(crate) fn as_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    #[cfg(test)]
    pub(crate) fn layout_size(&self) -> usize {
        self.layout.size()
    }

    /// Frees the backing allocation. Caller must have already run any
    /// destructors for values living inside, and pass the allocator that
    /// allocated the arena.
    pub(crate) fn deallocate<A: Allocator>(self, alloc: &A) {
        if self.layout.size() == 0 {
            return;
        }
        // SAFETY: a nonzero `layout` means `ptr` came from `allocate(layout)`
        // on `alloc` (the caller passes the owning allocator); `self` is
        // consumed, so it is freed once.
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
        // SAFETY: `CACHE_LINE` is a power of two and size 0 cannot overflow.
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
        // SAFETY: as above.
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
/// `Some` locations collide. Generic over each backend's location type.
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
struct DeallocGuard<'a, A: Allocator> {
    arena: Option<Arena>,
    alloc: &'a A,
}

impl<'a, A: Allocator> DeallocGuard<'a, A> {
    #[inline]
    fn new(arena: Arena, alloc: &'a A) -> Self {
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
        self.regions.as_mut().expect("regions live until disarm")
    }

    /// Success path: reclaim `(arena, regions)`; the guard's `Drop` no-ops.
    #[inline]
    pub(crate) fn disarm(mut self) -> (Arena, RS) {
        (
            self.arena.take().expect("arena live until disarm"),
            self.regions.take().expect("regions live until disarm"),
        )
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

/// Drops the value in every occupied slot of `regions`. Call before
/// [`Arena::deallocate`]. Like dropping a slice, a panicking `Drop` doesn't
/// stop the walk: the guard drops the remaining values, then the panic
/// resumes. A second panic aborts.
pub(crate) fn drop_values<T, R: ArenaSlots<T>>(regions: &mut [R]) {
    /// Walk position, shared by the normal path and the unwind path.
    struct Remaining<'a, T, R: ArenaSlots<T>> {
        regions: &'a [R],
        region: usize,
        scan: OccupiedIndices,
        marker: PhantomData<T>,
    }

    impl<T, R: ArenaSlots<T>> Remaining<'_, T, R> {
        fn drop_rest(&mut self) {
            while let Some(region) = self.regions.get(self.region) {
                // `step` moves past `idx` before its value drops, so a resumed
                // walk skips the value that panicked.
                while let Some(idx) = self.scan.step(region) {
                    // SAFETY: `step` yields occupied in-bounds slots, each
                    // visited once, so every value drops exactly once.
                    unsafe { ptr::drop_in_place(region.slot_ptr(idx)) }
                }
                self.region += 1;
                self.scan = OccupiedIndices::new();
            }
        }
    }

    impl<T, R: ArenaSlots<T>> Drop for Remaining<'_, T, R> {
        fn drop(&mut self) {
            self.drop_rest();
        }
    }

    if !mem::needs_drop::<T>() {
        return;
    }
    // On success the guard's `Drop` finds nothing left; on unwind it resumes.
    Remaining {
        regions,
        region: 0,
        scan: OccupiedIndices::new(),
        marker: PhantomData,
    }
    .drop_rest();
}

/// One slot's `(key, value)` pair. Co-located so `read`/`drop_in_place`
/// touches both in one shot.
#[derive(Clone)]
pub(crate) struct SlotEntry<K, V> {
    pub(crate) key: K,
    pub(crate) value: V,
}

/// Per-region view of a map's arena. Descriptors borrow into the arena
/// allocation, parameterized by slot type `T`.
///
/// Every slot whose control byte is occupied holds an initialized `T`; the
/// `unsafe` index accessors exist so no safe call can break that.
///
/// # Safety
///
/// For as long as the descriptor is used, `ctrl_ptr()` must be valid for
/// reads and writes of `capacity()` bytes and `data_ptr()` valid for
/// `capacity()` slots of `T`, with neither range overlapping another
/// descriptor's. A new descriptor must start with no occupied control byte
/// over an uninitialized slot.
pub(crate) unsafe trait ArenaSlots<T> {
    fn ctrl_ptr(&self) -> *mut u8;
    fn data_ptr(&self) -> *mut MaybeUninit<T>;
    fn capacity(&self) -> usize;

    /// # Safety
    ///
    /// `idx < self.capacity()`.
    #[inline]
    unsafe fn slot_ptr(&self, idx: usize) -> *mut T {
        debug_assert!(idx < self.capacity());
        // SAFETY: caller keeps `idx` in bounds of the `capacity()` slots.
        unsafe { self.data_ptr().add(idx).cast::<T>() }
    }

    /// # Safety
    ///
    /// `idx < self.capacity()`.
    #[inline]
    unsafe fn control_at(&self, idx: usize) -> u8 {
        debug_assert!(idx < self.capacity());
        // SAFETY: caller keeps `idx` in bounds of the `capacity()` ctrl bytes.
        unsafe { *self.ctrl_ptr().add(idx) }
    }

    /// Bounds-checked [`control_at`](Self::control_at) for test assertions.
    #[cfg(test)]
    fn checked_control(&self, idx: usize) -> u8 {
        assert!(idx < self.capacity(), "control index {idx} out of bounds");
        // SAFETY: bounds checked above.
        unsafe { self.control_at(idx) }
    }

    /// Bounds-checked [`slot_ptr`](Self::slot_ptr) for test assertions.
    #[cfg(test)]
    fn checked_slot_ptr(&self, idx: usize) -> *mut T {
        assert!(idx < self.capacity(), "slot index {idx} out of bounds");
        // SAFETY: bounds checked above.
        unsafe { self.slot_ptr(idx) }
    }

    /// # Safety
    ///
    /// `idx < self.capacity()`, and an occupied `ctrl` is only stamped on a
    /// slot that holds an initialized `T`.
    #[inline]
    unsafe fn set_control(&mut self, idx: usize, ctrl: u8) {
        debug_assert!(idx < self.capacity());
        // SAFETY: caller keeps `idx` in bounds of the `capacity()` ctrl bytes.
        unsafe { *self.ctrl_ptr().add(idx) = ctrl }
    }

    /// Leaks the slot's value unless the caller already moved or dropped it.
    ///
    /// # Safety
    ///
    /// `idx < self.capacity()`.
    #[inline]
    unsafe fn mark_tombstone(&mut self, idx: usize) {
        // SAFETY: caller keeps `idx` in bounds; a tombstone is never occupied.
        unsafe { self.set_control(idx, CTRL_TOMBSTONE) };
    }

    /// Wipe every ctrl byte in this region to EMPTY.
    /// Caller is responsible for having dropped occupied values first.
    #[inline]
    fn clear_all_controls(&mut self) {
        if self.capacity() == 0 {
            return;
        }
        // SAFETY: the trait contract makes `ctrl_ptr()` writable for
        // `capacity()` bytes.
        unsafe { ptr::write_bytes(self.ctrl_ptr(), 0, self.capacity()) }
    }

    /// # Safety
    ///
    /// `idx < self.capacity()`. The slot should be free (debug-asserted);
    /// overwriting a live value leaks it.
    #[inline]
    unsafe fn write_with_control(&mut self, idx: usize, entry: T, ctrl: u8) {
        // SAFETY: caller keeps `idx` in bounds; the slot is initialized
        // before `ctrl` is stamped.
        unsafe {
            debug_assert!(control::is_free(self.control_at(idx)));
            self.slot_ptr(idx).write(entry);
            self.set_control(idx, ctrl);
        }
    }

    /// # Safety
    ///
    /// `idx < self.capacity()` and the slot is initialized.
    #[inline]
    unsafe fn get_ref(&self, idx: usize) -> &T {
        debug_assert!(idx < self.capacity());
        // SAFETY: caller guarantees `idx` is in bounds and initialized.
        unsafe {
            debug_assert!(control::is_occupied(self.control_at(idx)));
            &*self.slot_ptr(idx)
        }
    }

    /// `&mut self` is a type-level proof of exclusive access — without it,
    /// two calls with the same `idx` could hand out aliasing `&mut T` (UB).
    ///
    /// # Safety
    ///
    /// `idx < self.capacity()` and the slot is initialized.
    #[inline]
    unsafe fn get_mut(&mut self, idx: usize) -> &mut T {
        debug_assert!(idx < self.capacity());
        // SAFETY: caller guarantees `idx` is in bounds and initialized;
        // `&mut self` rules out an aliasing borrow.
        unsafe {
            debug_assert!(control::is_occupied(self.control_at(idx)));
            &mut *self.slot_ptr(idx)
        }
    }

    /// # Safety
    ///
    /// `idx < self.capacity()` and the slot is initialized. The slot must not
    /// be read again before being re-written.
    #[inline]
    unsafe fn take(&mut self, idx: usize) -> T {
        debug_assert!(idx < self.capacity());
        // SAFETY: caller guarantees `idx` is in bounds, initialized, and not
        // read again, so the bitwise move cannot double-drop.
        unsafe {
            debug_assert!(control::is_occupied(self.control_at(idx)));
            self.slot_ptr(idx).read()
        }
    }

    /// Clone every occupied slot of `src` into `self` in panic-safe order: clone
    /// → write → stamp OCCUPIED. A panic mid-loop leaves `self` OCCUPIED only on
    /// fully-written slots. Once every value is in place, all controls are
    /// copied, which adds the TOMBSTONE bytes. `self` must match `src`'s
    /// capacity and start all-EMPTY.
    fn clone_region_from(&mut self, src: &Self)
    where
        Self: Sized,
        T: Clone,
    {
        let capacity = src.capacity();
        assert_eq!(capacity, self.capacity(), "clone dst must match src");
        let mut scan = OccupiedIndices::new();
        while let Some(idx) = scan.step(src) {
            // SAFETY: `step` yields occupied in-bounds indices of `src`, and
            // the capacities match, so `idx` is in bounds of `self` too.
            let cloned = unsafe { src.get_ref(idx) }.clone();
            // SAFETY: as above; the slot is written before it is stamped.
            unsafe {
                self.slot_ptr(idx).write(cloned);
                self.set_control(idx, src.control_at(idx));
            }
        }
        if capacity != 0 {
            // SAFETY: both ctrl ranges hold `capacity` bytes in distinct
            // allocations.
            unsafe { ptr::copy_nonoverlapping(src.ctrl_ptr(), self.ctrl_ptr(), capacity) };
        }
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
