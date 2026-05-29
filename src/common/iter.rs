use std::fmt;
use std::iter::FusedIterator;
use std::marker::PhantomData;
use std::ptr;

use super::arena::ArenaSlots;
use super::bitmask::BitMask;
use super::config::GROUP_SIZE;
use super::simd;

/// Projects the `K` from a borrowing `(&K, &V)` iterator.
pub struct Keys<I> {
    inner: I,
}

impl<I> Keys<I> {
    pub(crate) fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I: Clone> Clone for Keys<I> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<I, K, V> Iterator for Keys<I>
where
    I: Iterator<Item = (K, V)>,
{
    type Item = K;
    #[inline]
    fn next(&mut self) -> Option<K> {
        self.inner.next().map(|(k, _)| k)
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
    #[inline]
    fn fold<B, F: FnMut(B, K) -> B>(self, init: B, mut f: F) -> B {
        self.inner.fold(init, move |acc, (k, _)| f(acc, k))
    }
    #[inline]
    fn for_each<F: FnMut(K)>(self, mut f: F) {
        self.inner.for_each(move |(k, _)| f(k));
    }
}

impl<I, K, V> ExactSizeIterator for Keys<I> where I: ExactSizeIterator<Item = (K, V)> {}
impl<I, K, V> FusedIterator for Keys<I> where I: FusedIterator<Item = (K, V)> {}

impl<I> fmt::Debug for Keys<I> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Keys").finish_non_exhaustive()
    }
}

/// Projects the `V` from a borrowing `(&K, &V)` iterator.
pub struct Values<I> {
    inner: I,
}

impl<I> Values<I> {
    pub(crate) fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I: Clone> Clone for Values<I> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<I, K, V> Iterator for Values<I>
where
    I: Iterator<Item = (K, V)>,
{
    type Item = V;
    #[inline]
    fn next(&mut self) -> Option<V> {
        self.inner.next().map(|(_, v)| v)
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
    #[inline]
    fn fold<B, F: FnMut(B, V) -> B>(self, init: B, mut f: F) -> B {
        self.inner.fold(init, move |acc, (_, v)| f(acc, v))
    }
    #[inline]
    fn for_each<F: FnMut(V)>(self, mut f: F) {
        self.inner.for_each(move |(_, v)| f(v));
    }
}

impl<I, K, V> ExactSizeIterator for Values<I> where I: ExactSizeIterator<Item = (K, V)> {}
impl<I, K, V> FusedIterator for Values<I> where I: FusedIterator<Item = (K, V)> {}

impl<I> fmt::Debug for Values<I> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Values").finish_non_exhaustive()
    }
}

/// Projects the owned `K` from a consuming `(K, V)` iterator.
pub struct IntoKeys<I> {
    inner: I,
}

impl<I> IntoKeys<I> {
    pub(crate) fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I, K, V> Iterator for IntoKeys<I>
where
    I: Iterator<Item = (K, V)>,
{
    type Item = K;
    #[inline]
    fn next(&mut self) -> Option<K> {
        self.inner.next().map(|(k, _)| k)
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
    #[inline]
    fn fold<B, F: FnMut(B, K) -> B>(self, init: B, mut f: F) -> B {
        self.inner.fold(init, move |acc, (k, _)| f(acc, k))
    }
    #[inline]
    fn for_each<F: FnMut(K)>(self, mut f: F) {
        self.inner.for_each(move |(k, _)| f(k));
    }
}

impl<I, K, V> ExactSizeIterator for IntoKeys<I> where I: ExactSizeIterator<Item = (K, V)> {}
impl<I, K, V> FusedIterator for IntoKeys<I> where I: FusedIterator<Item = (K, V)> {}

impl<I> fmt::Debug for IntoKeys<I> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IntoKeys").finish_non_exhaustive()
    }
}

/// Projects the owned `V` from a consuming `(K, V)` iterator.
pub struct IntoValues<I> {
    inner: I,
}

impl<I> IntoValues<I> {
    pub(crate) fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I, K, V> Iterator for IntoValues<I>
where
    I: Iterator<Item = (K, V)>,
{
    type Item = V;
    #[inline]
    fn next(&mut self) -> Option<V> {
        self.inner.next().map(|(_, v)| v)
    }
    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
    }
    #[inline]
    fn fold<B, F: FnMut(B, V) -> B>(self, init: B, mut f: F) -> B {
        self.inner.fold(init, move |acc, (_, v)| f(acc, v))
    }
    #[inline]
    fn for_each<F: FnMut(V)>(self, mut f: F) {
        self.inner.for_each(move |(_, v)| f(v));
    }
}

impl<I, K, V> ExactSizeIterator for IntoValues<I> where I: ExactSizeIterator<Item = (K, V)> {}
impl<I, K, V> FusedIterator for IntoValues<I> where I: FusedIterator<Item = (K, V)> {}

impl<I> fmt::Debug for IntoValues<I> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("IntoValues").finish_non_exhaustive()
    }
}

/// Initial slot offset that becomes `0` after the first group load.
const GROUP_SLOT_INIT: usize = 0_usize.wrapping_sub(GROUP_SIZE);

/// Iterator over occupied slot indices in one arena region.
///
/// Map-level iterators reuse this as their group scanner while they decide
/// which region to scan next.
pub(crate) struct OccupiedSlots {
    /// Ptr to the next group's first ctrl byte (or `end_ctrl` if done).
    next_ctrl: *const u8,
    /// One-past-end of the current region's ctrl bytes.
    end_ctrl: *const u8,
    /// Slot offset of the currently-loaded group.
    current_group_slot: usize,
    current_mask: BitMask,
}

impl OccupiedSlots {
    #[inline]
    pub(crate) fn empty() -> Self {
        Self {
            next_ctrl: ptr::null(),
            end_ctrl: ptr::null(),
            current_group_slot: GROUP_SLOT_INIT,
            current_mask: BitMask(0),
        }
    }

    /// Set ctrl pointers + reset state for a new region.
    #[inline]
    pub(crate) fn set_region<T, D: ArenaSlots<T> + ?Sized>(&mut self, region: &D) {
        self.next_ctrl = region.ctrl_ptr();
        // SAFETY: `ctrl_ptr() + capacity()` is one-past-end of the ctrl bytes.
        self.end_ctrl = unsafe { region.ctrl_ptr().add(region.capacity()) };
        self.current_group_slot = GROUP_SLOT_INIT;
        self.current_mask = BitMask(0);
    }

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

impl Iterator for OccupiedSlots {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        self.step()
    }
}

impl Clone for OccupiedSlots {
    fn clone(&self) -> Self {
        Self {
            next_ctrl: self.next_ctrl,
            end_ctrl: self.end_ctrl,
            current_group_slot: self.current_group_slot,
            current_mask: self.current_mask.clone(),
        }
    }
}

/// Shared scanner over a slice of `D` descriptors. Yielded
/// [`SlotHandle`]s permit `as_ref` only. For mutating scans use
/// [`RegionIterMut`].
pub(crate) struct RegionIter<'a, T, D: ArenaSlots<T>> {
    regions: *const D,
    regions_len: usize,
    region_idx: usize,
    slots: OccupiedSlots,
    _marker: PhantomData<(&'a [D], *const T)>,
}

// SAFETY: shared borrow of `[D]` is `Send` iff `D: Sync`; same here.
unsafe impl<T: Sync, D: ArenaSlots<T> + Sync> Send for RegionIter<'_, T, D> {}
unsafe impl<T: Sync, D: ArenaSlots<T> + Sync> Sync for RegionIter<'_, T, D> {}

impl<'a, T, D: ArenaSlots<T>> RegionIter<'a, T, D> {
    #[inline]
    pub(crate) fn new(slice: &'a [D]) -> Self {
        let mut me = Self {
            regions: slice.as_ptr(),
            regions_len: slice.len(),
            region_idx: 0,
            slots: OccupiedSlots::empty(),
            _marker: PhantomData,
        };
        if me.regions_len > 0 {
            // SAFETY: regions_len > 0.
            me.slots.set_region(unsafe { &*me.regions });
        }
        me
    }

    #[inline]
    pub(crate) fn next_handle(&mut self) -> Option<SlotHandle<'a, T, D>> {
        loop {
            if let Some(idx) = self.slots.step() {
                // SAFETY: `region_idx < regions_len` (`slots.step` returned).
                let descriptor = unsafe { self.regions.add(self.region_idx) }.cast_mut();
                return Some(SlotHandle {
                    descriptor,
                    idx,
                    _marker: PhantomData,
                });
            }
            self.region_idx += 1;
            if self.region_idx >= self.regions_len {
                return None;
            }
            // SAFETY: region_idx < regions_len.
            self.slots
                .set_region(unsafe { &*self.regions.add(self.region_idx) });
        }
    }
}

impl<T, D: ArenaSlots<T>> Clone for RegionIter<'_, T, D> {
    fn clone(&self) -> Self {
        Self {
            regions: self.regions,
            regions_len: self.regions_len,
            region_idx: self.region_idx,
            slots: self.slots.clone(),
            _marker: PhantomData,
        }
    }
}

impl<T, D: ArenaSlots<T>> Iterator for RegionIter<'_, T, D> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        // Plain `usize` collapses level identity; valid only for single-region scans.
        debug_assert!(
            self.regions_len <= 1,
            "RegionIter::next yields ambiguous indices across multiple regions; use next_handle"
        );
        loop {
            if let Some(idx) = self.slots.step() {
                return Some(idx);
            }
            self.region_idx += 1;
            if self.region_idx >= self.regions_len {
                return None;
            }
            self.slots
                .set_region(unsafe { &*self.regions.add(self.region_idx) });
        }
    }
}

/// Mut sibling of [`RegionIter`]. Yielded [`SlotHandle`]s permit `as_mut`.
/// Not `Clone` — would alias `&mut`.
pub(crate) struct RegionIterMut<'a, T, D: ArenaSlots<T>> {
    regions: *mut D,
    regions_len: usize,
    region_idx: usize,
    slots: OccupiedSlots,
    _marker: PhantomData<(&'a mut [D], *mut T)>,
}

// SAFETY: exclusive borrow of `[D]` is `Send` iff `D: Send`.
unsafe impl<T: Send, D: ArenaSlots<T> + Send> Send for RegionIterMut<'_, T, D> {}
unsafe impl<T: Sync, D: ArenaSlots<T> + Sync> Sync for RegionIterMut<'_, T, D> {}

impl<'a, T, D: ArenaSlots<T>> RegionIterMut<'a, T, D> {
    #[inline]
    pub(crate) fn new(slice: &'a mut [D]) -> Self {
        let mut me = Self {
            regions: slice.as_mut_ptr(),
            regions_len: slice.len(),
            region_idx: 0,
            slots: OccupiedSlots::empty(),
            _marker: PhantomData,
        };
        if me.regions_len > 0 {
            // SAFETY: regions_len > 0.
            me.slots.set_region(unsafe { &*me.regions });
        }
        me
    }

    #[inline]
    pub(crate) fn next_handle(&mut self) -> Option<SlotHandle<'a, T, D>> {
        loop {
            if let Some(idx) = self.slots.step() {
                // SAFETY: `region_idx < regions_len` (`slots.step` returned).
                let descriptor = unsafe { self.regions.add(self.region_idx) };
                return Some(SlotHandle {
                    descriptor,
                    idx,
                    _marker: PhantomData,
                });
            }
            self.region_idx += 1;
            if self.region_idx >= self.regions_len {
                return None;
            }
            // SAFETY: region_idx < regions_len.
            self.slots
                .set_region(unsafe { &*self.regions.add(self.region_idx) });
        }
    }
}

/// Handle to one occupied slot (descriptor pointer + index). Only safe
/// to construct via a scanner over a confirmed-occupied slot.
pub(crate) struct SlotHandle<'a, T, D: ArenaSlots<T>> {
    descriptor: *mut D,
    idx: usize,
    _marker: PhantomData<(&'a mut D, *mut T)>,
}

impl<'a, T, D: ArenaSlots<T>> SlotHandle<'a, T, D> {
    /// Returns a reference with the scanner's lifetime `'a`, not the
    /// handle's borrow — yielded refs can outlive the handle.
    ///
    /// SAFETY: caller ensures no `&mut` to this slot is live.
    #[inline]
    pub(crate) unsafe fn as_ref(&self) -> &'a T {
        unsafe { &*(*self.descriptor).data_ptr().add(self.idx) }
    }

    /// SAFETY: caller ensures no other reference to this slot is live.
    #[inline]
    pub(crate) unsafe fn as_mut(&mut self) -> &mut T {
        unsafe { (*self.descriptor).get_mut(self.idx) }
    }
}
