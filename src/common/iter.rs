use core::fmt;
use core::iter::FusedIterator;
use core::ptr;

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
            self.current_mask = unsafe { simd::occupied_mask_group(self.next_ctrl) };
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

/// Per-region scan state shared by the backends' `Scan` cursors: an
/// [`OccupiedSlots`] group scanner plus the current region's cached slot
/// pointer. Owns the per-region mechanics; each backend keeps its own region
/// ordering and location construction.
pub(crate) struct RegionCursor {
    cursor: OccupiedSlots,
    /// Cached `data_ptr()` of the current region, refreshed by `enter`.
    cur_data: *mut u8,
    /// `false` until the first `enter`, keeping a fresh cursor pointer-free.
    started: bool,
}

impl RegionCursor {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            cursor: OccupiedSlots::empty(),
            cur_data: ptr::null_mut(),
            started: false,
        }
    }

    #[inline]
    pub(crate) fn started(&self) -> bool {
        self.started
    }

    /// Binds the scanner to `region` and caches its slot pointer.
    #[inline]
    pub(crate) fn enter<T, D: ArenaSlots<T> + ?Sized>(&mut self, region: &D) {
        self.cursor.set_region(region);
        self.cur_data = region.data_ptr().cast();
        self.started = true;
    }

    /// Next occupied slot in the current region as `(slot pointer, index)`.
    #[inline]
    pub(crate) fn step<E>(&mut self) -> Option<(*mut E, usize)> {
        let slot_idx = self.cursor.step()?;
        // SAFETY: `cur_data` is the current region's slot array; `slot_idx` is
        // in-bounds for it (`step` yields only valid slots).
        let ptr = unsafe { self.cur_data.cast::<E>().add(slot_idx) };
        Some((ptr, slot_idx))
    }
}

impl Clone for RegionCursor {
    fn clone(&self) -> Self {
        Self {
            cursor: self.cursor.clone(),
            cur_data: self.cur_data,
            started: self.started,
        }
    }
}
