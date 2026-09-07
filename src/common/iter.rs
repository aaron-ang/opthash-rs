use core::fmt;
use core::iter::FusedIterator;
use core::ptr;

use super::arena::ArenaSlots;
use super::bitmask::{BITMASK_STRIDE, BitMask};
use super::config::GROUP_SIZE;
use super::control::ControlByte;
use super::simd;

/// Generate a projection iterator over a `(K, V)`-yielding inner iterator.
///
/// Each type wraps `inner`, maps every item through `$project`, forwards
/// `size_hint`/`fold`/`for_each`, and mirrors the inner `ExactSizeIterator`
/// and `FusedIterator` impls. `Debug` prints only the type name so the inner
/// iterator needs no `Debug` bound. Leading attributes (doc comments, derives)
/// are applied to the generated struct.
macro_rules! project_iter {
    (
        $(#[$attr:meta])*
        $name:ident => $item:ident, |($k:pat_param, $v:pat_param)| $project:expr
    ) => {
        $(#[$attr])*
        pub struct $name<I> {
            inner: I,
        }

        impl<I> $name<I> {
            pub(crate) fn new(inner: I) -> Self {
                Self { inner }
            }
        }

        impl<I, K, V> Iterator for $name<I>
        where
            I: Iterator<Item = (K, V)>,
        {
            type Item = $item;
            #[inline]
            fn next(&mut self) -> Option<$item> {
                self.inner.next().map(|($k, $v)| $project)
            }
            #[inline]
            fn size_hint(&self) -> (usize, Option<usize>) {
                self.inner.size_hint()
            }
            #[inline]
            fn fold<B, F: FnMut(B, $item) -> B>(self, init: B, mut f: F) -> B {
                self.inner.fold(init, move |acc, ($k, $v)| f(acc, $project))
            }
            #[inline]
            fn for_each<F: FnMut($item)>(self, mut f: F) {
                self.inner.for_each(move |($k, $v)| f($project));
            }
        }

        impl<I, K, V> ExactSizeIterator for $name<I> where I: ExactSizeIterator<Item = (K, V)> {}
        impl<I, K, V> FusedIterator for $name<I> where I: FusedIterator<Item = (K, V)> {}

        impl<I> fmt::Debug for $name<I> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }
    };
}

project_iter! {
    /// Projects the `K` from a borrowing `(&K, &V)` iterator.
    #[derive(Clone)]
    Keys => K, |(k, _)| k
}

project_iter! {
    /// Projects the `V` from a borrowing `(&K, &V)` iterator.
    #[derive(Clone)]
    Values => V, |(_, v)| v
}

project_iter! {
    /// Projects the owned `K` from a consuming `(K, V)` iterator.
    IntoKeys => K, |(k, _)| k
}

project_iter! {
    /// Projects the owned `V` from a consuming `(K, V)` iterator.
    IntoValues => V, |(_, v)| v
}

/// Initial slot offset that becomes `0` after the first group load.
const GROUP_SLOT_INIT: usize = 0_usize.wrapping_sub(GROUP_SIZE);

/// Iterator over occupied slot indices in one arena region.
///
/// Map-level iterators reuse this as their group scanner while they decide
/// which region to scan next.
#[derive(Clone)]
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
            let remaining = usize::try_from(unsafe { self.end_ctrl.offset_from(self.next_ctrl) })
                .expect("iterator control pointers remain ordered");
            if remaining >= GROUP_SIZE {
                self.current_mask = unsafe { simd::occupied_mask_group(self.next_ctrl) };
                self.next_ctrl = unsafe { self.next_ctrl.add(GROUP_SIZE) };
            } else {
                let mut mask = 0_u64;
                for index in 0..remaining {
                    let control = unsafe { *self.next_ctrl.add(index) };
                    if control.is_occupied() {
                        let lane = u32::try_from(index).expect("control-group lane fits u32");
                        mask |= 1_u64 << (lane * BITMASK_STRIDE);
                    }
                }
                self.current_mask = BitMask(mask);
                self.next_ctrl = self.end_ctrl;
            }
        }
    }
}

/// Per-region scan state shared by the backends' `Scan` cursors: an
/// [`OccupiedSlots`] group scanner plus the current region's cached slot
/// pointer. Owns the per-region mechanics; each backend keeps its own region
/// ordering and location construction.
#[derive(Clone)]
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
