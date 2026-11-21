use super::arena::ArenaSlots;
use super::bitmask::{BITMASK_STRIDE, BitMask};
use super::config::GROUP_SIZE;
use super::control;
use super::simd;

/// Initial slot offset that becomes `0` after the first group load.
const GROUP_SLOT_INIT: usize = 0_usize.wrapping_sub(GROUP_SIZE);

/// Load occupied lanes, using scalar reads only for a final partial group.
///
/// # Safety
/// `ctrl` must address at least `remaining.min(GROUP_SIZE)` control bytes.
#[inline]
unsafe fn occupied_mask(ctrl: *const u8, remaining: usize) -> BitMask {
    if remaining >= GROUP_SIZE {
        // SAFETY: `remaining >= GROUP_SIZE`, so the caller guarantees a full
        // group is readable.
        return unsafe { simd::occupied_mask_group(ctrl) };
    }
    let mut mask = 0_u64;
    for index in 0..remaining {
        // SAFETY: `index < remaining`, all of which the caller guarantees readable.
        let control = unsafe { *ctrl.add(index) };
        if control::is_occupied(control) {
            let lane = u32::try_from(index).expect("control-group lane fits u32");
            mask |= 1_u64 << (lane * BITMASK_STRIDE);
        }
    }
    BitMask(mask)
}

/// Pointerless group scanner for a single region. The caller supplies the same
/// region on each step; removing already-yielded slots is allowed, but resizing
/// or inserting while a scan is in progress is not.
#[derive(Clone, Debug)]
pub(crate) struct OccupiedIndices {
    current_group_slot: usize,
    current_mask: BitMask,
}

impl OccupiedIndices {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            current_group_slot: GROUP_SLOT_INIT,
            current_mask: BitMask(0),
        }
    }

    #[inline]
    pub(crate) fn step<T, D: ArenaSlots<T> + ?Sized>(&mut self, region: &D) -> Option<usize> {
        loop {
            if let Some(bit) = self.current_mask.next() {
                return Some(self.current_group_slot + bit);
            }
            let next_group = self.current_group_slot.wrapping_add(GROUP_SIZE);
            if next_group >= region.capacity() {
                return None;
            }
            self.current_group_slot = next_group;
            // SAFETY: `next_group` is in bounds.
            self.current_mask = unsafe { group_mask(region, next_group) };
        }
    }

    /// Folds the slots [`step`](Self::step) would yield from here on. `f`
    /// gets the region back so it can remove the slot it is handed.
    ///
    /// Empty groups are skipped in a loop of their own, which keeps the
    /// per-group work of a sparse region below that of repeated `step` calls.
    #[inline]
    pub(crate) fn fold<T, D: ArenaSlots<T> + ?Sized, B>(
        self,
        region: &mut D,
        init: B,
        mut f: impl FnMut(B, &mut D, usize) -> B,
    ) -> B {
        let capacity = region.capacity();
        let mut group = self.current_group_slot;
        let mut mask = self.current_mask;
        let mut acc = init;
        loop {
            for bit in mask {
                acc = f(acc, region, group + bit);
            }
            loop {
                group = group.wrapping_add(GROUP_SIZE);
                if group >= capacity {
                    return acc;
                }
                // SAFETY: `group` is in bounds.
                mask = unsafe { group_mask(region, group) };
                if mask.0 != 0 {
                    break;
                }
            }
        }
    }
}

/// Occupied lanes of the group starting at slot `group`.
///
/// # Safety
/// `group < region.capacity()`.
#[inline]
unsafe fn group_mask<T, D: ArenaSlots<T> + ?Sized>(region: &D, group: usize) -> BitMask {
    // SAFETY: `group` is in bounds. A padded region keeps a full group
    // readable past it, and its padding never reads occupied; otherwise
    // `occupied_mask` reads at most the remaining controls.
    unsafe {
        let ctrl = region.ctrl_ptr().add(group);
        if D::PADDED_TAIL {
            simd::occupied_mask_group(ctrl)
        } else {
            occupied_mask(ctrl, region.capacity() - group)
        }
    }
}
