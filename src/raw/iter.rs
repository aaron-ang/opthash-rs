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
            // SAFETY: `next_group` is in bounds, and `occupied_mask` reads at
            // most the remaining controls, including a partial final group.
            self.current_mask = unsafe {
                occupied_mask(
                    region.ctrl_ptr().add(next_group),
                    region.capacity() - next_group,
                )
            };
        }
    }
}
