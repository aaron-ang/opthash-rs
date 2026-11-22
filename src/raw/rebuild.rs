//! Panic-safe resize shared by both tables: build the new generation from
//! bitwise copies, and free the old arena only once every entry has moved.

use core::{mem, ptr};

use super::arena::{ArenaSlots, SlotEntry};
use super::iter::OccupiedIndices;

/// A table whose storage a resize replaces as one unit, a generation.
pub(crate) trait Rebuildable {
    type Key;
    type Value;
    type Region: ArenaSlots<SlotEntry<Self::Key, Self::Value>>;
    /// The fields a resize replaces, holding an arena and its regions.
    type Generation;

    /// Exchanges the table's storage fields with `other`.
    fn swap_generation(&mut self, other: &mut Self::Generation);

    fn regions(generation: &Self::Generation) -> &[Self::Region];

    /// Frees `generation`'s arena without dropping any entry in it.
    fn release(&self, generation: Self::Generation);

    fn hash_key(&self, key: &Self::Key) -> u64;

    /// Prefetches the lines a later [`place_unique`](Self::place_unique) of
    /// `key_hash` will write. A hint: it must not change table state.
    fn prefetch_placement(&self, key_hash: u64);

    /// Places an entry known to be absent from a table being rebuilt.
    /// Returns `true` on exceptional placement. Must run no user code: a
    /// panic here would leave the entry owned by both generations. Must
    /// leave the state [`swap_generation`](Self::swap_generation) does not
    /// swap as it found it: a rollback swaps the old generation back under
    /// that state.
    fn place_unique(&mut self, entry: SlotEntry<Self::Key, Self::Value>, key_hash: u64) -> bool;
}

/// Entries hashed and prefetched ahead of the one being placed, so their
/// cache misses overlap instead of running one after another. The distance
/// only has to give a prefetch time to finish before its entry is placed;
/// going further gains nothing.
const PREFETCH_DISTANCE: usize = 16;

/// Smallest old-generation slot footprint that rebuilds with prefetching. A
/// smaller table stays in cache, where hashing ahead is only extra work.
///
/// The value assumes a cache size; it is not a property of the table. With a
/// smaller cache, some rebuilds that would gain from prefetching take the
/// plain loop. With a larger one, some rebuilds prefetch without need, at a
/// small cost.
pub(crate) const PREFETCH_MIN_BYTES: usize = 1 << 22;

/// Moves every entry of `table` into `next` and installs it. Each key is
/// hashed in place before its entry is copied, so a panicking hasher
/// leaves `table` exactly as it was. Returns `true` if any entry needed
/// exceptional placement.
pub(crate) fn rebuild<T: Rebuildable>(table: &mut T, next: T::Generation) -> bool {
    let mut rebuild = Rebuild::start(table, next);
    let mut exceptional = false;
    let Rebuild { table, previous } = &mut rebuild;
    let previous = previous.as_ref().expect("rebuild not yet committed");
    let regions = T::regions(previous);
    let slots: usize = regions.iter().map(ArenaSlots::capacity).sum();
    let prefetch =
        slots.saturating_mul(mem::size_of::<SlotEntry<T::Key, T::Value>>()) >= PREFETCH_MIN_BYTES;
    if prefetch {
        for region in regions {
            exceptional |= place_region_prefetched(&mut **table, region);
        }
    } else {
        for region in regions {
            exceptional |= place_region(&mut **table, region);
        }
    }
    rebuild.commit();
    exceptional
}

/// Places every entry of `region` into `table` in slot order.
#[inline]
fn place_region<T: Rebuildable>(table: &mut T, region: &T::Region) -> bool {
    let mut exceptional = false;
    let mut scan = OccupiedIndices::new();
    while let Some(slot) = scan.step(region) {
        // SAFETY: `step` yields occupied in-bounds slots.
        let entry = unsafe { region.get_ref(slot) };
        let key_hash = table.hash_key(&entry.key);
        // SAFETY: the copy becomes the live entry; `previous` keeps the
        // original only until `commit` frees its arena without drops.
        let entry = unsafe { ptr::read(entry) };
        exceptional |= table.place_unique(entry, key_hash);
    }
    exceptional
}

/// [`place_region`] with each entry hashed and its placement prefetched
/// [`PREFETCH_DISTANCE`] entries ahead. Placement order is unchanged. Out of
/// line so the plain loop compiles as if this one did not exist.
#[inline(never)]
fn place_region_prefetched<T: Rebuildable>(table: &mut T, region: &T::Region) -> bool {
    let mut exceptional = false;
    let mut scan = OccupiedIndices::new();
    // A ring of `(slot, key_hash)` waiting to be placed, oldest at `head`.
    let mut pending = [(0_usize, 0_u64); PREFETCH_DISTANCE];
    let mut head = 0;
    let mut queued = 0;
    loop {
        while queued < PREFETCH_DISTANCE {
            let Some(slot) = scan.step(region) else {
                break;
            };
            // SAFETY: `step` yields occupied in-bounds slots.
            let key_hash = table.hash_key(unsafe { &region.get_ref(slot).key });
            table.prefetch_placement(key_hash);
            pending[(head + queued) % PREFETCH_DISTANCE] = (slot, key_hash);
            queued += 1;
        }
        if queued == 0 {
            return exceptional;
        }
        let (slot, key_hash) = pending[head];
        head = (head + 1) % PREFETCH_DISTANCE;
        queued -= 1;
        // SAFETY: `slot` was yielded occupied and is read exactly once. The
        // copy becomes the live entry; `previous` keeps the original only
        // until `commit` frees its arena without drops.
        let entry = unsafe { ptr::read(region.get_ref(slot)) };
        exceptional |= table.place_unique(entry, key_hash);
    }
}

/// A resize in progress: the table holds the new generation and `previous`
/// holds the old one, whose entries it still owns. Dropping an uncommitted
/// rebuild puts the old generation back and frees the new arena without
/// dropping its entries, which are bitwise copies.
struct Rebuild<'a, T: Rebuildable> {
    table: &'a mut T,
    previous: Option<T::Generation>,
}

impl<'a, T: Rebuildable> Rebuild<'a, T> {
    fn start(table: &'a mut T, mut next: T::Generation) -> Self {
        table.swap_generation(&mut next);
        Self {
            table,
            previous: Some(next),
        }
    }

    /// Frees the old arena. Every entry it held now lives in the table.
    fn commit(mut self) {
        let previous = self.previous.take().expect("rebuild committed once");
        self.table.release(previous);
    }
}

impl<T: Rebuildable> Drop for Rebuild<'_, T> {
    fn drop(&mut self) {
        if let Some(mut previous) = self.previous.take() {
            self.table.swap_generation(&mut previous);
            self.table.release(previous);
        }
    }
}
