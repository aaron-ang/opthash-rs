//! Panic-safe resize shared by both tables: build the new generation from
//! bitwise copies, and free the old arena only once every entry has moved.

use core::ptr;

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

    /// Places an entry known to be absent from a table being rebuilt.
    /// Returns `true` on exceptional placement. Must run no user code: a
    /// panic here would leave the entry owned by both generations.
    fn place_unique(&mut self, entry: SlotEntry<Self::Key, Self::Value>, key_hash: u64) -> bool;
}

/// Moves every entry of `table` into `next` and installs it. Each key is
/// hashed in place before its entry is copied, so a panicking hasher
/// leaves `table` exactly as it was. Returns `true` if any entry needed
/// exceptional placement.
pub(crate) fn rebuild<T: Rebuildable>(table: &mut T, next: T::Generation) -> bool {
    let mut rebuild = Rebuild::start(table, next);
    let mut exceptional = false;
    let Rebuild { table, previous } = &mut rebuild;
    let previous = previous.as_ref().expect("rebuild not yet committed");
    for region in T::regions(previous) {
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
    }
    rebuild.commit();
    exceptional
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
