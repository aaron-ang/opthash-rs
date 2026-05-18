use std::fmt;

/// Read-only view into an occupied entry. Implemented by each map's
/// `OccupiedEntry` so the shared `OccupiedError` impls can format key/value.
/// Method names are prefixed to avoid colliding with the inherent
/// `key`/`get` methods on the concrete entry types.
pub trait EntryView {
    type Key;
    type Value;
    fn view_key(&self) -> &Self::Key;
    fn view_value(&self) -> &Self::Value;
}

/// Error returned by `try_insert` on key collision. Generic over the
/// concrete `OccupiedEntry` newtype so each map can re-export this with
/// its own entry type bound.
pub struct OccupiedError<E, V> {
    /// The existing entry.
    pub entry: E,
    /// The value that was rejected.
    pub value: V,
}

impl<E, V> fmt::Debug for OccupiedError<E, V>
where
    E: EntryView<Value = V>,
    E::Key: fmt::Debug,
    V: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OccupiedError")
            .field("key", self.entry.view_key())
            .field("value", &self.value)
            .finish()
    }
}

impl<E, V> fmt::Display for OccupiedError<E, V>
where
    E: EntryView<Value = V>,
    E::Key: fmt::Debug,
    V: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tried to insert {:?}, but key {:?} was already present with {:?}",
            self.value,
            self.entry.view_key(),
            self.entry.view_value(),
        )
    }
}

impl<E, V> std::error::Error for OccupiedError<E, V>
where
    E: EntryView<Value = V>,
    E::Key: fmt::Debug,
    V: fmt::Debug,
{
}
