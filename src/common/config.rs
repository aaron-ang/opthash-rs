/// `SwissTable` control-byte group width; SIMD scans operate one group at a time.
pub(crate) const GROUP_SIZE: usize = 16;
/// First-allocation slot count when a map grows from empty.
pub(crate) const INITIAL_CAPACITY: usize = 16;
/// Default headroom: `max_insertions = capacity * (1 - reserve_fraction)`.
pub(crate) const DEFAULT_RESERVE_FRACTION: f64 = 0.10;
/// Lower clamp for `sanitize_reserve_fraction`.
pub(crate) const MIN_RESERVE_FRACTION: f64 = 1e-6;
/// Upper clamp for `sanitize_reserve_fraction`.
pub(crate) const MAX_RESERVE_FRACTION: f64 = 0.999_999;
