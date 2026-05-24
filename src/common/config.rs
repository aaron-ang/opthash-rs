/// `SwissTable` control-byte group width; SIMD scans operate one group at a time.
pub(crate) const GROUP_SIZE: usize = 16;
pub(crate) const GROUP_SIZE_F64: f64 = 16.0;
/// First-allocation slot count when a map grows from empty.
pub(crate) const INITIAL_CAPACITY: usize = 16;
/// Default headroom: `max_insertions = capacity * (1 - reserve_fraction)`.
pub(crate) const DEFAULT_RESERVE_FRACTION: f64 = 0.10;
/// Lower clamp for `sanitize_reserve_fraction`.
pub(crate) const MIN_RESERVE_FRACTION: f64 = 1e-6;
/// Upper clamp for `sanitize_reserve_fraction`.
pub(crate) const MAX_RESERVE_FRACTION: f64 = 0.999_999;
/// Default `ElasticOptions::probe_scale`.
pub(crate) const DEFAULT_PROBE_SCALE: f64 = 16.0;
/// Upper bound on `FunnelOptions::reserve_fraction`; level capacities become
/// unstable beyond this load factor.
pub(crate) const MAX_FUNNEL_RESERVE_FRACTION: f64 = 1.0 / 8.0;
/// Control-byte region alignment. 64 = cache-line size, so the first group
/// is line-aligned and groups pack 4-per-line without straddling.
pub(crate) const CONTROL_ALIGN: usize = 64;
