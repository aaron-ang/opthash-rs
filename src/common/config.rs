/// `SwissTable` control-byte group width; SIMD scans operate one group at a time.
#[cfg(opthash_wide_group)]
pub(crate) const GROUP_SIZE_U32: u32 = 64;
/// Portable SWAR fallback packs one group into a single `u64` (8 control bytes).
#[cfg(opthash_scalar_group)]
pub(crate) const GROUP_SIZE_U32: u32 = 8;
#[cfg(any(opthash_neon_group, opthash_x86_16_group))]
pub(crate) const GROUP_SIZE_U32: u32 = 16;
pub(crate) const GROUP_SIZE: usize = GROUP_SIZE_U32 as usize;
/// Align arena allocations so memset can use cache-line fast paths.
pub(crate) const CACHE_LINE: usize = 64;
/// First-allocation slot count when a map grows from empty.
pub(crate) const INITIAL_CAPACITY: usize = GROUP_SIZE;
/// Default headroom: `max_insertions = capacity * (1 - reserve_fraction)`.
pub(crate) const DEFAULT_RESERVE_FRACTION: f64 = 0.45;
/// Lower clamp for `sanitize_reserve_fraction`.
pub(crate) const MIN_RESERVE_FRACTION: f64 = 1e-6;
/// Upper clamp for `sanitize_reserve_fraction`.
pub(crate) const MAX_RESERVE_FRACTION: f64 = 0.999_999;
