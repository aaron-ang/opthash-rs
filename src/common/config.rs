/// `SwissTable` control-byte group width; SIMD scans operate one group at a time.
#[cfg(opthash_wide_group)]
pub(crate) const GROUP_SIZE_U32: u32 = 64;
/// Portable SWAR and NEON groups fit eight control bytes in one `u64` mask.
#[cfg(any(opthash_scalar_group, opthash_neon_group))]
pub(crate) const GROUP_SIZE_U32: u32 = 8;
#[cfg(opthash_x86_16_group)]
pub(crate) const GROUP_SIZE_U32: u32 = 16;
pub(crate) const GROUP_SIZE: usize = GROUP_SIZE_U32 as usize;
/// Align arena allocations so memset can use cache-line fast paths.
pub(crate) const CACHE_LINE: usize = 64;
/// First-allocation slot count when a map grows from empty.
#[cfg(opthash_neon_group)]
pub(crate) const INITIAL_CAPACITY: usize = 16;
#[cfg(not(opthash_neon_group))]
pub(crate) const INITIAL_CAPACITY: usize = GROUP_SIZE;
