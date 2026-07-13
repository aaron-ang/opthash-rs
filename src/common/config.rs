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

#[cfg(all(
    test,
    target_arch = "x86_64",
    target_feature = "avx512f",
    target_feature = "avx512bw",
    feature = "nightly"
))]
mod avx512_tests {
    #[test]
    fn avx512_keeps_the_sixteen_lane_layout() {
        assert_eq!(super::GROUP_SIZE, 16);
    }
}
