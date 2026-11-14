//! Cache-line prefetch hints for writes the caller is about to make.

/// Asks the CPU to start loading `ptr`'s cache line ahead of a write, with a
/// write-intent hint where the target's baseline instruction set has one. A
/// hint only: it never faults, reads, or writes, so any address is sound.
#[inline]
pub(crate) fn prefetch_write<T>(ptr: *const T) {
    #[cfg(all(target_arch = "aarch64", not(miri)))]
    // SAFETY: `prfm` is a hint that never faults and touches no memory.
    unsafe {
        core::arch::asm!(
            "prfm pstl1keep, [{ptr}]",
            ptr = in(reg) ptr,
            options(nostack, preserves_flags, readonly),
        );
    }
    #[cfg(all(
        any(target_arch = "x86", target_arch = "x86_64"),
        target_feature = "sse",
        not(miri)
    ))]
    // SAFETY: the `sse` feature `_mm_prefetch` needs is enabled for the whole
    // build, and the hint never faults and touches no memory.
    unsafe {
        #[cfg(target_arch = "x86")]
        use core::arch::x86::{_MM_HINT_T0, _mm_prefetch};
        #[cfg(target_arch = "x86_64")]
        use core::arch::x86_64::{_MM_HINT_T0, _mm_prefetch};
        _mm_prefetch::<_MM_HINT_T0>(ptr.cast());
    }
    #[cfg(not(any(
        all(target_arch = "aarch64", not(miri)),
        all(
            any(target_arch = "x86", target_arch = "x86_64"),
            target_feature = "sse",
            not(miri)
        )
    )))]
    let _ = ptr;
}
