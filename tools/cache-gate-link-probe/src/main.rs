use std::hint::black_box;

macro_rules! probe_kernel {
    ($cfg:ident, $name:ident, $section:literal, $value:expr) => {
        #[cfg($cfg)]
        // SAFETY: Capability probe links this code with the matching checked
        // target-specific ELF augmentation and validates the final segments.
        #[unsafe(link_section = $section)]
        #[inline(never)]
        fn $name(value: u64) -> u64 {
            black_box(value).wrapping_mul($value)
        }
    };
}

probe_kernel!(
    cache_gate_probe_elastic,
    elastic_cache_gate_insert_kernel,
    ".text.opthash.cache_gate.elastic.insert",
    3
);
probe_kernel!(
    cache_gate_probe_elastic,
    elastic_cache_gate_get_kernel,
    ".text.opthash.cache_gate.elastic.get",
    5
);
probe_kernel!(
    cache_gate_probe_funnel,
    funnel_cache_gate_insert_kernel,
    ".text.opthash.cache_gate.funnel.insert",
    7
);
probe_kernel!(
    cache_gate_probe_funnel,
    funnel_cache_gate_get_kernel,
    ".text.opthash.cache_gate.funnel.get",
    11
);
probe_kernel!(
    cache_gate_probe_profile,
    elastic_profile_insert_kernel,
    ".text.opthash.cache_gate.profile.elastic.insert",
    13
);
probe_kernel!(
    cache_gate_probe_profile,
    elastic_profile_get_kernel,
    ".text.opthash.cache_gate.profile.elastic.get",
    17
);
probe_kernel!(
    cache_gate_probe_profile,
    funnel_profile_insert_kernel,
    ".text.opthash.cache_gate.profile.funnel.insert",
    19
);
probe_kernel!(
    cache_gate_probe_profile,
    funnel_profile_get_kernel,
    ".text.opthash.cache_gate.profile.funnel.get",
    23
);

fn main() {
    #[cfg(cache_gate_probe_elastic)]
    black_box(
        elastic_cache_gate_insert_kernel(29) ^ elastic_cache_gate_get_kernel(31),
    );
    #[cfg(cache_gate_probe_funnel)]
    black_box(funnel_cache_gate_insert_kernel(37) ^ funnel_cache_gate_get_kernel(41));
    #[cfg(cache_gate_probe_profile)]
    black_box(
        elastic_profile_insert_kernel(43)
            ^ elastic_profile_get_kernel(47)
            ^ funnel_profile_insert_kernel(53)
            ^ funnel_profile_get_kernel(59),
    );
}
