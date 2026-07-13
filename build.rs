//! Build script: emits the `opthash_*` control-group `cfg`s (and their
//! `check-cfg` declarations) chosen from the target arch, target features, and
//! the `nightly` feature.

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_FEATURE");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NIGHTLY");

    for cfg in [
        "opthash_avx512_group",
        "opthash_wide_group",
        "opthash_neon_group",
        "opthash_x86_16_group",
        "opthash_scalar_group",
    ] {
        println!("cargo:rustc-check-cfg=cfg({cfg})");
    }

    let nightly = std::env::var_os("CARGO_FEATURE_NIGHTLY").is_some();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let features = std::env::var("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let has_feature = |feature: &str| features.split(',').any(|f| f == feature);

    // Only nightly AVX-512 builds use the 64-byte control-group layout.
    let avx512_group =
        nightly && arch == "x86_64" && has_feature("avx512f") && has_feature("avx512bw");
    // Portable SWAR-8 fallback for targets without a NEON/SSE control scan.
    let scalar = arch != "x86_64" && arch != "aarch64";

    if avx512_group {
        println!("cargo:rustc-cfg=opthash_x86_16_group");
    }
    if arch == "aarch64" {
        println!("cargo:rustc-cfg=opthash_neon_group");
    }
    if arch == "x86_64" && !avx512_group {
        println!("cargo:rustc-cfg=opthash_x86_16_group");
    }
    if scalar {
        println!("cargo:rustc-cfg=opthash_scalar_group");
    }
}
