//! Build script: emits the `opthash_*` control-group `cfg`s (and their
//! `check-cfg` declarations) chosen from the target architecture.

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_CFG_TARGET_ARCH");

    for cfg in [
        "opthash_avx512_group",
        "opthash_wide_group",
        "opthash_neon_group",
        "opthash_x86_16_group",
        "opthash_scalar_group",
    ] {
        println!("cargo:rustc-check-cfg=cfg({cfg})");
    }

    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    // Portable SWAR-8 fallback for targets without a NEON/SSE control scan.
    let scalar = arch != "x86_64" && arch != "aarch64";

    if arch == "aarch64" {
        println!("cargo:rustc-cfg=opthash_neon_group");
    }
    if arch == "x86_64" {
        println!("cargo:rustc-cfg=opthash_x86_16_group");
    }
    if scalar {
        println!("cargo:rustc-cfg=opthash_scalar_group");
    }
}
