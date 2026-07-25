# Reviewed cache-gate record fixture

`aarch64-attempt-5-records.tar.xz` is a deterministic, solid-compressed copy of
the accepted AArch64 attempt-5 records used to review the portable verifier's
real recursive schemas and semantic relationships. It contains:

- the original capability record;
- original clean-a, clean-b, and adversary v2 manifests;
- the original replayed v1 manifest shape;
- all nine capability shape symbol, layout, link-argument, linker-execution,
  and trace records;
- all six explicit GNU/LLD Cargo-execution and trace records;
- all nine reviewed manifest link-command and link-trace records.

The capability, v1, and shape bytes are unchanged. The reviewed v2 manifests
have two documented safety normalizations. First, trailing empty
`LD_LIBRARY_PATH` elements were removed from captured `rustc_argv` environment
strings because an empty dynamic-library search element denotes the current
directory and is rejected by the portable verifier. Second, each executable
fragment record and each corresponding `-T` command/trace token was normalized
from its same-hash per-manifest copy to the exact absolute path authenticated
by `capability.fragments[target]`; the affected command, trace, and manifest
hash records were recomputed. No linker input or link order changed. Large ELF
binaries, link maps, rlibs, and toolchain payloads are omitted; their original
hash records, complete linker chains/raw symlink targets, and every
`rlib(member)` owner remain in the JSON. Focused tests bind the five top-level
records to reviewed fixture SHA-256 values and exercise tiny real `ar` archives
for member-index behavior.

The v1 record was produced at `1080c188a47f02202b6a0878830dbf2947629992`,
whose tree is the exact replay tree
`d77cc082fe48799f26ff4440bd1898a71d0dc8cc`, shared by the selected replay
commit `b0d53234dc051af91fe0321450b3e8312a84e635`. The fixture proves the real v1
schema; archive acceptance separately requires the selected exact replay
commit.

Fixture SHA-256:

```text
100920ab673be133a57cd193c9d02118c2feb7bdc470e37c09e53124ee05d6ee  aarch64-attempt-5-records.tar.xz
```

This fixture is schema/semantic test evidence only. It is not native x86-64
acceptance evidence.
