# Reviewed cache-gate record fixture

`aarch64-attempt-5-records.tar.xz` is a deterministic, solid-compressed copy of
the accepted AArch64 attempt-5 records used to review the portable verifier's
real recursive schemas and semantic relationships. It contains:

- the original capability record;
- original clean-a, clean-b, and adversary v2 manifests;
- the original replayed v1 manifest shape;
- all nine capability shape symbol, layout, link-argument, linker-execution,
  and trace records;
- all six explicit GNU/LLD Cargo-execution and trace records.

The JSON and log bytes are unchanged. Large ELF binaries, link maps, rlibs, and
toolchain payloads are omitted; their original hash records, complete linker
chains/raw symlink targets, and every `rlib(member)` owner remain in the JSON.
Focused tests bind the five top-level source records to their reviewed SHA-256
values and exercise tiny real `ar` archives for member-index behavior.

The v1 record was produced at `1080c188a47f02202b6a0878830dbf2947629992`,
whose tree is the exact replay tree
`d77cc082fe48799f26ff4440bd1898a71d0dc8cc`, shared by the selected replay
commit `b0d53234dc051af91fe0321450b3e8312a84e635`. The fixture proves the real v1
schema; archive acceptance separately requires the selected exact replay
commit.

Fixture SHA-256:

```text
088f5e3edfdc3d0d51ca2b7cb4f24bd2247f5b47c4794c726b9401f854144b69  aarch64-attempt-5-records.tar.xz
```

This fixture is schema/semantic test evidence only. It is not native x86-64
acceptance evidence.
