# Upgrades

## 0.8.1

Selects the Rust toolchain by version, `1.99.1`, in place of the floating `stable` channel. The channel manifest for 1.99.1 (rustc 1.99.1, 58cf8f9c3, 2026-10-13, manifest dated 2026-10-15) is byte-identical to what `stable` served, verified by hash `sha256-+xUr6Al1wZSqX8aEsq7DpuFOK4Ve/i+qTl+K5uWQ9GM=`, so the flake's integrity hash is unchanged. Components and profile are unchanged. The 0.8.0 stale-hash failure came from `stable` moving: specified `sha256-zm3dyIY2T414ZRR3EhLOvptzG6gta4WZUcawzMUWtqI=`, got `sha256-+xUr6Al1wZSqX8aEsq7DpuFOK4Ve/i+qTl+K5uWQ9GM=`. A version moves to a patch release when it changes only the build's pins. No source, API or state change.

## 0.8.0

Repins protos 0.33.0 (3c7a), datom-codec 0.33.0 (eabe) and ethos-zero 19.2.0 (5a5d, flake input now the bare URL, the lock pins).

What breaks:

- Generated Rust (`src/generated/clavifaber.rs`) adds `clippy::type_complexity` to its crate-level allow. No type or derive changed.
- `protos` is spelled `rev = "3c7ade3"` to match the spelling datom-codec uses, so the lock holds one protos source.
- Protos 0.33.0 makes `ReaderBudget` fields private; the command budget and the tests build it with `ReaderBudget::try_from`.
- The flake's Rust toolchain hash is refreshed, because the stable channel moved and the old hash no longer matched.
- No change to the request surface, the replies or `publication.datom`.

How to deploy: build clavifaber 0.8.0 and replace the binary. No stored state changes.

## 0.7.0

Repins ethos-zero 16.0.0, protos 0.32.2 and datom-codec 0.32.2.

What breaks:

- Generated Rust (`src/generated/clavifaber.rs`) now derives rkyv Archive,
  Serialize and Deserialize on every type; Datomizable and Composing sit behind
  the `datom` feature. The crate depends on rkyv 0.8 and declares `datom`,
  on by default because the crate's Error, request surface and tests name
  datom-codec unconditionally; building without it does not compile.
- Command-line replies and the written `publication.datom` use the one-line
  `Compactable::compact` print. `Textualizable::textualize` is now the vertical
  canonical print and is not used here. The text of a reply is unchanged from
  0.6.0; decoders accept both.

How to deploy: build clavifaber 0.7.0 and replace the binary. No stored state
changes; existing `publication.datom` files still decode.
