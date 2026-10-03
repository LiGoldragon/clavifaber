# Upgrades

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
