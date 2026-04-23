# Agent Bootstrap — clavifaber

## First thing

Run `bd list --status open` to see what's already on the table.

## Rust style

Follow [`~/git/tools-documentation/rust/style.md`](../tools-documentation/rust/style.md):
methods on types, typed newtypes for domain values (keygrip, cert, key
material — not raw `String`/`Vec<u8>` at boundaries), single-object I/O,
`thiserror`-derived `Error` enum (no `anyhow`, no `eyre`), trait-domain rule.

The current `src/` was copied verbatim from `criomos-archive/src/clavifaber`
during the split; refactor toward the style as you touch each module.

## Hard process rules

- Jujutsu only. Never `git` CLI.
- Push immediately after every change.
- Mentci three-tuple commit format:
  `(("CommitType", "scope"), ("Action", "what"), ("Verdict", "why"))`.

## Scope

GPG → X.509 PKI tool plus node-identity complex generation. Used by
CriomOS for WiFi EAP-TLS and node SSH key derivation.
