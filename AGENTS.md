# Agent Bootstrap — clavifaber

## First thing

Run `bd list --status open` to see what's already on the table.

## Hard process rules

- Jujutsu only. Never `git` CLI.
- Push immediately after every change.
- Mentci three-tuple commit format:
  `(("CommitType", "scope"), ("Action", "what"), ("Verdict", "why"))`.

## Scope

GPG → X.509 PKI tool plus node-identity complex generation. Used by
CriomOS for WiFi EAP-TLS and node SSH key derivation.
