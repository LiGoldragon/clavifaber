# clavifaber

GPG → X.509 certificate tool for CriomOS. Derives a node-identity complex
(Ed25519 keypair), issues a self-signed CA certificate from a GPG Ed25519 key,
and issues server/node certificates for WiFi PKI (EAP-TLS).

Split out from legacy CriomOS `src/clavifaber/` so the tool can be consumed
independently and versioned on its own cadence.

## Commands

- `clavifaber ca-init --keygrip <G> --cn <N> --out ca.crt`
- `clavifaber server-cert --ca-keygrip <G> --ca-cert ca.crt --cn <N> --out-cert server.crt --out-key server.key`
- `clavifaber node-cert --ca-keygrip <G> --ca-cert ca.crt --ssh-pubkey <S> --cn <N> --out node.crt`
- `clavifaber complex-init --dir <D>`
- `clavifaber derive-pubkey --dir <D>`
- `clavifaber verify --ca-cert ca.crt --cert some.crt`

## Layout

Blueprint flake:

- `src/`, `Cargo.toml`, `Cargo.lock` — the Rust crate.
- `packages/default.nix` → `packages.<system>.default` (wrapped with GPG on PATH).
- `devshell.nix`, `formatter.nix`.

## Consumption

```nix
inputs.clavifaber.url = "github:LiGoldragon/clavifaber";
# → inputs.clavifaber.packages.${system}.default
```

## Conventions

- Jujutsu (`jj`) for all VCS. Never `git` CLI.
- Mentci three-tuple commit format.
