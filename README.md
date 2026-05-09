# clavifaber

ClaviFaber forms host key material for CriomOS and produces the public
projection records the rest of the cluster needs. The current implementation
derives a node identity directory, issues a self-signed CA certificate from a
GPG Ed25519 key, and issues server/node certificates for WiFi PKI (EAP-TLS).

The repository is intentionally separate from CriomOS so the key-management
tool can be versioned and tested on its own cadence.

## Commands

Preferred operator surface:

```sh
clavifaber '(IdentityDirectoryInitialization "/var/lib/clavifaber")'
clavifaber '(PublicKeyPublicationRequest probus "/var/lib/clavifaber" None None None)'
```

Compatibility commands:

- `clavifaber ca-init --keygrip <G> --cn <N> --out ca.crt`
- `clavifaber server-cert --ca-keygrip <G> --ca-cert ca.crt --cn <N> --out-cert server.crt --out-key server.key`
- `clavifaber node-cert --ca-keygrip <G> --ca-cert ca.crt --ssh-pubkey <S> --cn <N> --out node.crt`
- `clavifaber complex-init --dir <D>`
- `clavifaber derive-pubkey --dir <D>`
- `clavifaber verify --ca-cert ca.crt --cert some.crt`

The Clap command surface is a compatibility bridge. New operator-facing work
targets the Nota request surface described in `ARCHITECTURE.md`.

## Development

```sh
nix flake check
nix run .#test-pki-lifecycle
```

`nix flake check` runs the pure Rust build, tests, formatting, and clippy
checks. `nix run .#test-pki-lifecycle` runs the impure GPG/gpg-agent lifecycle
test in a temporary home.

Pure tests include process-level coverage for the compatibility CLI and the
inline Nota request surface. The impure lifecycle covers GPG key creation, CA
certificate generation, server certificate generation, node certificate
generation, verification, and identity corruption recovery.

## Consumption

```nix
inputs.clavifaber.url = "github:LiGoldragon/clavifaber";
# inputs.clavifaber.packages.${system}.default
```

## Conventions

- Jujutsu (`jj`) for all VCS. Never `git` CLI.
- Mentci three-tuple commit format.
- See `ARCHITECTURE.md` and `skills.md` before changing private-material or
  publication behavior.
