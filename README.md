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
clavifaber 'YggdrasilKeypairSetup.{ /var/lib/clavifaber/yggdrasil/keypair.json }'
clavifaber 'PublicKeyPublicationWriting.{ probus { /etc/ssh/ssh_host_ed25519_key.pub } None None /var/lib/clavifaber/publication.datom }'
```

The CLI accepts one generated `ClaviFaberRequest` Datom per invocation and
prints one generated `ClaviFaberResponse` Datom. The public publication is a
direct `PublicKeyPublication` Datom at `publication.datom`; retained
`publication.dotos` files are not read or rewritten.

## Development

```sh
nix flake check
nix run .#test-pki-lifecycle
```

`nix flake check` runs the pure Rust build, tests, formatting, and clippy
checks. `nix run .#test-pki-lifecycle` runs the impure GPG/gpg-agent lifecycle
test in a temporary home.

Pure tests include process-level coverage for the inline Datom request surface.
The impure lifecycle covers GPG key creation, CA
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
