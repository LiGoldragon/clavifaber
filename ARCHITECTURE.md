# ClaviFaber Architecture

ClaviFaber forms and publishes host key material for CriomOS nodes. It is a
local authority over private host material and a producer of public
projections; it is not the cluster database itself.

## Planes

### Local Material

The local material plane owns private key creation and repair. Private key
bytes must stay out of stdout, logs, reports, test fixtures, and the Nix store.
The current implementation creates an Ed25519 node identity directory with:

- `key.pem`: PKCS#8 private key, mode `0600`.
- `ssh.pub`: OpenSSH public key projection, mode `0644`.

The directory is mode `0700`. If the private key is corrupt, ClaviFaber moves it
aside before generating replacement material. The broken material remains local
for forensic inspection.

### Public Projection

The public projection plane turns private material into records other hosts can
trust. Today this includes the OpenSSH public key and X.509 certificates for the
CriomOS WiFi PKI path. The intended cluster bundle also includes Yggdrasil
identity material and any WiFi client certificate public metadata needed by the
cluster database.

This plane should produce typed records. Consumers must not poll arbitrary files
looking for key changes; producers push a complete current public projection
when material is created or repaired.

### Certificate Authority

The certificate-authority plane bridges a GPG Ed25519 signing key into X.509
certificates. It currently supports:

- a self-signed CA certificate from a GPG keygrip,
- a P-256 server key and certificate,
- a node certificate from an Ed25519 OpenSSH public key,
- issuer and signature verification against the CA certificate.

This code path is functional but still older than the repo discipline. New work
should move certificate operations behind data-bearing request/issuer types and
avoid adding new public free functions.

### Publication

The publication plane is still design work. ClaviFaber should emit a typed
public-key publication record for the component that owns the CriomOS cluster
database. It should not learn ad hoc paths into unrelated repositories and
should not mutate cluster state through string patches.

## Command Surface

The current Clap command line exists for compatibility with the extracted
prototype. The target operator surface is a single Nota request argument with
typed request and result records. No new flag/subcommand surface should be added
unless it is explicitly a temporary compatibility bridge.

## Test Contract

Pure Rust tests run through `nix flake check`. The GPG/gpg-agent lifecycle is an
impure integration test exposed as:

```sh
nix run .#test-pki-lifecycle
```

Tests should be named by their behavioral premise and should use fixture nouns
instead of inline command plumbing.
