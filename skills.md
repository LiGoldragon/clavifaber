# ClaviFaber Repo Skill

Use this file with the workspace skills before editing this repository.

## Scope

ClaviFaber is a **host-key-material aggregator and certificate signer**
for CriomOS hosts. Its concern is:

1. Reading sshd's existing `/etc/ssh/ssh_host_ed25519_key.pub` (clavifaber
   does **not** create or own this key — that's sshd's job).
2. Issuing X.509 certificates against a GPG-Ed25519 cluster CA (CA cert,
   server cert + EC keypair, per-host client cert binding sshd's ed25519
   pubkey).
3. Generating a per-host Yggdrasil keypair (when wired in).
4. Writing the typed `publication.nota` aggregate that other hosts read.

It does **not** own:

- **The SSH host key.** sshd creates it. Clavifaber reads the `.pub` and
  aggregates. Rotating the SSH host key (the operator deletes
  `/etc/ssh/ssh_host_ed25519_key*` and restarts sshd) is fine; the next
  clavifaber run picks up the new pubkey. **The wifi-PKI client cert
  that bound the old pubkey is now stale** — delete the cert file (per
  the per-handler loud-fail policy) to force re-issuance.
- **Convergence orchestration.** Deciding "should I run?" or "is the
  system in the desired state?" belongs to an orchestrator
  (lojix today; future cluster orchestrator). Don't add a Converge
  request, an input-hash gate, or a sema/redb state file to clavifaber.
- The cluster database schema or deployment graph.
- Cluster-side aggregation of publication files.
- Rotation / renewal scheduling (parked).

## Operator surface — NOTA only

The CLI takes exactly one positional NOTA record. There is no Clap
subcommand surface; there is no `Converge` mega-request; there is no
`IdentitySetup` (sshd owns that). Six focused, idempotent verbs:

```sh
clavifaber '(CertificateAuthorityIssuance "<keygrip>" "<cn>" "/path/ca.pem")'
clavifaber '(ServerCertificateIssuance "<keygrip>" "/path/ca.pem" "<cn>" "/path/srv.pem" "/path/srv.key")'
clavifaber '(ClientCertificateIssuance "<keygrip>" "/path/ca.pem" "<ssh-ed25519 ...>" "<cn>" "/path/cli.pem")'
clavifaber '(CertificateChainVerification "/path/ca.pem" "/path/cert.pem")'
clavifaber '(YggdrasilKeypairSetup "/path/yggdrasil-keypair.json")'
clavifaber '(PublicKeyPublicationWriting <node-name> \
  (OpenSshPublicKeyLocation "/etc/ssh/ssh_host_ed25519_key.pub") \
  (YggdrasilKeypairLocation "/path/yggdrasil-keypair.json") | None \
  (WifiClientCertificateLocation "/path/client.pem") | None \
  "/path/publication.nota")'
```

Adding new operator behavior means adding a new variant to
`ClaviFaberRequest` (and a paired variant to `ClaviFaberResponse`).
Each variant is its own `NotaRecord`-deriving struct in `src/request.rs`
with its own `execute()` method.

## Safety

- Never print, snapshot, or place private key material in the Nix store,
  on stdout, on stderr, or in any response NOTA record.
- Clavifaber writes private bytes ONLY for: the X.509 server private
  key (`ServerCertificateIssuance.output_private_key`), the Yggdrasil
  keypair file (`YggdrasilKeypairSetup.keypair_path`). Both at mode 0600
  via `AtomicFile`.
- The SSH host key is sshd's responsibility; clavifaber must never
  attempt to write to `/etc/ssh/`.

## Rust shape

- Behavior lives on data-bearing nouns. No public free functions doing
  domain work. `main.rs` is the only place a free function (`run`) lives.
- One `Error` enum per crate via `thiserror`.
- Full English field and variable names.
- `serde_json` is the workspace-edge codec for parsing external-tool
  output (e.g. `yggdrasil -genconf -json`). Don't hand-roll JSON parsers —
  see `~/primary/skills/rust-discipline.md` §"No hand-rolled parsers".

## Actor topology

Four Kameo 0.20 actors live under `src/actors/`. The runtime root is
`actors::runtime_root::RuntimeRoot`; each request type's `execute()` is
`async` and dispatches through typed `Message<T>` impls.

Current actors: `GpgAgentSession`, `CertificateIssuer`, `YggdrasilKey`,
`TraceRecorder` (test-time only).

- `GpgAgentSession` is the **sole owner** of the `gpg_agent` module's
  connections (witness: `tests/forbidden_edges.rs`). The `gpg_agent`
  module is crate-private.
- `YggdrasilKey` is the **sole owner** of the `yggdrasil` binary
  invocation. Same shape; enforced by
  `only_yggdrasil_key_owns_the_yggdrasil_binary`.
- `CertificateIssuer` asks `GpgAgentSession` via the signer-closure
  pattern; doesn't touch gpg-agent directly.
- The publication-writing handler is **not** an actor — it reads three
  files and writes one. Stateless dispatch glue.

For Kameo-specific discipline (Self IS the actor, per-kind `Message<T>`,
DelegatedReply for blocking IO, no-public-ZST), read
`~/primary/skills/kameo.md`. For architectural rules (actors all the
way down, no shared locks, supervision), read
`~/primary/skills/actor-systems.md`.

## Idempotency

Each request handler is idempotent on disk-existence, with parse-
before-skip for cryptographic outputs:

- `CertificateAuthorityIssuance`: skip if output parses as a PEM cert;
  **fail loudly** if it exists but doesn't parse.
- `ServerCertificateIssuance`: skip if both output files parse;
  **fail loudly** on any unparseable file or half-existence (a fresh
  issuance mints a new EC keypair and would silently rotate; operator
  must decide).
- `ClientCertificateIssuance`: skip if output parses as a PEM cert;
  **fail loudly** if it exists but doesn't parse.
- `YggdrasilKeypairSetup`: skip if keypair file exists.
- `PublicKeyPublicationWriting`: always re-assemble + atomically write.
  (No skip; the publication is cheap to re-derive and has no private
  bytes.)
- `CertificateChainVerification`: read-only; always runs.

The loud-fail policy means a re-deploy with stale/corrupt cryptographic
material doesn't silently rotate the host's identity. Operators get a
typed error explaining why; the fix is to `rm` the offending file (or
restore from backup) and re-run.

## Operator override (CriomOS)

CriomOS's `complex-init` systemd unit has
`unitConfig.ConditionPathExists = "!${dir}/.disabled"`. To lock
clavifaber out of a specific host:

```sh
touch /etc/criomOS/complex/.disabled
```

The unit becomes a no-op. Removing the sentinel re-enables runs.

## Force-rotate

There is no `--force` flag. To force re-issuance of a specific
artifact:

```sh
mv /etc/criomOS/complex/server.pem /etc/criomOS/complex/server.pem.retired
mv /etc/criomOS/complex/server.key /etc/criomOS/complex/server.key.retired
# next clavifaber ServerCertificateIssuance run: re-issues both
```

For the SSH host key (which clavifaber does not own): rotate it on
the sshd side (`rm /etc/ssh/ssh_host_ed25519_key*`, restart sshd).
The next `PublicKeyPublicationWriting` run picks up the new pubkey.
The client cert that bound the old pubkey is now stale — also delete
the client cert file to force re-issuance.

## Nix and tests

- `nix flake check` is the canonical gate (4 derivations: build, test,
  fmt, clippy).
- `nix run .#test-pki-lifecycle` is the impure end-to-end against real
  gpg-agent, real yggdrasil binary, and real ssh-keygen (7 phases).
- `nix run .#test-deployment-sandbox` is a rootless bwrap container
  e2e — no sudo required.
- Each load-bearing constraint in `ARCHITECTURE.md` maps to a same-named
  witness test in `tests/`. Adding a constraint without a witness is a
  smell — name the witness first.
- Tests live in `tests/<topic>.rs`, not in inline `#[cfg(test)] mod tests`
  blocks (per `~/primary/skills/rust-discipline.md`).
