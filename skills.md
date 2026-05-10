# ClaviFaber Repo Skill

Use this file with the workspace skills before editing this repository.

## Scope

ClaviFaber owns local host key-material formation and public projection
records for CriomOS. Its concern is the per-host setup of cryptographic
identities (SSH ed25519, X.509 against a GPG-Ed25519 cluster CA, Yggdrasil
keypair) and the typed `publication.nota` file that other hosts read.

It does not own:

- **Convergence orchestration.** Deciding "should I run?" or "is the
  system in the desired state?" belongs to an orchestrator component
  (lojix today; future cluster orchestrator). Don't add a Converge
  request, an input-hash gate, or a sema/redb state file to clavifaber.
- The cluster database schema or deployment graph.
- Cluster-side aggregation of publication files (the haywire-stage
  consumer is "an SSH user pulls per-host publication.nota").
- Rotation / renewal scheduling (parked; rotation will land on the
  actors that already own each plane).

## Operator surface — NOTA only

The CLI takes exactly one positional NOTA record. There is no Clap
subcommand surface; there is no `Converge` mega-request. Each request
type does one focused job and is idempotent.

```sh
clavifaber '(IdentitySetup "/var/lib/clavifaber/identity")'
clavifaber '(YggdrasilKeypairSetup "/var/lib/clavifaber/yggdrasil/keypair.json")'
clavifaber '(PublicKeyPublicationWriting probus "/var/lib/clavifaber/identity" \
  (YggdrasilKeypairLocation "/var/lib/clavifaber/yggdrasil/keypair.json") \
  None \
  "/var/lib/clavifaber/publication.nota")'
```

Adding new operator behavior means adding a new variant to
`ClaviFaberRequest` (and a paired variant to `ClaviFaberResponse`). Each
variant is its own `NotaRecord`-deriving struct in `src/request.rs` with
its own `execute()` method. The match in `ClaviFaberRequest::execute`
dispatches by variant.

## Safety

- Never print, snapshot, or place private key material in the Nix store,
  on stdout, on stderr, or in any response NOTA record.
- Public outputs may be returned in responses or written to mode-0644
  files (publication.nota, ca.pem, server.pem, client cert files).
- Private outputs (`key.pem`, `server.key`, `yggdrasil/keypair.json`) are
  written atomically with mode 0600 via `AtomicFile`.
- Treat corruption recovery as preservation plus regeneration, not
  deletion (see `IdentityDirectory::quarantine_corrupt_private_key`).

## Rust shape

- Behavior lives on data-bearing nouns. No public free functions doing
  domain work. `main.rs` is the only place a free function (`run`) lives.
- One `Error` enum per crate via `thiserror`.
- Full English field and variable names.
- New operator behavior enters through `ClaviFaberRequest` and returns
  `ClaviFaberResponse`.
- `serde_json` is the workspace-edge codec for parsing external-tool
  output (e.g. `yggdrasil -genconf -json`). Don't write hand-rolled
  JSON parsers — use `serde_json::Value` and `.get()` / `.as_str()`.

## Actor topology

Five Kameo 0.20 actors live under `src/actors/`. The runtime root is
`actors::runtime_root::RuntimeRoot`; each request type's `execute()` is
`async` and dispatches through typed `Message<T>` impls on the actors.

Current actors: `HostIdentity`, `GpgAgentSession`, `CertificateIssuer`,
`YggdrasilKey`, `TraceRecorder` (test-time only). Each owns its plane's
data, accepts typed per-kind `Message<T>` impls, and (for the blocking-IO
planes — `GpgAgentSession`, `YggdrasilKey`) replies via
`DelegatedReply<Result<…, Error>>` over `tokio::task::spawn_blocking` so
the mailbox stays responsive. `CertificateIssuer`'s replies are plain
`Result<…, Error>` because its blocking work is delegated through
`GpgAgentSession`'s `DelegatedReply` chain.

- Add a new actor as a new file under `src/actors/<noun>.rs` plus the
  matching module declaration in `src/actors.rs`. Co-locate the `Actor`
  impl, the `Message<T>` impls for that actor, and the message/reply
  types in the same file.
- Actor types must carry data — no public ZST actor markers. The
  `tests/actor_topology.rs::actor_types_carry_data_not_zero_size` test
  enforces `mem::size_of::<MyActor>() > 0` for every named actor.
- `GpgAgentSession` is the **sole owner** of the `gpg_agent` module's
  connections. Other actors and request handlers must ask it through
  its mailbox. The `gpg_agent` module is crate-private; the
  `tests/forbidden_edges.rs::only_gpg_agent_session_owns_the_gpg_agent_connection`
  static source scan enforces this.
- `YggdrasilKey` is the **sole owner** of the `yggdrasil` binary
  invocation. Other code must ask it through its mailbox. Same shape;
  enforced by `only_yggdrasil_key_owns_the_yggdrasil_binary`.
- `HostIdentity` owns three messages: `EnsureIdentity`, `LoadIdentity`,
  `WritePublicKeyProjection`. Don't split the projection into a
  separate actor — it lives on the noun that owns the private key.

For the Kameo-specific discipline (Self IS the actor, per-kind
`Message<T>` impls, `DelegatedReply` for blocking IO, no-public-ZST
rule, public consumer surface), read `~/primary/skills/kameo.md`. For
the architectural rule (actors all the way down, no shared locks,
supervision is part of the design), read
`~/primary/skills/actor-systems.md`.

## Idempotency

Each request handler is idempotent on disk-existence:

- `IdentitySetup`: load if `key.pem` exists; else generate. Quarantine
  if corrupt.
- `OpenSshPublicKeyDerivation`: regenerate `ssh.pub` from the loaded
  identity (always fresh; cheap).
- `CertificateAuthorityIssuance`: skip if output file exists.
- `ServerCertificateIssuance`: skip if both output files exist.
- `ClientCertificateIssuance`: skip if output file exists.
- `YggdrasilKeypairSetup`: skip if keypair file exists.
- `PublicKeyPublicationWriting`: always re-assemble + atomically write.
  (No skip; the publication is cheap to re-derive.)
- `CertificateChainVerification`: read-only; always runs.

Idempotency is the orchestrator's contract: re-running clavifaber after
a successful run is a fast no-op for everything except the publication
write.

## Nix and tests

- `nix flake check` is the canonical gate (4 derivations: build, test,
  fmt, clippy).
- `nix run .#test-pki-lifecycle` is the impure end-to-end against real
  gpg-agent and real yggdrasil binary (8 phases).
- Each load-bearing constraint in `ARCHITECTURE.md` maps to a same-named
  witness test in `tests/`. Adding a constraint without a witness is a
  smell — name the witness first.
- Tests live in `tests/<topic>.rs`, not in inline `#[cfg(test)] mod tests`
  blocks (per `~/primary/skills/rust-discipline.md`).
