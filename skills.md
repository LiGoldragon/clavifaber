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

Each request handler is idempotent on disk-existence, with parse-
before-skip for cryptographic outputs:

- `IdentitySetup`: load if `key.pem` exists and parses as Ed25519
  PKCS#8; quarantine to `key.pem.broken.<unix-seconds>` if not even
  a PEM block; **fail loudly** (don't quarantine) if the file is
  structured PEM but the wrong label or wrong algorithm. Generate
  fresh if absent.
- `OpenSshPublicKeyDerivation`: regenerate `ssh.pub` from the loaded
  identity (always fresh; cheap).
- `CertificateAuthorityIssuance`: skip if output parses as a PEM
  certificate; **fail loudly** if the output exists but doesn't
  parse.
- `ServerCertificateIssuance`: skip if both output files parse;
  **fail loudly** on any unparseable file or half-existence (a fresh
  issuance mints a new EC keypair and would silently rotate; operator
  must decide).
- `ClientCertificateIssuance`: skip if output parses as a PEM
  certificate; **fail loudly** if the output exists but doesn't
  parse.
- `YggdrasilKeypairSetup`: skip if keypair file exists.
- `PublicKeyPublicationWriting`: always re-assemble + atomically write.
  (No skip; the publication is cheap to re-derive.)
- `CertificateChainVerification`: read-only; always runs.

The loud-fail policy means a re-deploy with stale/corrupt cryptographic
material doesn't silently rotate the host's identity. Operators get a
typed error explaining why; the fix is to `rm` the offending file (or
restore from backup) and re-run.

Idempotency is the orchestrator's contract: re-running clavifaber after
a successful run is a fast no-op for everything except the publication
write.

## Operator override (CriomOS)

CriomOS's `complex-init` systemd unit has
`unitConfig.ConditionPathExists = "!${dir}/.disabled"`. To lock
clavifaber out of a specific host (e.g., the identity is managed
out-of-band, HSM-backed, or being investigated for a corruption
incident):

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

For the SSH host identity, the same shape with `key.pem` + `ssh.pub`
(both must move together; clavifaber treats half-existence as an
error per the loud-fail policy).

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
