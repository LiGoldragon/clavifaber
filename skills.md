# ClaviFaber Repo Skill

Use this file with the workspace skills before editing this repository.

## Scope

ClaviFaber owns local host key-material formation and public projection records
for CriomOS. It does not own the cluster database schema, the deployment graph,
or host activation orchestration.

The cluster database writer belongs in the cluster-management/deployment layer
that owns the database revision. ClaviFaber emits `PublicKeyPublication`; it
does not patch cluster database files.

## Safety

- Never print, snapshot, or place private key material in the Nix store.
- Public outputs may be logged or printed only when the command is explicitly a
  public projection command.
- Keep private material writes atomic and permissioned.
- Treat corruption recovery as preservation plus regeneration, not deletion.

## Rust Shape

- Put behavior on data-bearing nouns.
- Do not add public free functions. Main should only parse a request and call
  request objects.
- Prefer one crate error enum with `thiserror`.
- Use full English field and variable names. Keep compatibility flag spellings
  behind Clap attributes only while the compatibility CLI exists.
- New operator behavior should enter through `ClaviFaberRequest` and return
  `ClaviFaberResponse`.

## Actor Topology

Every plane is owned by a Kameo 0.20 actor under `src/actors/`. The runtime
root lives in `actors::runtime_root::RuntimeRoot`; each request type's
`execute()` is `async` and dispatches by sending typed `Message<T>` to the
appropriate child actor through an `ActorRef`. The CLI binary uses
`#[tokio::main]`.

Current actors: `HostIdentity`, `SshHostKey`, `GpgAgentSession`,
`CertificateIssuer`, `PublicationCollector`, `WifiCertificate`,
`YggdrasilKey`, `TraceRecorder` (test-time only). Each owns its plane's
data, accepts typed per-kind `Message<T>` impls, and (for the blocking-IO
planes — `GpgAgentSession`, `YggdrasilKey`) replies via
`DelegatedReply<Result<…, Error>>` over `tokio::task::spawn_blocking` so
the mailbox stays responsive. `WifiCertificate` replies plain
`Result<(), Error>` because its `ask` to `CertificateIssuer` is itself
non-blocking from the runtime's perspective.

- Add a new actor as a new file under `src/actors/<noun>.rs` plus the matching
  module declaration in `src/actors.rs`. Co-locate the `Actor` impl, the
  `Message<T>` impls for that actor, and the message/reply types in the same
  file (per `~/primary/skills/kameo.md` §"The core shape").
- Actor types must carry data — no public ZST actor markers. The
  `tests/actor_topology.rs::actor_types_carry_data_not_zero_size` test enforces
  `mem::size_of::<MyActor>() > 0` for every named actor.
- `GpgAgentSession` is the **sole owner** of the `gpg_agent` module's
  connections. Other actors and request handlers must ask it through its
  mailbox. The `gpg_agent` module is crate-private; the
  `tests/forbidden_edges.rs::only_gpg_agent_session_owns_the_gpg_agent_connection`
  static source scan enforces this.
- New cert-side behavior in `x509.rs` takes an async signer closure; the
  closure is supplied by `CertificateIssuer` and asks `GpgAgentSession` for
  the signature. Do not reach for `GpgAgent::connect()` outside
  `gpg_agent_session.rs`.
- New traces enter through `actors::trace_recorder::emit(...)` at message
  receive and reply boundaries; production passes `None` as the tracer; tests
  pass a `TraceRecorder` ActorRef and assert on the recorded sequence.
- The Yggdrasil identity plane is owned by `YggdrasilKey`. Other actors
  must not call the `yggdrasil` binary directly — they ask `YggdrasilKey`
  via `EnsureYggdrasilIdentity` / `ReadYggdrasilProjection`. The
  `yggdrasil` binary is resolved from the process PATH (override:
  `CLAVIFABER_YGGDRASIL_BIN`); CriomOS supplies it via the systemd
  unit's `Path = [ pkgs.yggdrasil ]`.
- The wifi-PKI cert plane is owned by `WifiCertificate`. Converge's
  `ServerCertificatePlan` and `NodeCertificatePlan` route through it
  (not directly to `CertificateIssuer`) so disk-existence-idempotency
  is taken in the same place as the future renewal driver. The CA
  issuance plane (signing the cluster CA itself) is not wifi-shaped
  and stays on `CertificateIssuer` directly via the
  `converge_certificate_authority` helper in `src/request.rs`.

For the Kameo-specific discipline (Self IS the actor, per-kind `Message<T>`
impls, `DelegatedReply` for blocking IO, no-public-ZST rule, public consumer
surface), read `~/primary/skills/kameo.md`. For the architectural rule
(actors all the way down, no shared locks, supervision is part of the
design), read `~/primary/skills/actor-systems.md`.

## Nix And Tests

- `nix flake check` is the pure test entry point.
- `nix run .#test-pki-lifecycle` is the impure GPG/gpg-agent lifecycle test.
- Name tests by the premise being defended.
- Use fixture structs and helper binaries/scripts when the behavior needs a
  real process boundary.
