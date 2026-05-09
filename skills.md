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

## Nix And Tests

- `nix flake check` is the pure test entry point.
- `nix run .#test-pki-lifecycle` is the impure GPG/gpg-agent lifecycle test.
- Name tests by the premise being defended.
- Use fixture structs and helper binaries/scripts when the behavior needs a
  real process boundary.
