# clavifaber Intent

`clavifaber` is the CriomOS host key-material provisioning tool. It is a
thin, explicit operator surface for issuing and verifying X.509 material,
reading GPG-backed Ed25519 public keys, preparing per-host Yggdrasil key
projection, and writing public host-key publication records.

Its external interface is one positional NOTA request record and one
positional NOTA response record. The CLI accepts one argument assembled
from the command line, decodes it through `nota-next`, runs the requested
operation, and prints the encoded response. It is not a daemon, has no
SEMA store, and owns no durable state beyond the files it is explicitly
asked to create.

Private key material must not be printed, snapshotted, or copied into the
Nix store. File writes go through `AtomicFile`; private outputs use mode
0600, and public publication records use mode 0644.

Behavior belongs on typed request and domain nouns. The request surface is
the operator-visible capability catalog: adding behavior means adding a
typed request payload, response payload, and execution method rather than
adding flags or loose helper logic.
