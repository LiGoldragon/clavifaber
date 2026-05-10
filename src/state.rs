//! Clavifaber's durable per-concern state.
//!
//! Backed by sema (redb + rkyv via `~/primary/skills/rust-discipline.md`
//! §"redb + rkyv"). One sema database per host at the configured path
//! (default `/var/lib/clavifaber/clavifaber.redb`, mode 0600). The
//! convergence ledger records the last successfully converged input hash
//! per concern so the runner can answer "should I run?" with a fast
//! sema read at startup before any actor work happens.

use crate::error::{Error, Result};
use rkyv::{Archive, Deserialize, Serialize};
use sema::{Schema, SchemaVersion, Sema, Table};
use sha2::{Digest, Sha256};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const SCHEMA: Schema = Schema {
    version: SchemaVersion::new(1),
};

pub const CONVERGENCE_LEDGER: Table<&'static str, ConvergenceLedgerEntry> =
    Table::new("convergence_ledger");

pub const CONVERGE_KEY: &str = "converge";

#[derive(Debug, Clone, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct ConvergenceLedgerEntry {
    pub last_input_hash: InputHash,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Archive, Serialize, Deserialize)]
pub struct InputHash(pub [u8; 32]);

impl InputHash {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest[..]);
        Self(bytes)
    }
}

pub struct State {
    sema: Sema,
}

impl State {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path_ref = path.as_ref();
        let sema = Sema::open_with_schema(path_ref, &SCHEMA)
            .map_err(|error| Error::State(format!("open sema: {error}")))?;
        sema.write(|txn| CONVERGENCE_LEDGER.ensure(txn))
            .map_err(|error| Error::State(format!("ensure ledger table: {error}")))?;
        std::fs::set_permissions(path_ref, std::fs::Permissions::from_mode(0o600))
            .map_err(|error| Error::State(format!("chmod {}: {error}", path_ref.display())))?;
        Ok(Self { sema })
    }

    pub fn read_converge_entry(&self) -> Result<Option<ConvergenceLedgerEntry>> {
        self.sema
            .read(|txn| CONVERGENCE_LEDGER.get(txn, CONVERGE_KEY))
            .map_err(|error| Error::State(format!("read converge ledger: {error}")))
    }

    pub fn record_converge(&self, entry: &ConvergenceLedgerEntry) -> Result<()> {
        self.sema
            .write(|txn| CONVERGENCE_LEDGER.insert(txn, CONVERGE_KEY, entry))
            .map_err(|error| Error::State(format!("write converge ledger: {error}")))
    }
}
