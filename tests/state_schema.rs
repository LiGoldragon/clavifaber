use clavifaber::error::Error;
use clavifaber::state::State;
use redb::{Database, TableDefinition};
use tempfile::TempDir;

/// Sema's schema header is stored in a known table on first open. If a
/// caller writes a different schema version into that table, sema's open
/// path must hard-fail per `~/primary/skills/rust-discipline.md`
/// §"Schema discipline" (and per the kernel's design — schema upgrades
/// are coordinated, not silent).
#[test]
fn sema_open_with_wrong_schema_version_hard_fails() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let database_path = temporary_directory.path().join("foreign.redb");

    {
        let database = Database::create(&database_path).expect("create redb");
        let txn = database.begin_write().expect("begin write");
        {
            let header_table: TableDefinition<&str, &[u8]> = TableDefinition::new("__sema_header");
            let mut table = txn.open_table(header_table).expect("open header table");
            table
                .insert("schema_version", &b"\xFF\xFF\xFF\xFF"[..])
                .expect("insert garbage version");
        }
        txn.commit().expect("commit");
    }

    match State::open(&database_path) {
        Err(Error::State(message)) => {
            assert!(
                !message.is_empty(),
                "schema-mismatch error must carry a diagnostic message"
            );
        }
        Err(other) => {
            panic!("expected State::open to hard-fail with Error::State, got Err({other})")
        }
        Ok(_) => panic!("expected State::open to hard-fail on schema-version mismatch"),
    }
}
