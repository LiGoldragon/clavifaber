use std::fs;
use std::path::Path;

const GPG_AGENT_OWNER: &str = "gpg_agent_session.rs";
const FORBIDDEN_PATTERNS: &[&str] = &["use crate::gpg_agent", "crate::gpg_agent::"];

pub(crate) struct ForbiddenEdgeScan {
    sources: Vec<(String, String)>,
}

impl ForbiddenEdgeScan {
    fn from_crate_root() -> Self {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        let mut sources = Vec::new();
        Self::collect_rust_sources(Path::new(manifest_dir).join("src"), &mut sources);
        Self { sources }
    }

    pub(crate) fn collect_rust_sources(
        directory: std::path::PathBuf,
        sources: &mut Vec<(String, String)>,
    ) {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                Self::collect_rust_sources(path, sources);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) != Some("rs") {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_string();
            let content = fs::read_to_string(&path).expect("read source");
            sources.push((file_name, content));
        }
    }

    fn assert_only_owner_reaches_gpg_agent(&self) {
        for (file_name, content) in &self.sources {
            if file_name == GPG_AGENT_OWNER || file_name == "gpg_agent.rs" {
                continue;
            }
            for pattern in FORBIDDEN_PATTERNS {
                assert!(
                    !content.contains(pattern),
                    "Forbidden edge: {file_name} reaches gpg_agent module directly via `{pattern}`. \
                     Only {GPG_AGENT_OWNER} may import gpg_agent; other actors and request \
                     handlers must ask GpgAgentSession through its mailbox."
                );
            }
        }
    }
}

#[test]
fn only_gpg_agent_session_owns_the_gpg_agent_connection() {
    ForbiddenEdgeScan::from_crate_root().assert_only_owner_reaches_gpg_agent();
}

const ATOMIC_FILE_OWNER: &str = "util.rs";
const ATOMIC_BYPASS_PATTERNS: &[&str] = &["fs::write", "File::create"];

#[test]
fn all_file_writes_go_through_atomic_file() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut sources: Vec<(String, String)> = Vec::new();
    ForbiddenEdgeScan::collect_rust_sources(
        std::path::Path::new(manifest_dir).join("src"),
        &mut sources,
    );
    for (file_name, content) in &sources {
        if file_name == ATOMIC_FILE_OWNER {
            continue;
        }
        for pattern in ATOMIC_BYPASS_PATTERNS {
            assert!(
                !content.contains(pattern),
                "Forbidden edge: {file_name} writes through `{pattern}` instead of \
                 AtomicFile. Atomic write-then-rename is the source-of-truth for \
                 publication.nota and identity files; partial writes must never be \
                 visible to readers."
            );
        }
    }
}

const YGGDRASIL_OWNER_DATA: &str = "yggdrasil.rs";
const YGGDRASIL_OWNER_ACTOR: &str = "yggdrasil_key.rs";
const YGGDRASIL_BYPASS_PATTERNS: &[&str] = &["\"yggdrasil\"", "yggdrasil_binary"];

#[test]
fn only_yggdrasil_key_owns_the_yggdrasil_binary() {
    // Mirror of `only_gpg_agent_session_owns_the_gpg_agent_connection`:
    // the yggdrasil binary is reached only by the data type
    // (`src/yggdrasil.rs`) and the actor that drives it
    // (`src/actors/yggdrasil_key.rs`). Other actors and request
    // handlers must ask `YggdrasilKey` through its mailbox.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let mut sources: Vec<(String, String)> = Vec::new();
    ForbiddenEdgeScan::collect_rust_sources(
        std::path::Path::new(manifest_dir).join("src"),
        &mut sources,
    );
    for (file_name, content) in &sources {
        if file_name == YGGDRASIL_OWNER_DATA || file_name == YGGDRASIL_OWNER_ACTOR {
            continue;
        }
        for pattern in YGGDRASIL_BYPASS_PATTERNS {
            assert!(
                !content.contains(pattern),
                "Forbidden edge: {file_name} reaches the yggdrasil binary directly via \
                 `{pattern}`. Only {YGGDRASIL_OWNER_DATA} (data) and {YGGDRASIL_OWNER_ACTOR} \
                 (actor) may invoke yggdrasil; other actors and request handlers must ask \
                 YggdrasilKey through its mailbox."
            );
        }
    }
}
