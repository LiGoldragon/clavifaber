//! NOTA round-trip + inline-NOTA CLI dispatch for every request kind.

use clavifaber::request::{
    ClaviFaberRequest, ClaviFaberResponse, IdentitySetup, OpenSshPublicKeyDerivation,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

struct CliFixture {
    temporary_directory: TempDir,
}

impl CliFixture {
    fn new() -> Self {
        Self {
            temporary_directory: tempfile::tempdir().expect("create fixture directory"),
        }
    }

    fn identity_directory(&self) -> PathBuf {
        self.temporary_directory.path().join("identity")
    }

    fn run(&self, request: &ClaviFaberRequest) -> Output {
        Command::new(env!("CARGO_BIN_EXE_clavifaber"))
            .arg(request.to_nota().expect("encode request"))
            .output()
            .expect("run clavifaber")
    }
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn directory_text(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[test]
fn nota_request_round_trip_preserves_open_ssh_public_key_derivation() {
    let request = ClaviFaberRequest::OpenSshPublicKeyDerivation(OpenSshPublicKeyDerivation {
        directory: "/var/lib/clavifaber".to_string(),
    });

    let encoded = request.to_nota().expect("request encodes");
    let decoded = ClaviFaberRequest::from_nota(&encoded).expect("request decodes");

    assert_eq!(decoded, request);
}

#[test]
fn inline_nota_identity_setup_returns_typed_identity_set_response() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory();
    let request = ClaviFaberRequest::IdentitySetup(IdentitySetup {
        directory: directory_text(&identity_directory),
    });

    let output = fixture.run(&request);

    assert!(output.status.success(), "stderr: {}", stderr_text(&output));
    let response = ClaviFaberResponse::from_nota(&stdout_text(&output)).expect("response decodes");
    let ClaviFaberResponse::IdentitySet(set) = response else {
        panic!("expected IdentitySet response");
    };
    assert_eq!(set.directory, directory_text(&identity_directory));
    assert!(
        set.open_ssh_public_key.starts_with("ssh-ed25519 "),
        "open_ssh_public_key wrong format: {}",
        set.open_ssh_public_key
    );
}
