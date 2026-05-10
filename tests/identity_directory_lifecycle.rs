//! End-to-end identity-directory lifecycle through the NOTA-only CLI:
//! IdentitySetup creates private + public files; OpenSshPublicKeyDerivation
//! re-derives ssh.pub; corrupt private keys are quarantined; mode bits stay
//! stable.

use clavifaber::request::{
    ClaviFaberRequest, ClaviFaberResponse, IdentitySetup, OpenSshPublicKeyDerivation,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
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

    fn identity_directory(&self, name: &str) -> PathBuf {
        self.temporary_directory.path().join(name)
    }

    fn identity_setup(&self, identity_directory: &Path) -> Output {
        let request = ClaviFaberRequest::IdentitySetup(IdentitySetup {
            directory: directory_text(identity_directory),
        });
        run_request(&request)
    }

    fn open_ssh_public_key_derivation(&self, identity_directory: &Path) -> Output {
        let request = ClaviFaberRequest::OpenSshPublicKeyDerivation(OpenSshPublicKeyDerivation {
            directory: directory_text(identity_directory),
        });
        run_request(&request)
    }
}

fn directory_text(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn run_request(request: &ClaviFaberRequest) -> Output {
    Command::new(env!("CARGO_BIN_EXE_clavifaber"))
        .arg(request.to_nota().expect("encode request"))
        .output()
        .expect("run clavifaber")
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn parse_response(output: &Output) -> ClaviFaberResponse {
    ClaviFaberResponse::from_nota(&stdout_text(output)).expect("decode response")
}

fn open_ssh_public_key_from_response(response: ClaviFaberResponse) -> String {
    match response {
        ClaviFaberResponse::IdentitySet(set) => set.open_ssh_public_key,
        ClaviFaberResponse::OpenSshPublicKeyDerived(derived) => derived.open_ssh_public_key,
        other => panic!("expected IdentitySet or OpenSshPublicKeyDerived, got {other:?}"),
    }
}

#[test]
fn identity_setup_creates_private_key_and_public_key_with_stable_modes() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let output = fixture.identity_setup(&identity_directory);

    assert!(output.status.success(), "stderr: {}", stderr_text(&output));

    let private_key_path = identity_directory.join("key.pem");
    let public_key_path = identity_directory.join("ssh.pub");
    assert!(private_key_path.exists(), "key.pem missing");
    assert!(public_key_path.exists(), "ssh.pub missing");

    let private_key_mode = fs::metadata(&private_key_path)
        .expect("private key metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        private_key_mode, 0o600,
        "key.pem should be 0600, got {private_key_mode:o}"
    );

    let public_key_mode = fs::metadata(&public_key_path)
        .expect("public key metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        public_key_mode, 0o644,
        "ssh.pub should be 0644, got {public_key_mode:o}"
    );

    let private_key_pem = fs::read_to_string(&private_key_path).expect("read private key");
    assert!(
        private_key_pem.contains("BEGIN PRIVATE KEY"),
        "key.pem not valid PEM"
    );

    let on_disk_public_key = fs::read_to_string(&public_key_path).expect("read public key");
    assert!(
        on_disk_public_key.starts_with("ssh-ed25519 "),
        "ssh.pub wrong format: {on_disk_public_key}"
    );

    let response_public_key = open_ssh_public_key_from_response(parse_response(&output));
    assert_eq!(
        response_public_key, on_disk_public_key,
        "response open_ssh_public_key should match the file's content"
    );
}

#[test]
fn identity_setup_preserves_existing_identity() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let first = fixture.identity_setup(&identity_directory);
    assert!(first.status.success(), "stderr: {}", stderr_text(&first));
    let first_private_key =
        fs::read_to_string(identity_directory.join("key.pem")).expect("read first private key");
    let first_public_key = open_ssh_public_key_from_response(parse_response(&first));

    let second = fixture.identity_setup(&identity_directory);
    assert!(second.status.success(), "stderr: {}", stderr_text(&second));
    let second_private_key =
        fs::read_to_string(identity_directory.join("key.pem")).expect("read second private key");
    let second_public_key = open_ssh_public_key_from_response(parse_response(&second));

    assert_eq!(first_private_key, second_private_key, "key.pem changed");
    assert_eq!(first_public_key, second_public_key, "public key changed");
}

#[test]
fn identity_setup_quarantines_corrupt_private_key_before_replacement() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let first = fixture.identity_setup(&identity_directory);
    assert!(first.status.success(), "stderr: {}", stderr_text(&first));
    let original_public_key = open_ssh_public_key_from_response(parse_response(&first));

    fs::write(identity_directory.join("key.pem"), b"CORRUPT DATA").expect("corrupt private key");

    let second = fixture.identity_setup(&identity_directory);
    assert!(second.status.success(), "stderr: {}", stderr_text(&second));
    let new_public_key = open_ssh_public_key_from_response(parse_response(&second));
    assert_ne!(original_public_key, new_public_key, "key was not replaced");

    let broken_private_key_count = fs::read_dir(&identity_directory)
        .expect("read identity directory")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("key.pem.broken.")
        })
        .count();
    assert!(
        broken_private_key_count >= 1,
        "broken key should be preserved"
    );
}

#[test]
fn open_ssh_public_key_derivation_restores_public_projection_from_private_key() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let first = fixture.identity_setup(&identity_directory);
    assert!(first.status.success(), "stderr: {}", stderr_text(&first));
    let original_public_key = open_ssh_public_key_from_response(parse_response(&first));

    fs::write(
        identity_directory.join("ssh.pub"),
        "ssh-ed25519 AAAA_WRONG wrong",
    )
    .expect("tamper public key");

    let derivation = fixture.open_ssh_public_key_derivation(&identity_directory);
    assert!(
        derivation.status.success(),
        "stderr: {}",
        stderr_text(&derivation)
    );
    let derived_public_key = open_ssh_public_key_from_response(parse_response(&derivation));

    assert_eq!(
        original_public_key, derived_public_key,
        "derived public key should match original"
    );

    let public_key_file =
        fs::read_to_string(identity_directory.join("ssh.pub")).expect("read restored public key");
    assert_eq!(
        public_key_file, derived_public_key,
        "ssh.pub file should be corrected"
    );
}

#[test]
fn identity_setup_leaves_stable_modes_and_no_temporary_files() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let output = fixture.identity_setup(&identity_directory);
    assert!(output.status.success(), "stderr: {}", stderr_text(&output));

    let temporary_file_count = fs::read_dir(&identity_directory)
        .expect("read identity directory")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
        .count();
    assert_eq!(temporary_file_count, 0, "temporary files remain");

    let directory_mode = fs::metadata(&identity_directory)
        .expect("identity directory metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        directory_mode, 0o700,
        "identity directory should be 0700, got {directory_mode:o}"
    );
}

#[test]
fn open_ssh_public_key_derivation_fails_when_private_key_is_absent() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");
    fs::create_dir_all(&identity_directory).expect("create empty identity directory");

    let output = fixture.open_ssh_public_key_derivation(&identity_directory);

    assert!(
        !output.status.success(),
        "OpenSshPublicKeyDerivation should fail without private key"
    );
}

#[test]
fn identity_setup_fails_loudly_when_existing_key_is_pem_with_wrong_label() {
    // A perfectly-PEM-shaped file with the WRONG label (say, a
    // CERTIFICATE block) must NOT be quarantined-and-replaced —
    // that's the dangerous silent-rotation path report 112 named.
    // Instead clavifaber surfaces an error and refuses to overwrite.
    // Operator decides what to do.
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");
    fs::create_dir_all(&identity_directory).expect("create identity dir");
    fs::write(
        identity_directory.join("key.pem"),
        "-----BEGIN CERTIFICATE-----\nDEFINITELYNOTAPRIVATEKEY\n-----END CERTIFICATE-----\n",
    )
    .expect("seed wrong-label PEM");

    let output = fixture.identity_setup(&identity_directory);

    assert!(
        !output.status.success(),
        "structured-but-not-ours PEM must fail loudly, not silently quarantine + replace"
    );
    let stderr = stderr_text(&output);
    assert!(
        stderr.contains("PRIVATE KEY") || stderr.contains("corrupt"),
        "error message must explain the structural mismatch; got: {stderr}"
    );

    // The file is untouched — not quarantined, not overwritten.
    let on_disk = fs::read_to_string(identity_directory.join("key.pem")).expect("read key.pem");
    assert!(
        on_disk.contains("DEFINITELYNOTAPRIVATEKEY"),
        "structured-but-not-ours file was modified despite the loud-fail policy"
    );
    let broken_count = fs::read_dir(&identity_directory)
        .expect("read identity dir")
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("key.pem.broken.")
        })
        .count();
    assert_eq!(
        broken_count, 0,
        "structured-but-not-ours file must NOT be quarantined"
    );
}
