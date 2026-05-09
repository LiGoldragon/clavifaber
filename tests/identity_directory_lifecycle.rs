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

    fn complex_init(&self, identity_directory: &Path) -> Output {
        clavifaber()
            .args(["complex-init", "--dir"])
            .arg(identity_directory)
            .output()
            .expect("run complex-init")
    }

    fn derive_public_key(&self, identity_directory: &Path) -> Output {
        clavifaber()
            .args(["derive-pubkey", "--dir"])
            .arg(identity_directory)
            .output()
            .expect("run derive-pubkey")
    }
}

fn clavifaber() -> Command {
    Command::new(env!("CARGO_BIN_EXE_clavifaber"))
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn complex_init_creates_private_key_public_key_and_public_stdout_projection() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let output = fixture.complex_init(&identity_directory);

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
    assert!(
        private_key_pem.contains("END PRIVATE KEY"),
        "key.pem not valid PEM"
    );

    let public_key = fs::read_to_string(&public_key_path).expect("read public key");
    assert!(
        public_key.starts_with("ssh-ed25519 "),
        "ssh.pub wrong format: {public_key}"
    );
    assert!(
        public_key.ends_with(" complex"),
        "ssh.pub missing complex comment"
    );

    let stdout = stdout_text(&output);
    assert!(
        stdout.starts_with("ssh-ed25519 "),
        "stdout should be pubkey"
    );
    assert_eq!(stdout, public_key, "stdout should match ssh.pub");
}

#[test]
fn complex_init_preserves_existing_identity() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let first_output = fixture.complex_init(&identity_directory);
    assert!(
        first_output.status.success(),
        "stderr: {}",
        stderr_text(&first_output)
    );
    let first_private_key =
        fs::read_to_string(identity_directory.join("key.pem")).expect("read first private key");
    let first_public_key = stdout_text(&first_output);

    let second_output = fixture.complex_init(&identity_directory);
    assert!(
        second_output.status.success(),
        "stderr: {}",
        stderr_text(&second_output)
    );
    let second_private_key =
        fs::read_to_string(identity_directory.join("key.pem")).expect("read second private key");
    let second_public_key = stdout_text(&second_output);

    assert_eq!(first_private_key, second_private_key, "key.pem changed");
    assert_eq!(first_public_key, second_public_key, "public key changed");
}

#[test]
fn complex_init_quarantines_corrupt_private_key_before_replacement() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let first_output = fixture.complex_init(&identity_directory);
    assert!(
        first_output.status.success(),
        "stderr: {}",
        stderr_text(&first_output)
    );
    let original_public_key = stdout_text(&first_output);

    fs::write(identity_directory.join("key.pem"), b"CORRUPT DATA").expect("corrupt private key");

    let second_output = fixture.complex_init(&identity_directory);
    assert!(
        second_output.status.success(),
        "stderr: {}",
        stderr_text(&second_output)
    );
    assert!(
        stderr_text(&second_output).contains("corrupt"),
        "corruption warning missing"
    );

    let new_public_key = stdout_text(&second_output);
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
fn derive_pubkey_restores_public_projection_from_private_key() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let first_output = fixture.complex_init(&identity_directory);
    assert!(
        first_output.status.success(),
        "stderr: {}",
        stderr_text(&first_output)
    );
    let original_public_key = stdout_text(&first_output);

    fs::write(
        identity_directory.join("ssh.pub"),
        "ssh-ed25519 AAAA_WRONG wrong",
    )
    .expect("tamper public key");

    let derivation_output = fixture.derive_public_key(&identity_directory);
    assert!(
        derivation_output.status.success(),
        "stderr: {}",
        stderr_text(&derivation_output)
    );
    let derived_public_key = stdout_text(&derivation_output);

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
fn complex_init_leaves_stable_modes_and_no_temporary_files() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");

    let output = fixture.complex_init(&identity_directory);
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
fn derive_pubkey_fails_when_private_key_is_absent() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory("identity");
    fs::create_dir_all(&identity_directory).expect("create empty identity directory");

    let output = fixture.derive_public_key(&identity_directory);

    assert!(!output.status.success(), "derive-pubkey should fail");
}
