use clavifaber::publication::PublicKeyPublication;
use clavifaber::request::{ClaviFaberRequest, ClaviFaberResponse, Converge, ConvergenceComplete};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

struct ConvergeFixture {
    temporary_directory: TempDir,
}

impl ConvergeFixture {
    fn new() -> Self {
        Self {
            temporary_directory: tempfile::tempdir().expect("create fixture directory"),
        }
    }

    fn identity_directory(&self) -> PathBuf {
        self.temporary_directory.path().join("identity")
    }

    fn publication_output(&self) -> PathBuf {
        self.temporary_directory.path().join("publication.nota")
    }

    fn run_converge(&self, request: &ClaviFaberRequest) -> Output {
        Command::new(env!("CARGO_BIN_EXE_clavifaber"))
            .arg(request.to_nota().expect("encode request"))
            .output()
            .expect("run converge")
    }
}

fn directory_text(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn converge_creates_identity_then_writes_publication_atomically() {
    let fixture = ConvergeFixture::new();
    let request = ClaviFaberRequest::Converge(Converge {
        identity_directory: directory_text(&fixture.identity_directory()),
        node_name: "probus".to_string(),
        publication_output: directory_text(&fixture.publication_output()),
        yggdrasil_address: Some("200:0:0:0:0:0:0:1".to_string()),
        yggdrasil_public_key: Some("ed25519:abc".to_string()),
        wifi_client_certificate_pem: None,
    });

    let output = fixture.run_converge(&request);

    assert!(
        output.status.success(),
        "converge failed; stderr: {}",
        stderr_text(&output)
    );

    let response = ClaviFaberResponse::from_nota(&stdout_text(&output)).expect("decode reply");
    let ClaviFaberResponse::ConvergenceComplete(ConvergenceComplete { publication_output }) =
        response
    else {
        panic!("expected ConvergenceComplete, got: {response:?}");
    };
    assert_eq!(
        publication_output,
        directory_text(&fixture.publication_output())
    );

    let private_key = fixture.identity_directory().join("key.pem");
    let public_key = fixture.identity_directory().join("ssh.pub");
    let publication = fixture.publication_output();
    assert!(private_key.exists(), "key.pem missing");
    assert!(public_key.exists(), "ssh.pub missing");
    assert!(publication.exists(), "publication.nota missing");

    let publication_text = std::fs::read_to_string(&publication).expect("read publication.nota");
    let parsed: PublicKeyPublication = decode_publication(&publication_text);
    assert_eq!(parsed.node_name, "probus");
    assert!(
        parsed.open_ssh_public_key.starts_with("ssh-ed25519 "),
        "publication's open_ssh_public_key wrong shape: {}",
        parsed.open_ssh_public_key
    );
    assert_eq!(
        parsed.yggdrasil_address.as_deref(),
        Some("200:0:0:0:0:0:0:1")
    );
    assert_eq!(parsed.yggdrasil_public_key.as_deref(), Some("ed25519:abc"));
    assert_eq!(parsed.wifi_client_certificate_pem, None);
}

#[test]
fn converge_is_idempotent_against_existing_identity() {
    let fixture = ConvergeFixture::new();
    let request = ClaviFaberRequest::Converge(Converge {
        identity_directory: directory_text(&fixture.identity_directory()),
        node_name: "probus".to_string(),
        publication_output: directory_text(&fixture.publication_output()),
        yggdrasil_address: None,
        yggdrasil_public_key: None,
        wifi_client_certificate_pem: None,
    });

    let first = fixture.run_converge(&request);
    assert!(
        first.status.success(),
        "first converge: {}",
        stderr_text(&first)
    );
    let first_private_key = std::fs::read_to_string(fixture.identity_directory().join("key.pem"))
        .expect("read first key.pem");
    let first_publication =
        std::fs::read_to_string(fixture.publication_output()).expect("read first publication");

    let second = fixture.run_converge(&request);
    assert!(
        second.status.success(),
        "second converge: {}",
        stderr_text(&second)
    );
    let second_private_key = std::fs::read_to_string(fixture.identity_directory().join("key.pem"))
        .expect("read second key.pem");
    let second_publication =
        std::fs::read_to_string(fixture.publication_output()).expect("read second publication");

    assert_eq!(
        first_private_key, second_private_key,
        "private key should not change on second converge"
    );
    assert_eq!(
        first_publication, second_publication,
        "publication should be byte-identical on second converge"
    );
}

fn decode_publication(text: &str) -> PublicKeyPublication {
    use nota_codec::{Decoder, NotaDecode};
    let mut decoder = Decoder::new(text);
    PublicKeyPublication::decode(&mut decoder).expect("decode publication.nota")
}
