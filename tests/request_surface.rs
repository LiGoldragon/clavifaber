use clavifaber::publication::PublicKeyPublicationRequest;
use clavifaber::request::{
    ClaviFaberRequest, ClaviFaberResponse, IdentityDirectoryInitialization, PublicKeyDerivation,
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

    fn inline_nota(&self, request: &ClaviFaberRequest) -> Output {
        clavifaber()
            .arg(request.to_nota().expect("request encodes"))
            .output()
            .expect("run inline Nota request")
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

fn directory_text(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[test]
fn nota_request_round_trip_preserves_identity_directory_derivation() {
    let request = ClaviFaberRequest::PublicKeyDerivation(PublicKeyDerivation {
        directory: "/var/lib/clavifaber".to_string(),
    });

    let encoded = request.to_nota().expect("request encodes");
    let decoded = ClaviFaberRequest::from_nota(&encoded).expect("request decodes");

    assert_eq!(decoded, request);
}

#[test]
fn inline_nota_identity_initialization_returns_typed_public_key_projection() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory();
    let request =
        ClaviFaberRequest::IdentityDirectoryInitialization(IdentityDirectoryInitialization {
            directory: directory_text(&identity_directory),
        });

    let output = fixture.inline_nota(&request);

    assert!(output.status.success(), "stderr: {}", stderr_text(&output));
    let response = ClaviFaberResponse::from_nota(&stdout_text(&output)).expect("response decodes");
    let ClaviFaberResponse::PublicKeyProjection(projection) = response else {
        panic!("expected public key projection response");
    };
    assert!(
        projection.open_ssh_public_key.starts_with("ssh-ed25519 "),
        "public projection should carry OpenSSH text"
    );
}

#[test]
fn inline_nota_publication_request_returns_cluster_ready_public_record() {
    let fixture = CliFixture::new();
    let identity_directory = fixture.identity_directory();
    let initialization =
        ClaviFaberRequest::IdentityDirectoryInitialization(IdentityDirectoryInitialization {
            directory: directory_text(&identity_directory),
        });
    let initialization_output = fixture.inline_nota(&initialization);
    assert!(
        initialization_output.status.success(),
        "stderr: {}",
        stderr_text(&initialization_output)
    );

    let publication_request =
        ClaviFaberRequest::PublicKeyPublicationRequest(PublicKeyPublicationRequest {
            node_name: "probus".to_string(),
            directory: directory_text(&identity_directory),
            yggdrasil: None,
            wifi_client_certificate_pem: None,
        });

    let output = fixture.inline_nota(&publication_request);

    assert!(output.status.success(), "stderr: {}", stderr_text(&output));
    let response = ClaviFaberResponse::from_nota(&stdout_text(&output)).expect("response decodes");
    let ClaviFaberResponse::PublicKeyPublication(publication) = response else {
        panic!("expected public key publication response");
    };
    assert_eq!(publication.node_name, "probus");
    assert!(
        publication.open_ssh_public_key.starts_with("ssh-ed25519 "),
        "publication should carry OpenSSH public key"
    );
    assert_eq!(publication.yggdrasil_address, None);
    assert_eq!(publication.yggdrasil_public_key, None);
    assert_eq!(publication.wifi_client_certificate_pem, None);
}
