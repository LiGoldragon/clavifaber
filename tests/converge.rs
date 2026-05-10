use clavifaber::publication::PublicKeyPublication;
use clavifaber::request::{
    CertificateAuthorityPlan, ClaviFaberRequest, ClaviFaberResponse, Converge, ConvergenceComplete,
    NodeCertificatePlan, ServerCertificatePlan,
};
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

    fn state_database(&self) -> PathBuf {
        self.temporary_directory.path().join("clavifaber.redb")
    }

    fn converge_request(&self) -> Converge {
        Converge {
            identity_directory: directory_text(&self.identity_directory()),
            node_name: "probus".to_string(),
            publication_output: directory_text(&self.publication_output()),
            yggdrasil_address: Some("200:0:0:0:0:0:0:1".to_string()),
            yggdrasil_public_key: Some("ed25519:abc".to_string()),
            wifi_client_certificate_pem: None,
            state_database: directory_text(&self.state_database()),
            certificate_authority: None,
            server_certificate: None,
            node_certificates: Vec::new(),
        }
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

fn convergence_reply(output: &Output) -> ConvergenceComplete {
    let response = ClaviFaberResponse::from_nota(&stdout_text(output)).expect("decode reply");
    let ClaviFaberResponse::ConvergenceComplete(complete) = response else {
        panic!("expected ConvergenceComplete, got: {response:?}");
    };
    complete
}

#[test]
fn converge_creates_identity_then_writes_publication_atomically() {
    let fixture = ConvergeFixture::new();
    let request = ClaviFaberRequest::Converge(fixture.converge_request());

    let output = fixture.run_converge(&request);
    assert!(
        output.status.success(),
        "converge failed; stderr: {}",
        stderr_text(&output)
    );
    let complete = convergence_reply(&output);
    assert!(
        complete.work_performed,
        "first converge must report work_performed = true"
    );
    assert_eq!(
        complete.publication_output,
        directory_text(&fixture.publication_output())
    );

    let private_key = fixture.identity_directory().join("key.pem");
    let public_key = fixture.identity_directory().join("ssh.pub");
    let publication = fixture.publication_output();
    let state_database = fixture.state_database();
    assert!(private_key.exists(), "key.pem missing");
    assert!(public_key.exists(), "ssh.pub missing");
    assert!(publication.exists(), "publication.nota missing");
    assert!(state_database.exists(), "clavifaber.redb missing");

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
    let request = ClaviFaberRequest::Converge(fixture.converge_request());

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

#[test]
fn converge_skips_when_input_hash_matches_last_converged() {
    let fixture = ConvergeFixture::new();
    let request = ClaviFaberRequest::Converge(fixture.converge_request());

    let first = fixture.run_converge(&request);
    assert!(
        first.status.success(),
        "first converge: {}",
        stderr_text(&first)
    );
    let first_complete = convergence_reply(&first);
    assert!(
        first_complete.work_performed,
        "first converge must record work_performed = true"
    );

    // Externally delete publication.nota; the gate must trust sema and skip.
    std::fs::remove_file(fixture.publication_output()).expect("remove publication.nota");

    let second = fixture.run_converge(&request);
    assert!(
        second.status.success(),
        "second converge: {}",
        stderr_text(&second)
    );
    let second_complete = convergence_reply(&second);
    assert!(
        !second_complete.work_performed,
        "second converge must report work_performed = false because input hash matches last converged"
    );
    assert!(
        !fixture.publication_output().exists(),
        "publication.nota must NOT have been re-created — the convergence gate is supposed to skip when sema reports no work to do"
    );
}

#[test]
fn converge_re_runs_when_input_changes() {
    let fixture = ConvergeFixture::new();
    let mut original = fixture.converge_request();
    let first = fixture.run_converge(&ClaviFaberRequest::Converge(original.clone()));
    assert!(
        first.status.success(),
        "first converge: {}",
        stderr_text(&first)
    );
    let first_complete = convergence_reply(&first);
    assert!(first_complete.work_performed);

    original.node_name = "rigil".to_string();
    let second = fixture.run_converge(&ClaviFaberRequest::Converge(original));
    assert!(
        second.status.success(),
        "second converge: {}",
        stderr_text(&second)
    );
    let second_complete = convergence_reply(&second);
    assert!(
        second_complete.work_performed,
        "changed input must trigger re-run"
    );

    let publication_text = std::fs::read_to_string(fixture.publication_output())
        .expect("read publication after re-run");
    let parsed = decode_publication(&publication_text);
    assert_eq!(parsed.node_name, "rigil");
}

fn decode_publication(text: &str) -> PublicKeyPublication {
    use nota_codec::{Decoder, NotaDecode};
    let mut decoder = Decoder::new(text);
    PublicKeyPublication::decode(&mut decoder).expect("decode publication.nota")
}

#[test]
fn converge_round_trips_with_full_certificate_plan() {
    let request = ClaviFaberRequest::Converge(Converge {
        identity_directory: "/var/lib/clavifaber/identity".to_string(),
        node_name: "probus".to_string(),
        publication_output: "/var/lib/clavifaber/publication.nota".to_string(),
        yggdrasil_address: None,
        yggdrasil_public_key: None,
        wifi_client_certificate_pem: None,
        state_database: "/var/lib/clavifaber/clavifaber.redb".to_string(),
        certificate_authority: Some(CertificateAuthorityPlan {
            keygrip: "ABCDEF0123456789".to_string(),
            common_name: "Aedifico CA".to_string(),
            output: "/var/lib/clavifaber/ca.pem".to_string(),
        }),
        server_certificate: Some(ServerCertificatePlan {
            keygrip: "ABCDEF0123456789".to_string(),
            certificate_authority: "/var/lib/clavifaber/ca.pem".to_string(),
            common_name: "faber.aedifico.criome".to_string(),
            output_certificate: "/var/lib/clavifaber/server.pem".to_string(),
            output_private_key: "/var/lib/clavifaber/server.key".to_string(),
        }),
        node_certificates: vec![NodeCertificatePlan {
            keygrip: "ABCDEF0123456789".to_string(),
            certificate_authority: "/var/lib/clavifaber/ca.pem".to_string(),
            open_ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA probus".to_string(),
            common_name: "probus@aedifico".to_string(),
            output: "/var/lib/clavifaber/probus.pem".to_string(),
        }],
    });

    let encoded = request.to_nota().expect("encode converge with cert plan");
    let decoded = ClaviFaberRequest::from_nota(&encoded).expect("decode converge with cert plan");
    assert_eq!(decoded, request, "round-trip lost fields: {encoded}");
}
