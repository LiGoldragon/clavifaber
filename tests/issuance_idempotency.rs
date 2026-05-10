//! Per-handler idempotency: `CertificateAuthorityIssuance`,
//! `ServerCertificateIssuance`, and `ClientCertificateIssuance` skip the
//! gpg-agent round-trip when their output files already exist.
//!
//! Witness shape: bogus keygrip + nonexistent CA path. The skip path
//! returns Ok without touching gpg-agent or the CA. A successful run
//! that leaves the marker payload in place IS the witness that
//! short-circuiting happened — if the actor went through to gpg-agent,
//! the bogus keygrip would fail.

use clavifaber::request::{
    CertificateAuthorityIssuance, ClaviFaberRequest, ClaviFaberResponse, ClientCertificateIssuance,
    ServerCertificateIssuance,
};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn run(request: &ClaviFaberRequest) -> Output {
    Command::new(env!("CARGO_BIN_EXE_clavifaber"))
        .arg(request.to_nota().expect("encode request"))
        .output()
        .expect("run clavifaber")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn stdout_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn directory_text(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[test]
fn certificate_authority_issuance_skips_when_output_exists() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let output_path = temporary_directory.path().join("ca.pem");
    fs::write(&output_path, b"MARKER-CA-PEM").expect("seed CA file");

    let request = ClaviFaberRequest::CertificateAuthorityIssuance(CertificateAuthorityIssuance {
        keygrip: "BOGUS".to_string(),
        common_name: "irrelevant".to_string(),
        output: directory_text(&output_path),
    });

    let output = run(&request);
    assert!(
        output.status.success(),
        "skip path must succeed without gpg-agent; stderr: {}",
        stderr_text(&output)
    );

    let response = ClaviFaberResponse::from_nota(&stdout_text(&output)).expect("decode response");
    assert!(matches!(
        response,
        ClaviFaberResponse::CertificateAuthorityCertificateWritten(_)
    ));

    assert_eq!(
        fs::read(&output_path).expect("read CA file"),
        b"MARKER-CA-PEM",
        "CA file was re-issued instead of skipped"
    );
}

#[test]
fn server_certificate_issuance_skips_when_output_files_exist() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let certificate_path = temporary_directory.path().join("server.pem");
    let private_key_path = temporary_directory.path().join("server.key");
    fs::write(&certificate_path, b"MARKER-SERVER-PEM").expect("seed server cert");
    fs::write(&private_key_path, b"MARKER-SERVER-KEY").expect("seed server key");

    let request = ClaviFaberRequest::ServerCertificateIssuance(ServerCertificateIssuance {
        certificate_authority_keygrip: "BOGUS".to_string(),
        certificate_authority_certificate: directory_text(
            &temporary_directory.path().join("nonexistent-ca.pem"),
        ),
        common_name: "irrelevant".to_string(),
        output_certificate: directory_text(&certificate_path),
        output_private_key: directory_text(&private_key_path),
    });

    let output = run(&request);
    assert!(
        output.status.success(),
        "skip path must succeed without gpg-agent; stderr: {}",
        stderr_text(&output)
    );
    let response = ClaviFaberResponse::from_nota(&stdout_text(&output)).expect("decode response");
    assert!(matches!(
        response,
        ClaviFaberResponse::ServerCertificateWritten(_)
    ));

    assert_eq!(
        fs::read(&certificate_path).expect("read server cert"),
        b"MARKER-SERVER-PEM",
        "server cert was re-issued instead of skipped"
    );
    assert_eq!(
        fs::read(&private_key_path).expect("read server key"),
        b"MARKER-SERVER-KEY",
        "server private key was re-issued instead of skipped"
    );
}

#[test]
fn client_certificate_issuance_skips_when_output_exists() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let output_path = temporary_directory.path().join("client.pem");
    fs::write(&output_path, b"MARKER-CLIENT-PEM").expect("seed client cert");

    let request = ClaviFaberRequest::ClientCertificateIssuance(ClientCertificateIssuance {
        certificate_authority_keygrip: "BOGUS".to_string(),
        certificate_authority_certificate: directory_text(
            &temporary_directory.path().join("nonexistent-ca.pem"),
        ),
        open_ssh_public_key: "ssh-ed25519 IGNORED node".to_string(),
        common_name: "irrelevant".to_string(),
        output: directory_text(&output_path),
    });

    let output = run(&request);
    assert!(
        output.status.success(),
        "skip path must succeed without gpg-agent; stderr: {}",
        stderr_text(&output)
    );
    let response = ClaviFaberResponse::from_nota(&stdout_text(&output)).expect("decode response");
    assert!(matches!(
        response,
        ClaviFaberResponse::ClientCertificateWritten(_)
    ));

    assert_eq!(
        fs::read(&output_path).expect("read client cert"),
        b"MARKER-CLIENT-PEM",
        "client cert was re-issued instead of skipped"
    );
}
