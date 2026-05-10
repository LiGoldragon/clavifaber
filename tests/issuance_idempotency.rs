//! Per-handler idempotency for `CertificateAuthorityIssuance`,
//! `ServerCertificateIssuance`, and `ClientCertificateIssuance`.
//!
//! Three flavours of behaviour, witnessed:
//!
//! 1. **Valid existing output → skip the gpg-agent round-trip.**
//!    Bogus keygrip + nonexistent CA path; the handler returns Ok
//!    because the existing-file parse succeeded.
//! 2. **Unparseable existing output → fail loudly.** Operator must
//!    delete the file to force re-issue (no silent overwrite of
//!    structurally-typed cryptographic material). Report 112's
//!    parse-before-skip recommendation.
//! 3. **Server cert + key half-existence → fail loudly.** Refusing to
//!    silently rotate the EC keypair when only one of the pair
//!    survived.

use clavifaber::request::{
    CertificateAuthorityIssuance, ClaviFaberRequest, ClaviFaberResponse, ClientCertificateIssuance,
    ServerCertificateIssuance,
};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

// A real self-signed Ed25519 PEM cert generated via openssl, baked
// as a fixture so the "valid existing file" tests don't need a
// gpg-agent. Same content for CA / server / client fixtures (parse
// doesn't care about subject DN / issuer DN for the skip path).
const FIXTURE_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
MIIBWTCCAQugAwIBAgIUCOI0aFnL7cm2RulNMn+ML3r4KyowBQYDK2VwMCIxIDAe\n\
BgNVBAMMF2NsYXZpZmFiZXItdGVzdC1maXh0dXJlMB4XDTI2MDUxMTEyMTgxNFoX\n\
DTM2MDUwODEyMTgxNFowIjEgMB4GA1UEAwwXY2xhdmlmYWJlci10ZXN0LWZpeHR1\n\
cmUwKjAFBgMrZXADIQDFCzZebqFBUpVQVms3NLXQV96/IDcvrNORO3vzCn/tfaNT\n\
MFEwHQYDVR0OBBYEFDLHKssJDTiwI9rooR3vYnDocvXMMB8GA1UdIwQYMBaAFDLH\n\
KssJDTiwI9rooR3vYnDocvXMMA8GA1UdEwEB/wQFMAMBAf8wBQYDK2VwA0EA+qJV\n\
I/n7FrqPeUhhAx6Ab2wps34zFV3SpWaXFvAySyIDdusaksLReMuQt+/LwbGyF1TD\n\
+wMk5f2ZnYUfIRB2CQ==\n\
-----END CERTIFICATE-----\n";

const FIXTURE_PRIVATE_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEIApF2z/vIhwA+qC4OUeQn8yLfolX/Y2fDS+4PCW+4R7i\n\
-----END PRIVATE KEY-----\n";

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

// ─── Valid existing files → skip ─────────────────────────────────

#[test]
fn certificate_authority_issuance_skips_when_output_is_valid_cert() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let output_path = temporary_directory.path().join("ca.pem");
    fs::write(&output_path, FIXTURE_CERT_PEM).expect("seed CA file");

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
        fs::read_to_string(&output_path).expect("read CA file"),
        FIXTURE_CERT_PEM,
        "CA file was re-issued instead of skipped"
    );
}

#[test]
fn server_certificate_issuance_skips_when_output_files_are_valid() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let certificate_path = temporary_directory.path().join("server.pem");
    let private_key_path = temporary_directory.path().join("server.key");
    fs::write(&certificate_path, FIXTURE_CERT_PEM).expect("seed server cert");
    fs::write(&private_key_path, FIXTURE_PRIVATE_KEY_PEM).expect("seed server key");

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
        fs::read_to_string(&certificate_path).expect("read server cert"),
        FIXTURE_CERT_PEM,
        "server cert was re-issued instead of skipped"
    );
    assert_eq!(
        fs::read_to_string(&private_key_path).expect("read server key"),
        FIXTURE_PRIVATE_KEY_PEM,
        "server private key was re-issued instead of skipped"
    );
}

#[test]
fn client_certificate_issuance_skips_when_output_is_valid_cert() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let output_path = temporary_directory.path().join("client.pem");
    fs::write(&output_path, FIXTURE_CERT_PEM).expect("seed client cert");

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
        fs::read_to_string(&output_path).expect("read client cert"),
        FIXTURE_CERT_PEM,
        "client cert was re-issued instead of skipped"
    );
}

// ─── Unparseable existing files → fail loudly ─────────────────────

#[test]
fn certificate_authority_issuance_fails_loudly_when_output_unparseable() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let output_path = temporary_directory.path().join("ca.pem");
    fs::write(&output_path, b"GARBAGE-NOT-A-PEM-CERT").expect("seed garbage");

    let request = ClaviFaberRequest::CertificateAuthorityIssuance(CertificateAuthorityIssuance {
        keygrip: "BOGUS".to_string(),
        common_name: "irrelevant".to_string(),
        output: directory_text(&output_path),
    });

    let output = run(&request);
    assert!(
        !output.status.success(),
        "unparseable existing CA cert must fail loudly, not silently overwrite"
    );
    let stderr = stderr_text(&output);
    assert!(
        stderr.contains("not a parseable certificate")
            && stderr.contains("refusing to silently overwrite"),
        "error message must explain why; got: {stderr}"
    );

    assert_eq!(
        fs::read(&output_path).expect("read CA file"),
        b"GARBAGE-NOT-A-PEM-CERT",
        "CA file was overwritten despite the loud-fail policy"
    );
}

#[test]
fn client_certificate_issuance_fails_loudly_when_output_unparseable() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let output_path = temporary_directory.path().join("client.pem");
    fs::write(&output_path, b"GARBAGE-NOT-A-PEM-CERT").expect("seed garbage");

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
        !output.status.success(),
        "unparseable existing client cert must fail loudly"
    );
    assert!(
        stderr_text(&output).contains("refusing to silently overwrite"),
        "error message must explain refusal; got: {}",
        stderr_text(&output)
    );

    assert_eq!(
        fs::read(&output_path).expect("read client cert"),
        b"GARBAGE-NOT-A-PEM-CERT",
        "client cert was overwritten despite the loud-fail policy"
    );
}

#[test]
fn server_certificate_issuance_fails_loudly_when_cert_unparseable() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let certificate_path = temporary_directory.path().join("server.pem");
    let private_key_path = temporary_directory.path().join("server.key");
    fs::write(&certificate_path, b"GARBAGE-NOT-A-PEM-CERT").expect("seed garbage cert");
    fs::write(&private_key_path, FIXTURE_PRIVATE_KEY_PEM).expect("seed valid key");

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
        !output.status.success(),
        "unparseable existing server cert must fail loudly (would lose the EC keypair)"
    );
    assert!(
        stderr_text(&output).contains("refusing to silently overwrite"),
        "error message must explain refusal; got: {}",
        stderr_text(&output)
    );
}

#[test]
fn server_certificate_issuance_fails_loudly_when_key_unparseable() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let certificate_path = temporary_directory.path().join("server.pem");
    let private_key_path = temporary_directory.path().join("server.key");
    fs::write(&certificate_path, FIXTURE_CERT_PEM).expect("seed valid cert");
    fs::write(&private_key_path, b"GARBAGE-NOT-A-PRIVATE-KEY").expect("seed garbage key");

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
        !output.status.success(),
        "unparseable existing server private key must fail loudly (would lose the EC keypair)"
    );
    assert!(
        stderr_text(&output).contains("refusing to silently overwrite"),
        "error message must explain refusal; got: {}",
        stderr_text(&output)
    );
}

// ─── Server cert half-existence → fail loudly ─────────────────────

#[test]
fn server_certificate_issuance_fails_loudly_on_half_existence_cert_present() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let certificate_path = temporary_directory.path().join("server.pem");
    let private_key_path = temporary_directory.path().join("server.key");
    fs::write(&certificate_path, FIXTURE_CERT_PEM).expect("seed cert only");
    // private_key_path intentionally not created.

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
        !output.status.success(),
        "half-existence (cert present, key absent) must fail loudly"
    );
    let stderr = stderr_text(&output);
    assert!(
        stderr.contains("half-exist") && stderr.contains("refusing to re-issue"),
        "error message must explain half-existence; got: {stderr}"
    );

    assert_eq!(
        fs::read_to_string(&certificate_path).expect("read cert"),
        FIXTURE_CERT_PEM,
        "surviving cert file was overwritten despite refusal"
    );
}

#[test]
fn server_certificate_issuance_fails_loudly_on_half_existence_key_present() {
    let temporary_directory = TempDir::new().expect("tempdir");
    let certificate_path = temporary_directory.path().join("server.pem");
    let private_key_path = temporary_directory.path().join("server.key");
    fs::write(&private_key_path, FIXTURE_PRIVATE_KEY_PEM).expect("seed key only");
    // certificate_path intentionally not created.

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
        !output.status.success(),
        "half-existence (cert absent, key present) must fail loudly"
    );
    let stderr = stderr_text(&output);
    assert!(
        stderr.contains("half-exist") && stderr.contains("refusing to re-issue"),
        "error message must explain half-existence; got: {stderr}"
    );

    assert_eq!(
        fs::read_to_string(&private_key_path).expect("read key"),
        FIXTURE_PRIVATE_KEY_PEM,
        "surviving key file was overwritten despite refusal"
    );
}
