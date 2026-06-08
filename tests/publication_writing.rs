//! Witness that `PublicKeyPublicationWriting` reads sshd's host key
//! from disk (clavifaber does NOT create or own the SSH host key
//! anymore — that's sshd's concern) and assembles the publication
//! with typed `YggdrasilProjection` and `WifiClientCertificate`
//! wrappers.

use clavifaber::publication::PublicKeyPublication;
use clavifaber::request::{
    ClaviFaberRequest, OpenSshPublicKeyLocation, PublicKeyPublicationWriting,
    WifiClientCertificateLocation, YggdrasilKeypairLocation, YggdrasilKeypairSetup,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

struct Fixture {
    temporary_directory: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            temporary_directory: TempDir::new().expect("tempdir"),
        }
    }

    fn ssh_host_key(&self) -> PathBuf {
        self.temporary_directory.path().join("ssh_host_ed25519_key")
    }

    fn ssh_host_key_pub(&self) -> PathBuf {
        self.temporary_directory
            .path()
            .join("ssh_host_ed25519_key.pub")
    }

    fn yggdrasil_keypair(&self) -> PathBuf {
        self.temporary_directory
            .path()
            .join("yggdrasil/keypair.json")
    }

    fn wifi_client_cert(&self) -> PathBuf {
        self.temporary_directory.path().join("wifi-client.pem")
    }

    fn publication(&self) -> PathBuf {
        self.temporary_directory.path().join("publication.nota")
    }

    /// Fabricate an SSH host key the way sshd would have, before
    /// clavifaber runs. ssh-keygen writes both the private key and
    /// the `.pub` file; clavifaber will read only the `.pub` file.
    fn generate_ssh_host_key(&self) {
        let status = Command::new("ssh-keygen")
            .args([
                "-t",
                "ed25519",
                "-f",
                self.ssh_host_key().to_str().unwrap(),
                "-N",
                "",
                "-C",
                "test-host",
                "-q",
            ])
            .status()
            .expect("run ssh-keygen");
        assert!(status.success(), "ssh-keygen failed");
    }
}

fn run(request: &ClaviFaberRequest) -> Output {
    Command::new(env!("CARGO_BIN_EXE_clavifaber"))
        .arg(request.to_nota().expect("encode request"))
        .output()
        .expect("run clavifaber")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn directory_text(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn decode_publication(text: &str) -> PublicKeyPublication {
    nota_next::NotaSource::new(text)
        .parse()
        .expect("decode publication.nota")
}

#[test]
fn public_key_publication_writing_assembles_typed_record_atomically() {
    let fixture = Fixture::new();
    fixture.generate_ssh_host_key();

    // Seed the yggdrasil keypair.
    let yggdrasil = run(&ClaviFaberRequest::YggdrasilKeypairSetup(
        YggdrasilKeypairSetup {
            keypair_path: directory_text(&fixture.yggdrasil_keypair()),
        },
    ));
    assert!(
        yggdrasil.status.success(),
        "stderr: {}",
        stderr_text(&yggdrasil)
    );

    // Seed a fake wifi client cert PEM with newlines; nota-next emits
    // bracket-safe strings instead of quote-delimited strings.
    fs::write(
        fixture.wifi_client_cert(),
        b"-----BEGIN CERTIFICATE-----\nMARKER\n-----END CERTIFICATE-----\n",
    )
    .expect("seed wifi client cert");

    // Write the publication, pointing at the host key sshd would
    // have created.
    let writing = run(&ClaviFaberRequest::PublicKeyPublicationWriting(
        PublicKeyPublicationWriting {
            node_name: "probus".to_string(),
            open_ssh_public_key: OpenSshPublicKeyLocation {
                path: directory_text(&fixture.ssh_host_key_pub()),
            },
            yggdrasil_keypair: Some(YggdrasilKeypairLocation {
                keypair_path: directory_text(&fixture.yggdrasil_keypair()),
            }),
            wifi_client_certificate: Some(WifiClientCertificateLocation {
                certificate_path: directory_text(&fixture.wifi_client_cert()),
            }),
            publication_output: directory_text(&fixture.publication()),
        },
    ));
    assert!(
        writing.status.success(),
        "stderr: {}",
        stderr_text(&writing)
    );

    // Mode 0644 (publicly readable per the haywire-stage cluster contract).
    let mode = fs::metadata(fixture.publication())
        .expect("publication metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o644,
        "publication.nota must be mode 0644 (publicly readable for the haywire-stage SSH-collector pattern), got {mode:o}"
    );

    // Decode and assert typed fields.
    let publication_text =
        fs::read_to_string(fixture.publication()).expect("read publication.nota");
    let parsed = decode_publication(&publication_text);
    assert_eq!(parsed.node_name, "probus");

    // The publication's open_ssh_public_key should match the file
    // sshd wrote, verbatim (the file's trailing newline is stripped).
    let ssh_pub_on_disk = fs::read_to_string(fixture.ssh_host_key_pub())
        .expect("read ssh.pub")
        .trim()
        .to_string();
    assert_eq!(
        parsed.open_ssh_public_key, ssh_pub_on_disk,
        "publication's open_ssh_public_key must match sshd's ssh.pub verbatim"
    );
    assert!(
        parsed.open_ssh_public_key.starts_with("ssh-ed25519 "),
        "publication's open_ssh_public_key wrong shape: {}",
        parsed.open_ssh_public_key
    );

    let yggdrasil_projection = parsed
        .yggdrasil
        .expect("publication missing typed YggdrasilProjection");
    assert_eq!(
        yggdrasil_projection.public_key.len(),
        64,
        "yggdrasil public_key should be 64 hex chars, got {}: {}",
        yggdrasil_projection.public_key.len(),
        yggdrasil_projection.public_key
    );
    assert!(
        yggdrasil_projection
            .public_key
            .chars()
            .all(|c| c.is_ascii_hexdigit()),
        "yggdrasil public_key should be hex"
    );
    let wifi_certificate = parsed
        .wifi_client_certificate
        .expect("publication missing typed WifiClientCertificate");
    assert!(
        wifi_certificate.pem.contains("BEGIN CERTIFICATE"),
        "wifi_client_certificate.pem missing PEM marker: {}",
        wifi_certificate.pem
    );
}

#[test]
fn public_key_publication_writing_omits_optional_planes_when_none() {
    let fixture = Fixture::new();
    fixture.generate_ssh_host_key();

    let writing = run(&ClaviFaberRequest::PublicKeyPublicationWriting(
        PublicKeyPublicationWriting {
            node_name: "probus".to_string(),
            open_ssh_public_key: OpenSshPublicKeyLocation {
                path: directory_text(&fixture.ssh_host_key_pub()),
            },
            yggdrasil_keypair: None,
            wifi_client_certificate: None,
            publication_output: directory_text(&fixture.publication()),
        },
    ));
    assert!(
        writing.status.success(),
        "stderr: {}",
        stderr_text(&writing)
    );

    let publication_text =
        fs::read_to_string(fixture.publication()).expect("read publication.nota");
    let parsed = decode_publication(&publication_text);
    assert_eq!(parsed.yggdrasil, None);
    assert_eq!(parsed.wifi_client_certificate, None);
}

#[test]
fn public_key_publication_writing_fails_when_ssh_host_key_missing() {
    let fixture = Fixture::new();
    // Intentionally do NOT generate the ssh.pub file.

    let writing = run(&ClaviFaberRequest::PublicKeyPublicationWriting(
        PublicKeyPublicationWriting {
            node_name: "probus".to_string(),
            open_ssh_public_key: OpenSshPublicKeyLocation {
                path: directory_text(&fixture.ssh_host_key_pub()),
            },
            yggdrasil_keypair: None,
            wifi_client_certificate: None,
            publication_output: directory_text(&fixture.publication()),
        },
    ));
    assert!(
        !writing.status.success(),
        "publication writing must fail when the named ssh.pub file is absent — clavifaber does NOT generate one"
    );
}
