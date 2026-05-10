//! Witness that `PublicKeyPublicationWriting` assembles the publication
//! file with typed `YggdrasilProjection` and `WifiClientCertificate`
//! wrappers (replacing the old caller-supplied opaque PEM string).

use clavifaber::publication::PublicKeyPublication;
use clavifaber::request::{
    ClaviFaberRequest, IdentitySetup, PublicKeyPublicationWriting, WifiClientCertificateLocation,
    YggdrasilKeypairLocation, YggdrasilKeypairSetup,
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

    fn identity_directory(&self) -> PathBuf {
        self.temporary_directory.path().join("identity")
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
    use nota_codec::{Decoder, NotaDecode};
    let mut decoder = Decoder::new(text);
    PublicKeyPublication::decode(&mut decoder).expect("decode publication.nota")
}

#[test]
fn public_key_publication_writing_assembles_typed_record_atomically() {
    let fixture = Fixture::new();

    // Seed the identity.
    let setup = run(&ClaviFaberRequest::IdentitySetup(IdentitySetup {
        directory: directory_text(&fixture.identity_directory()),
    }));
    assert!(setup.status.success(), "stderr: {}", stderr_text(&setup));

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

    // Seed a fake wifi client cert PEM. NOTE: nota-codec's encoder
    // currently doesn't emit multi-line `""" """` strings for values
    // with newlines (filed as primary-* nota-codec bead), so the test
    // fixture is single-line. Real PEMs round-trip through publication
    // .nota only after that bead lands.
    fs::write(
        fixture.wifi_client_cert(),
        b"-----BEGIN CERTIFICATE----- MARKER -----END CERTIFICATE-----",
    )
    .expect("seed wifi client cert");

    // Write the publication.
    let writing = run(&ClaviFaberRequest::PublicKeyPublicationWriting(
        PublicKeyPublicationWriting {
            node_name: "probus".to_string(),
            identity_directory: directory_text(&fixture.identity_directory()),
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

    let setup = run(&ClaviFaberRequest::IdentitySetup(IdentitySetup {
        directory: directory_text(&fixture.identity_directory()),
    }));
    assert!(setup.status.success(), "stderr: {}", stderr_text(&setup));

    let writing = run(&ClaviFaberRequest::PublicKeyPublicationWriting(
        PublicKeyPublicationWriting {
            node_name: "probus".to_string(),
            identity_directory: directory_text(&fixture.identity_directory()),
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
