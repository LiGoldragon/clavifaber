//! Public Datom publication assembly from an sshd-owned host key.

use clavifaber::publication::PublicKeyPublication;
use clavifaber::request::{
    ClaviFaberRequest, OpenSshPublicKeyLocation, PublicKeyPublicationWriting,
    WifiClientCertificateLocation, YggdrasilKeypairLocation, YggdrasilKeypairSetup,
};
use clavifaber::text::DatomTexting;
use datom_codec::{Actualizing, Budget, Potential};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use tempfile::TempDir;

fn text(value: impl AsRef<str>) -> String {
    value.as_ref().to_owned()
}

fn budget() -> Budget {
    Budget {
        remaining: 4_096,
        reader: protos::ReaderBudget { remaining: 16_384 },
        depth: 0,
        maximum_depth: 4_096,
    }
}

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
        self.temporary_directory.path().join("publication.datom")
    }

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
        .arg(request.datom_text())
        .output()
        .expect("run clavifaber")
}

fn stderr_text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}
fn path_text(path: &Path) -> String {
    text(path.to_string_lossy())
}

fn decode_publication(source: &str) -> PublicKeyPublication {
    Potential::<PublicKeyPublication>::from(source)
        .actualize(&mut budget())
        .expect("decode publication.datom")
}

fn publication_request(fixture: &Fixture, yggdrasil: bool, wifi: bool) -> ClaviFaberRequest {
    ClaviFaberRequest::PublicKeyPublicationWriting(PublicKeyPublicationWriting {
        first_string: text("probus"),
        open_ssh_public_key_location: OpenSshPublicKeyLocation {
            string: path_text(&fixture.ssh_host_key_pub()),
        },
        yggdrasil_keypair_location_option: yggdrasil.then(|| YggdrasilKeypairLocation {
            string: path_text(&fixture.yggdrasil_keypair()),
        }),
        wifi_client_certificate_location_option: wifi.then(|| WifiClientCertificateLocation {
            string: path_text(&fixture.wifi_client_cert()),
        }),
        second_string: path_text(&fixture.publication()),
    })
}

#[test]
fn public_key_publication_writing_assembles_typed_record_atomically() {
    let fixture = Fixture::new();
    fixture.generate_ssh_host_key();

    let yggdrasil = run(&ClaviFaberRequest::YggdrasilKeypairSetup(
        YggdrasilKeypairSetup {
            string: path_text(&fixture.yggdrasil_keypair()),
        },
    ));
    assert!(
        yggdrasil.status.success(),
        "stderr: {}",
        stderr_text(&yggdrasil)
    );
    fs::write(
        fixture.wifi_client_cert(),
        b"-----BEGIN CERTIFICATE-----\nMARKER\n-----END CERTIFICATE-----\n",
    )
    .expect("seed wifi client cert");

    let writing = run(&publication_request(&fixture, true, true));
    assert!(
        writing.status.success(),
        "stderr: {}",
        stderr_text(&writing)
    );

    let mode = fs::metadata(fixture.publication())
        .expect("publication metadata")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode, 0o644,
        "publication.datom must be mode 0644, got {mode:o}"
    );

    let publication_text =
        fs::read_to_string(fixture.publication()).expect("read publication.datom");
    assert!(
        publication_text.starts_with("{ "),
        "the public file is a direct generated product, not a request envelope"
    );
    assert!(
        !publication_text.contains("PublicKeyPublication"),
        "the public file is not a nominal compatibility wrapper"
    );
    let parsed = decode_publication(&publication_text);
    assert_eq!(parsed.first_string, text("probus"));
    let ssh_pub_on_disk = fs::read_to_string(fixture.ssh_host_key_pub())
        .expect("read ssh.pub")
        .trim()
        .to_string();
    assert_eq!(
        parsed.second_string,
        text(&ssh_pub_on_disk),
        "publication carries sshd's ssh.pub verbatim"
    );
    assert!(parsed.second_string.starts_with("ssh-ed25519 "));

    let yggdrasil_projection = parsed
        .yggdrasil_projection_option
        .expect("publication missing typed YggdrasilProjection");
    assert_eq!(
        yggdrasil_projection.second_string.len(),
        64,
        "yggdrasil public key is 64 hex chars"
    );
    assert!(
        yggdrasil_projection
            .second_string
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    );
    let wifi_certificate = parsed
        .wifi_client_certificate_option
        .expect("publication missing typed WifiClientCertificate");
    assert!(wifi_certificate.string.contains("BEGIN CERTIFICATE"));
}

#[test]
fn public_key_publication_writing_omits_optional_planes_when_none() {
    let fixture = Fixture::new();
    fixture.generate_ssh_host_key();
    let writing = run(&publication_request(&fixture, false, false));
    assert!(
        writing.status.success(),
        "stderr: {}",
        stderr_text(&writing)
    );
    let parsed = decode_publication(
        &fs::read_to_string(fixture.publication()).expect("read publication.datom"),
    );
    assert_eq!(parsed.yggdrasil_projection_option, None);
    assert_eq!(parsed.wifi_client_certificate_option, None);
}

#[test]
fn public_key_publication_writing_fails_when_ssh_host_key_missing() {
    let fixture = Fixture::new();
    let writing = run(&publication_request(&fixture, false, false));
    assert!(
        !writing.status.success(),
        "publication writing must fail when ssh.pub is absent; clavifaber does not generate it"
    );
}
