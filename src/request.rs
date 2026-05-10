use crate::actors::certificate_issuer::{
    IssueCertificateAuthority, IssueNodeCertificate, IssueServerCertificate, VerifyCertificateChain,
};
use crate::actors::gpg_agent_session::ReadEd25519PublicKey;
use crate::actors::runtime_root::RuntimeRoot;
use crate::actors::translate_send_error;
use crate::actors::yggdrasil_key::{EnsureYggdrasilIdentity, ReadYggdrasilProjection};
use crate::error::{Error, Result};
use crate::publication::{PublicKeyPublication, WifiClientCertificate};
use crate::ssh_key::OpenSshPublicKey as SshKeyText;
use crate::util::AtomicFile;
use crate::x509::{
    CertificateAuthorityCertificateRequest, CertificateDer, Ed25519SubjectPublicKey,
    NodeCertificateSigningRequest, ServerCertificate, ServerCertificateSigningRequest,
};
use crate::yggdrasil::YggdrasilProjection;
use nota_codec::{Decoder, Encoder, NotaDecode, NotaEncode, NotaRecord, NotaSum};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, NotaSum)]
pub enum ClaviFaberRequest {
    CertificateAuthorityIssuance(CertificateAuthorityIssuance),
    ServerCertificateIssuance(ServerCertificateIssuance),
    ClientCertificateIssuance(ClientCertificateIssuance),
    CertificateChainVerification(CertificateChainVerification),
    YggdrasilKeypairSetup(YggdrasilKeypairSetup),
    PublicKeyPublicationWriting(PublicKeyPublicationWriting),
}

impl ClaviFaberRequest {
    pub fn from_nota(text: &str) -> Result<Self> {
        let mut decoder = Decoder::new(text);
        let request = <Self as NotaDecode>::decode(&mut decoder)?;
        if let Some(token) = decoder.peek_token()? {
            return Err(nota_codec::Error::UnexpectedToken {
                expected: "end of input",
                got: token,
            }
            .into());
        }
        Ok(request)
    }

    pub fn to_nota(&self) -> Result<String> {
        let mut encoder = Encoder::new();
        <Self as NotaEncode>::encode(self, &mut encoder)?;
        Ok(encoder.into_string())
    }

    pub async fn execute(self) -> Result<ClaviFaberResponse> {
        match self {
            Self::CertificateAuthorityIssuance(request) => request.execute().await,
            Self::ServerCertificateIssuance(request) => request.execute().await,
            Self::ClientCertificateIssuance(request) => request.execute().await,
            Self::CertificateChainVerification(request) => request.execute().await,
            Self::YggdrasilKeypairSetup(request) => request.execute().await,
            Self::PublicKeyPublicationWriting(request) => request.execute().await,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaSum)]
pub enum ClaviFaberResponse {
    CertificateAuthorityCertificateWritten(CertificateAuthorityCertificateWritten),
    ServerCertificateWritten(ServerCertificateWritten),
    ClientCertificateWritten(ClientCertificateWritten),
    CertificateChainVerified(CertificateChainVerified),
    YggdrasilKeypairSet(YggdrasilKeypairSet),
    PublicKeyPublicationWritten(PublicKeyPublicationWritten),
}

impl ClaviFaberResponse {
    pub fn from_nota(text: &str) -> Result<Self> {
        let mut decoder = Decoder::new(text);
        let response = <Self as NotaDecode>::decode(&mut decoder)?;
        if let Some(token) = decoder.peek_token()? {
            return Err(nota_codec::Error::UnexpectedToken {
                expected: "end of input",
                got: token,
            }
            .into());
        }
        Ok(response)
    }

    pub fn to_nota(&self) -> Result<String> {
        let mut encoder = Encoder::new();
        <Self as NotaEncode>::encode(self, &mut encoder)?;
        Ok(encoder.into_string())
    }
}

// ───────────────────────────────────────────────────────────────────
//  CertificateAuthorityIssuance — sign a CA cert against a GPG keygrip.
//  Idempotent: skip when the output file parses as a PEM certificate;
//  fail loudly when it exists but is unparseable.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct CertificateAuthorityIssuance {
    pub keygrip: String,
    pub common_name: String,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct CertificateAuthorityCertificateWritten {
    pub output: String,
}

impl CertificateAuthorityIssuance {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let output_path = PathBuf::from(&self.output);
        match existing_certificate_file(&output_path)? {
            ExistingCertificateFile::Absent => {}
            ExistingCertificateFile::Valid => {
                return Ok(ClaviFaberResponse::CertificateAuthorityCertificateWritten(
                    CertificateAuthorityCertificateWritten {
                        output: self.output,
                    },
                ));
            }
            ExistingCertificateFile::Unparseable(detail) => {
                return Err(Error::Certificate(format!(
                    "{} exists but is not a parseable certificate ({detail}); refusing to silently overwrite — delete the file (or `mv {0}.bad`) to force re-issue",
                    output_path.display()
                )));
            }
        }
        let runtime = RuntimeRoot::start(None);
        let public_key_bytes = runtime
            .gpg_agent_session
            .ask(ReadEd25519PublicKey {
                keygrip: self.keygrip.clone(),
            })
            .await
            .map_err(translate_send_error)?;
        let subject_public_key_info =
            Ed25519SubjectPublicKey::from_bytes(public_key_bytes).subject_public_key_info()?;
        let certificate = runtime
            .certificate_issuer
            .ask(IssueCertificateAuthority {
                keygrip: self.keygrip,
                request: CertificateAuthorityCertificateRequest::new(
                    self.common_name,
                    subject_public_key_info,
                ),
            })
            .await
            .map_err(translate_send_error)?;
        AtomicFile::new(output_path).write_bytes(certificate.to_pem()?.as_bytes(), 0o644)?;
        Ok(ClaviFaberResponse::CertificateAuthorityCertificateWritten(
            CertificateAuthorityCertificateWritten {
                output: self.output,
            },
        ))
    }
}

// ───────────────────────────────────────────────────────────────────
//  ServerCertificateIssuance — sign a P-256 server cert from the CA.
//  Skip when both output files parse. Fail loudly on unparseable or
//  half-existence (would silently rotate the EC keypair).
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct ServerCertificateIssuance {
    pub certificate_authority_keygrip: String,
    pub certificate_authority_certificate: String,
    pub common_name: String,
    pub output_certificate: String,
    pub output_private_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct ServerCertificateWritten {
    pub certificate: String,
    pub private_key: String,
}

impl ServerCertificateIssuance {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let certificate_path = PathBuf::from(&self.output_certificate);
        let private_key_path = PathBuf::from(&self.output_private_key);
        match (
            existing_certificate_file(&certificate_path)?,
            existing_private_key_file(&private_key_path)?,
        ) {
            (ExistingCertificateFile::Valid, ExistingPrivateKeyFile::Valid) => {
                return Ok(ClaviFaberResponse::ServerCertificateWritten(
                    ServerCertificateWritten {
                        certificate: self.output_certificate,
                        private_key: self.output_private_key,
                    },
                ));
            }
            (ExistingCertificateFile::Absent, ExistingPrivateKeyFile::Absent) => {}
            (ExistingCertificateFile::Unparseable(detail), _) => {
                return Err(Error::Certificate(format!(
                    "{} exists but is not a parseable certificate ({detail}); refusing to silently overwrite — delete BOTH cert and key files to force re-issue",
                    certificate_path.display()
                )));
            }
            (_, ExistingPrivateKeyFile::Unparseable(detail)) => {
                return Err(Error::Certificate(format!(
                    "{} exists but is not a parseable private key ({detail}); refusing to silently overwrite — delete BOTH cert and key files to force re-issue",
                    private_key_path.display()
                )));
            }
            (ExistingCertificateFile::Valid, _) | (_, ExistingPrivateKeyFile::Valid) => {
                return Err(Error::Certificate(format!(
                    "{} and {} half-exist; refusing to re-issue (would lose the surviving file's keypair). Delete BOTH files to force re-issue, or restore the missing one from backup",
                    certificate_path.display(),
                    private_key_path.display()
                )));
            }
        }
        let runtime = RuntimeRoot::start(None);
        let certificate_authority =
            read_certificate(Path::new(&self.certificate_authority_certificate))?;
        let server_certificate = runtime
            .certificate_issuer
            .ask(IssueServerCertificate {
                keygrip: self.certificate_authority_keygrip,
                certificate_authority,
                request: ServerCertificateSigningRequest::new(self.common_name),
            })
            .await
            .map_err(translate_send_error)?;
        write_server_certificate(&certificate_path, &private_key_path, &server_certificate)?;
        Ok(ClaviFaberResponse::ServerCertificateWritten(
            ServerCertificateWritten {
                certificate: self.output_certificate,
                private_key: self.output_private_key,
            },
        ))
    }
}

// ───────────────────────────────────────────────────────────────────
//  ClientCertificateIssuance — sign a per-host client cert from the
//  cluster CA against the host's OpenSSH ed25519 public key.
//  Idempotent: skip when the output parses; fail loudly otherwise.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct ClientCertificateIssuance {
    pub certificate_authority_keygrip: String,
    pub certificate_authority_certificate: String,
    pub open_ssh_public_key: String,
    pub common_name: String,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct ClientCertificateWritten {
    pub output: String,
}

impl ClientCertificateIssuance {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let output_path = PathBuf::from(&self.output);
        match existing_certificate_file(&output_path)? {
            ExistingCertificateFile::Absent => {}
            ExistingCertificateFile::Valid => {
                return Ok(ClaviFaberResponse::ClientCertificateWritten(
                    ClientCertificateWritten {
                        output: self.output,
                    },
                ));
            }
            ExistingCertificateFile::Unparseable(detail) => {
                return Err(Error::Certificate(format!(
                    "{} exists but is not a parseable certificate ({detail}); refusing to silently overwrite — delete the file to force re-issue",
                    output_path.display()
                )));
            }
        }
        let runtime = RuntimeRoot::start(None);
        let certificate_authority =
            read_certificate(Path::new(&self.certificate_authority_certificate))?;
        let subject_public_key_info =
            SshKeyText::from_text(self.open_ssh_public_key)?.subject_public_key_info()?;
        let certificate = runtime
            .certificate_issuer
            .ask(IssueNodeCertificate {
                keygrip: self.certificate_authority_keygrip,
                certificate_authority,
                request: NodeCertificateSigningRequest::new(
                    self.common_name,
                    subject_public_key_info,
                ),
            })
            .await
            .map_err(translate_send_error)?;
        AtomicFile::new(output_path).write_bytes(certificate.to_pem()?.as_bytes(), 0o644)?;
        Ok(ClaviFaberResponse::ClientCertificateWritten(
            ClientCertificateWritten {
                output: self.output,
            },
        ))
    }
}

// ───────────────────────────────────────────────────────────────────
//  CertificateChainVerification — issuer + signature + validity-window.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct CertificateChainVerification {
    pub certificate_authority_certificate: String,
    pub certificate: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct CertificateChainVerified {
    pub certificate: String,
}

impl CertificateChainVerification {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let certificate_authority =
            read_certificate(Path::new(&self.certificate_authority_certificate))?;
        let certificate = read_certificate(Path::new(&self.certificate))?;
        runtime
            .certificate_issuer
            .ask(VerifyCertificateChain {
                certificate_authority,
                certificate,
            })
            .await
            .map_err(translate_send_error)?;
        Ok(ClaviFaberResponse::CertificateChainVerified(
            CertificateChainVerified {
                certificate: self.certificate,
            },
        ))
    }
}

// ───────────────────────────────────────────────────────────────────
//  YggdrasilKeypairSetup — generate the per-host yggdrasil keypair
//  file. Idempotent: YggdrasilKey actor skips if the file exists.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct YggdrasilKeypairSetup {
    pub keypair_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct YggdrasilKeypairSet {
    pub keypair_path: String,
    pub projection: YggdrasilProjection,
}

impl YggdrasilKeypairSetup {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let keypair_path = PathBuf::from(&self.keypair_path);
        runtime
            .yggdrasil_key
            .ask(EnsureYggdrasilIdentity {
                keypair_path: keypair_path.clone(),
            })
            .await
            .map_err(translate_send_error)?;
        let projection = runtime
            .yggdrasil_key
            .ask(ReadYggdrasilProjection { keypair_path })
            .await
            .map_err(translate_send_error)?;
        Ok(ClaviFaberResponse::YggdrasilKeypairSet(
            YggdrasilKeypairSet {
                keypair_path: self.keypair_path,
                projection,
            },
        ))
    }
}

// ───────────────────────────────────────────────────────────────────
//  PublicKeyPublicationWriting — assemble and atomically write
//  publication.nota with typed open-ssh-pubkey / yggdrasil / wifi-cert
//  fields. clavifaber does NOT own the SSH host key — sshd does — so
//  the caller hands clavifaber a path to the existing
//  /etc/ssh/ssh_host_ed25519_key.pub (or wherever the operator
//  configures it).
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct PublicKeyPublicationWriting {
    pub node_name: String,
    pub open_ssh_public_key: OpenSshPublicKeyLocation,
    pub yggdrasil_keypair: Option<YggdrasilKeypairLocation>,
    pub wifi_client_certificate: Option<WifiClientCertificateLocation>,
    pub publication_output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct OpenSshPublicKeyLocation {
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct YggdrasilKeypairLocation {
    pub keypair_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct WifiClientCertificateLocation {
    pub certificate_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct PublicKeyPublicationWritten {
    pub publication_output: String,
}

impl PublicKeyPublicationWriting {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let open_ssh_public_key =
            read_open_ssh_public_key(Path::new(&self.open_ssh_public_key.path))?;
        let yggdrasil = match &self.yggdrasil_keypair {
            Some(location) => {
                let keypair_path = PathBuf::from(&location.keypair_path);
                let projection = runtime
                    .yggdrasil_key
                    .ask(ReadYggdrasilProjection {
                        keypair_path: keypair_path.clone(),
                    })
                    .await
                    .map_err(translate_send_error)?;
                Some(projection)
            }
            None => None,
        };
        let wifi_client_certificate = match &self.wifi_client_certificate {
            Some(location) => {
                let pem = std::fs::read_to_string(Path::new(&location.certificate_path)).map_err(
                    |source| Error::Io {
                        path: PathBuf::from(&location.certificate_path),
                        source,
                    },
                )?;
                Some(WifiClientCertificate { pem })
            }
            None => None,
        };
        let publication = PublicKeyPublication {
            node_name: self.node_name,
            open_ssh_public_key,
            yggdrasil,
            wifi_client_certificate,
        };
        let mut encoder = Encoder::new();
        publication.encode(&mut encoder)?;
        let publication_text = encoder.into_string();
        AtomicFile::new(PathBuf::from(&self.publication_output))
            .write_bytes(publication_text.as_bytes(), 0o644)?;
        Ok(ClaviFaberResponse::PublicKeyPublicationWritten(
            PublicKeyPublicationWritten {
                publication_output: self.publication_output,
            },
        ))
    }
}

// ───────────────────────────────────────────────────────────────────
//  Helpers (small; AtomicFile owns the write side).
// ───────────────────────────────────────────────────────────────────

fn read_certificate(path: &Path) -> Result<CertificateDer> {
    let pem = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    CertificateDer::from_pem(&pem)
}

/// Read an OpenSSH ed25519 public key from disk and return its text
/// form (e.g. `ssh-ed25519 AAAA... comment`). The publication carries
/// this verbatim so consumers compare apples-to-apples with what
/// sshd presents on the wire.
fn read_open_ssh_public_key(path: &Path) -> Result<String> {
    let raw = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let trimmed = raw.trim();
    if !trimmed.starts_with("ssh-ed25519 ") {
        return Err(Error::Parse(format!(
            "{}: expected an ssh-ed25519 public key, got: {:?}",
            path.display(),
            trimmed.chars().take(40).collect::<String>()
        )));
    }
    // Parse-validate via OpenSshPublicKey so a syntactically-wrong
    // line on disk surfaces here instead of later inside the X.509
    // cert path or downstream consumers.
    let _ = SshKeyText::from_text(trimmed)?;
    Ok(trimmed.to_owned())
}

/// Three-state classification of an on-disk certificate file: absent,
/// parseable, or present-but-unparseable. Per report 112: the cert
/// handlers' skip path used bare `Path::exists()`, which silently
/// passed a truncated / garbage file as "valid". This refines that.
enum ExistingCertificateFile {
    Absent,
    Valid,
    Unparseable(String),
}

fn existing_certificate_file(path: &Path) -> Result<ExistingCertificateFile> {
    if !path.exists() {
        return Ok(ExistingCertificateFile::Absent);
    }
    let pem = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    match CertificateDer::from_pem(&pem) {
        Ok(_) => Ok(ExistingCertificateFile::Valid),
        Err(error) => Ok(ExistingCertificateFile::Unparseable(error.to_string())),
    }
}

/// Three-state classification of an on-disk private-key file: absent,
/// looks-like-a-private-key-PEM, or present-but-not-PEM.
enum ExistingPrivateKeyFile {
    Absent,
    Valid,
    Unparseable(String),
}

fn existing_private_key_file(path: &Path) -> Result<ExistingPrivateKeyFile> {
    if !path.exists() {
        return Ok(ExistingPrivateKeyFile::Absent);
    }
    let content = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let has_begin = content.contains("-----BEGIN ");
    let has_end = content.contains("-----END ");
    let mentions_private_key = content.contains("PRIVATE KEY");
    if has_begin && has_end && mentions_private_key {
        Ok(ExistingPrivateKeyFile::Valid)
    } else {
        Ok(ExistingPrivateKeyFile::Unparseable(
            "file is not a PEM private-key block".to_string(),
        ))
    }
}

fn write_server_certificate(
    certificate_path: &Path,
    private_key_path: &Path,
    server_certificate: &ServerCertificate,
) -> Result<()> {
    AtomicFile::new(certificate_path.to_path_buf())
        .write_bytes(server_certificate.certificate().to_pem()?.as_bytes(), 0o644)?;
    AtomicFile::new(private_key_path.to_path_buf())
        .write_bytes(server_certificate.private_key_pem().as_bytes(), 0o600)
}

// ───────────────────────────────────────────────────────────────────
//  Inline-NOTA argv parser (the only operator surface).
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandLine {
    arguments: Vec<OsString>,
}

impl CommandLine {
    pub fn from_env() -> Self {
        Self::from_arguments(std::env::args_os().skip(1))
    }

    pub fn from_arguments<I, S>(arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        Self {
            arguments: arguments.into_iter().map(Into::into).collect(),
        }
    }

    pub fn parse_request(&self) -> Result<ClaviFaberRequest> {
        ClaviFaberRequest::from_nota(&self.text()?)
    }

    fn text(&self) -> Result<String> {
        let mut parts = Vec::new();
        for argument in &self.arguments {
            let Some(text) = argument.to_str() else {
                return Err(Error::InvalidInlineNotaArgument {
                    got: format!("{argument:?}"),
                });
            };
            parts.push(text.to_string());
        }
        Ok(parts.join(" "))
    }
}
