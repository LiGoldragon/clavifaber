//! The one-inline-Datom command boundary and request execution.

use crate::actors::certificate_issuer::{
    IssueCertificateAuthority, IssueNodeCertificate, IssueServerCertificate, VerifyCertificateChain,
};
use crate::actors::gpg_agent_session::ReadEd25519PublicKey;
use crate::actors::runtime_root::RuntimeRoot;
use crate::actors::translate_send_error;
use crate::actors::yggdrasil_key::{EnsureYggdrasilIdentity, ReadYggdrasilProjection};
use crate::error::{Error, Result};
use crate::ssh_key::OpenSshPublicKey as SshKeyText;
use crate::util::AtomicFile;
use crate::x509::{
    CertificateAuthorityCertificateRequest, CertificateDer, Ed25519SubjectPublicKey,
    NodeCertificateSigningRequest, ServerCertificate, ServerCertificateSigningRequest,
};
use datom_codec::{Actualizable, IncorporationBudget, Potential};
use protos::Textualizable;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

pub use crate::generated::clavifaber::*;

const COMMAND_BUDGET: i64 = 16_384;

impl ClaviFaberRequest {
    pub fn decode(text: &str) -> Result<Self> {
        Potential::<Self>::from(text.to_owned())
            .actualize(IncorporationBudget::try_from(COMMAND_BUDGET).expect("positive budget"))
            .map_err(Error::from)
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

impl CertificateAuthorityIssuance {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let Self(keygrip, common_name, output) = self;
        let output_path = PathBuf::from(output.as_ref());
        match existing_certificate_file(&output_path)? {
            ExistingCertificateFile::Absent => {}
            ExistingCertificateFile::Valid => {
                return Ok(ClaviFaberResponse::CertificateAuthorityCertificateWritten(
                    CertificateAuthorityCertificateWritten(output),
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
                keygrip: keygrip.to_string(),
            })
            .await
            .map_err(translate_send_error)?;
        let subject_public_key_info =
            Ed25519SubjectPublicKey::from_bytes(public_key_bytes).subject_public_key_info()?;
        let certificate = runtime
            .certificate_issuer
            .ask(IssueCertificateAuthority {
                keygrip: keygrip.to_string(),
                request: CertificateAuthorityCertificateRequest::new(
                    common_name.to_string(),
                    subject_public_key_info,
                ),
            })
            .await
            .map_err(translate_send_error)?;
        AtomicFile::new(output_path).write_bytes(certificate.to_pem()?.as_bytes(), 0o644)?;
        Ok(ClaviFaberResponse::CertificateAuthorityCertificateWritten(
            CertificateAuthorityCertificateWritten(output),
        ))
    }
}

impl ServerCertificateIssuance {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let Self(
            keygrip,
            authority_certificate,
            common_name,
            output_certificate,
            output_private_key,
        ) = self;
        let certificate_path = PathBuf::from(output_certificate.as_ref());
        let private_key_path = PathBuf::from(output_private_key.as_ref());
        match (
            existing_certificate_file(&certificate_path)?,
            existing_private_key_file(&private_key_path)?,
        ) {
            (ExistingCertificateFile::Valid, ExistingPrivateKeyFile::Valid) => {
                return Ok(ClaviFaberResponse::ServerCertificateWritten(
                    ServerCertificateWritten(output_certificate, output_private_key),
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
        let certificate_authority = read_certificate(Path::new(authority_certificate.as_ref()))?;
        let server_certificate = runtime
            .certificate_issuer
            .ask(IssueServerCertificate {
                keygrip: keygrip.to_string(),
                certificate_authority,
                request: ServerCertificateSigningRequest::new(common_name.to_string()),
            })
            .await
            .map_err(translate_send_error)?;
        write_server_certificate(&certificate_path, &private_key_path, &server_certificate)?;
        Ok(ClaviFaberResponse::ServerCertificateWritten(
            ServerCertificateWritten(output_certificate, output_private_key),
        ))
    }
}

impl ClientCertificateIssuance {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let Self(keygrip, authority_certificate, open_ssh_public_key, common_name, output) = self;
        let output_path = PathBuf::from(output.as_ref());
        match existing_certificate_file(&output_path)? {
            ExistingCertificateFile::Absent => {}
            ExistingCertificateFile::Valid => {
                return Ok(ClaviFaberResponse::ClientCertificateWritten(
                    ClientCertificateWritten(output),
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
        let certificate_authority = read_certificate(Path::new(authority_certificate.as_ref()))?;
        let subject_public_key_info =
            SshKeyText::from_text(open_ssh_public_key.as_ref())?.subject_public_key_info()?;
        let certificate = runtime
            .certificate_issuer
            .ask(IssueNodeCertificate {
                keygrip: keygrip.to_string(),
                certificate_authority,
                request: NodeCertificateSigningRequest::new(
                    common_name.to_string(),
                    subject_public_key_info,
                ),
            })
            .await
            .map_err(translate_send_error)?;
        AtomicFile::new(output_path).write_bytes(certificate.to_pem()?.as_bytes(), 0o644)?;
        Ok(ClaviFaberResponse::ClientCertificateWritten(
            ClientCertificateWritten(output),
        ))
    }
}

impl CertificateChainVerification {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let Self(authority_certificate, certificate) = self;
        let runtime = RuntimeRoot::start(None);
        let certificate_authority = read_certificate(Path::new(authority_certificate.as_ref()))?;
        let certificate_value = read_certificate(Path::new(certificate.as_ref()))?;
        runtime
            .certificate_issuer
            .ask(VerifyCertificateChain {
                certificate_authority,
                certificate: certificate_value,
            })
            .await
            .map_err(translate_send_error)?;
        Ok(ClaviFaberResponse::CertificateChainVerified(
            CertificateChainVerified(certificate),
        ))
    }
}

impl YggdrasilKeypairSetup {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let Self(keypair_path) = self;
        let runtime = RuntimeRoot::start(None);
        let keypair = PathBuf::from(keypair_path.as_ref());
        runtime
            .yggdrasil_key
            .ask(EnsureYggdrasilIdentity {
                keypair_path: keypair.clone(),
            })
            .await
            .map_err(translate_send_error)?;
        let projection = runtime
            .yggdrasil_key
            .ask(ReadYggdrasilProjection {
                keypair_path: keypair,
            })
            .await
            .map_err(translate_send_error)?;
        Ok(ClaviFaberResponse::YggdrasilKeypairSet(
            YggdrasilKeypairSet(keypair_path, projection),
        ))
    }
}

impl PublicKeyPublicationWriting {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let Self(
            node_name,
            open_ssh_public_key,
            yggdrasil_keypair,
            wifi_client_certificate,
            publication_output,
        ) = self;
        let runtime = RuntimeRoot::start(None);
        let open_ssh_public_key =
            read_open_ssh_public_key(Path::new(open_ssh_public_key.0.as_ref()))?;
        let yggdrasil = match yggdrasil_keypair {
            Some(YggdrasilKeypairLocation(keypair_path)) => Some(
                runtime
                    .yggdrasil_key
                    .ask(ReadYggdrasilProjection {
                        keypair_path: PathBuf::from(keypair_path.as_ref()),
                    })
                    .await
                    .map_err(translate_send_error)?,
            ),
            None => None,
        };
        let wifi_client_certificate = match wifi_client_certificate {
            Some(WifiClientCertificateLocation(certificate_path)) => {
                let pem = std::fs::read_to_string(Path::new(certificate_path.as_ref())).map_err(
                    |source| Error::Io {
                        path: PathBuf::from(certificate_path.as_ref()),
                        source,
                    },
                )?;
                Some(WifiClientCertificate(
                    protos::Text::try_from(pem).map_err(|error| Error::Parse(error.to_string()))?,
                ))
            }
            None => None,
        };
        let publication = PublicKeyPublication(
            node_name,
            open_ssh_public_key,
            yggdrasil,
            wifi_client_certificate,
        );
        let publication_text: String = publication.textualize();
        AtomicFile::new(PathBuf::from(publication_output.as_ref()))
            .write_bytes(publication_text.as_bytes(), 0o644)?;
        Ok(ClaviFaberResponse::PublicKeyPublicationWritten(
            PublicKeyPublicationWritten(publication_output),
        ))
    }
}

fn read_certificate(path: &Path) -> Result<CertificateDer> {
    let pem = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    CertificateDer::from_pem(&pem)
}

fn read_open_ssh_public_key(path: &Path) -> Result<protos::Text> {
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
    let _ = SshKeyText::from_text(trimmed)?;
    protos::Text::try_from(trimmed).map_err(|error| Error::Parse(error.to_string()))
}

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
    if content.contains("-----BEGIN ")
        && content.contains("-----END ")
        && content.contains("PRIVATE KEY")
    {
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

/// The CLI accepts exactly one inline Datom value and no flags.
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
        ClaviFaberRequest::decode(&self.text()?)
    }

    fn text(&self) -> Result<String> {
        let mut parts = Vec::new();
        for argument in &self.arguments {
            let Some(text) = argument.to_str() else {
                return Err(Error::InvalidInlineDatomArgument {
                    got: format!("{argument:?}"),
                });
            };
            parts.push(text.to_string());
        }
        Ok(parts.join(" "))
    }
}
