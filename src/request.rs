use crate::actors::certificate_issuer::{
    IssueCertificateAuthority, IssueNodeCertificate, IssueServerCertificate, VerifyCertificateChain,
};
use crate::actors::gpg_agent_session::ReadEd25519PublicKey;
use crate::actors::host_identity::{EnsureIdentity, LoadIdentity, WritePublicKeyProjection};
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
    IdentitySetup(IdentitySetup),
    OpenSshPublicKeyDerivation(OpenSshPublicKeyDerivation),
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
            Self::IdentitySetup(request) => request.execute().await,
            Self::OpenSshPublicKeyDerivation(request) => request.execute().await,
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
    IdentitySet(IdentitySet),
    OpenSshPublicKeyDerived(OpenSshPublicKeyDerived),
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
//  IdentitySetup — ensure host SSH ed25519 identity exists on disk.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct IdentitySetup {
    pub directory: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct IdentitySet {
    pub directory: String,
    pub open_ssh_public_key: String,
}

impl IdentitySetup {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let directory = PathBuf::from(&self.directory);
        let identity = runtime
            .host_identity
            .ask(EnsureIdentity {
                directory: directory.clone(),
            })
            .await
            .map_err(translate_send_error)?;
        Ok(ClaviFaberResponse::IdentitySet(IdentitySet {
            directory: self.directory,
            open_ssh_public_key: identity.open_ssh_public_key(),
        }))
    }
}

// ───────────────────────────────────────────────────────────────────
//  OpenSshPublicKeyDerivation — re-derive ssh.pub from the private key.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct OpenSshPublicKeyDerivation {
    pub directory: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct OpenSshPublicKeyDerived {
    pub open_ssh_public_key: String,
}

impl OpenSshPublicKeyDerivation {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let directory = PathBuf::from(&self.directory);
        let identity = runtime
            .host_identity
            .ask(LoadIdentity {
                directory: directory.clone(),
            })
            .await
            .map_err(translate_send_error)?;
        let projection = runtime
            .host_identity
            .ask(WritePublicKeyProjection {
                directory,
                identity,
            })
            .await
            .map_err(translate_send_error)?;
        Ok(ClaviFaberResponse::OpenSshPublicKeyDerived(
            OpenSshPublicKeyDerived {
                open_ssh_public_key: projection.open_ssh_public_key,
            },
        ))
    }
}

// ───────────────────────────────────────────────────────────────────
//  CertificateAuthorityIssuance — sign a CA cert against a GPG keygrip.
//  Idempotent: if `output` exists and is a parseable cert, skip.
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
        if output_path.exists() {
            return Ok(ClaviFaberResponse::CertificateAuthorityCertificateWritten(
                CertificateAuthorityCertificateWritten {
                    output: self.output,
                },
            ));
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
//  Idempotent: skip when both output files already exist.
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
        if certificate_path.exists() && private_key_path.exists() {
            return Ok(ClaviFaberResponse::ServerCertificateWritten(
                ServerCertificateWritten {
                    certificate: self.output_certificate,
                    private_key: self.output_private_key,
                },
            ));
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
//  ClientCertificateIssuance — sign a per-host client cert from the CA.
//  Idempotent: skip when output file already exists.
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
        if output_path.exists() {
            return Ok(ClaviFaberResponse::ClientCertificateWritten(
                ClientCertificateWritten {
                    output: self.output,
                },
            ));
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
//  CertificateChainVerification — issuer + signature + validity-window check.
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
//  YggdrasilKeypairSetup — generate the per-host yggdrasil keypair file.
//  Idempotent: handled inside YggdrasilKey actor.
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
//  publication.nota with typed identity / yggdrasil / wifi-cert fields.
// ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct PublicKeyPublicationWriting {
    pub node_name: String,
    pub identity_directory: String,
    pub yggdrasil_keypair: Option<YggdrasilKeypairLocation>,
    pub wifi_client_certificate: Option<WifiClientCertificateLocation>,
    pub publication_output: String,
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
        let identity_directory = PathBuf::from(&self.identity_directory);
        let identity = runtime
            .host_identity
            .ask(LoadIdentity {
                directory: identity_directory,
            })
            .await
            .map_err(translate_send_error)?;
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
            open_ssh_public_key: identity.open_ssh_public_key(),
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
//  Helpers (keep them small; AtomicFile owns the write side).
// ───────────────────────────────────────────────────────────────────

fn read_certificate(path: &Path) -> Result<CertificateDer> {
    let pem = std::fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_path_buf(),
        source,
    })?;
    CertificateDer::from_pem(&pem)
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
