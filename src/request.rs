use crate::actors::host_identity::{EnsureIdentity, LoadIdentity};
use crate::actors::runtime_root::RuntimeRoot;
use crate::actors::ssh_host_key::WritePublicKeyProjection;
use crate::actors::translate_send_error;
use crate::error::{Error, Result};
use crate::gpg_agent::GpgAgent;
use crate::publication::{PublicKeyPublication, PublicKeyPublicationRequest};
use crate::ssh_key::OpenSshPublicKey;
use crate::util::AtomicFile;
use crate::x509::{
    CertificateAuthorityCertificateRequest, CertificateAuthorityIssuer, CertificateChain,
    CertificateDer, Ed25519SubjectPublicKey, NodeCertificateSigningRequest, ServerCertificate,
    ServerCertificateSigningRequest,
};
use nota_codec::{Decoder, Encoder, NotaDecode, NotaEncode, NotaRecord, NotaSum};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, NotaSum)]
pub enum ClaviFaberRequest {
    CertificateAuthorityInitialization(CertificateAuthorityInitialization),
    ServerCertificateCreation(ServerCertificateCreation),
    NodeCertificateCreation(NodeCertificateCreation),
    IdentityDirectoryInitialization(IdentityDirectoryInitialization),
    PublicKeyDerivation(PublicKeyDerivation),
    CertificateVerification(CertificateVerification),
    PublicKeyPublicationRequest(PublicKeyPublicationRequest),
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
            Self::CertificateAuthorityInitialization(request) => request.execute(),
            Self::ServerCertificateCreation(request) => request.execute(),
            Self::NodeCertificateCreation(request) => request.execute(),
            Self::IdentityDirectoryInitialization(request) => request.execute().await,
            Self::PublicKeyDerivation(request) => request.execute().await,
            Self::CertificateVerification(request) => request.execute(),
            Self::PublicKeyPublicationRequest(request) => Ok(
                ClaviFaberResponse::PublicKeyPublication(request.collect().await?),
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaSum)]
pub enum ClaviFaberResponse {
    CertificateAuthorityCertificateWritten(CertificateAuthorityCertificateWritten),
    ServerCertificateWritten(ServerCertificateWritten),
    NodeCertificateWritten(NodeCertificateWritten),
    PublicKeyProjection(PublicKeyProjection),
    CertificateChainVerified(CertificateChainVerified),
    PublicKeyPublication(PublicKeyPublication),
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

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct CertificateAuthorityInitialization {
    pub keygrip: String,
    pub common_name: String,
    pub output: String,
}

impl CertificateAuthorityInitialization {
    fn execute(self) -> Result<ClaviFaberResponse> {
        let public_key_bytes = GpgEd25519PublicKey::from_keygrip(&self.keygrip).bytes()?;
        let subject_public_key_info =
            Ed25519SubjectPublicKey::from_bytes(public_key_bytes).subject_public_key_info()?;
        let issuer = CertificateAuthorityIssuer::from_keygrip(self.keygrip);
        let certificate = issuer.self_signed_certificate(
            CertificateAuthorityCertificateRequest::new(self.common_name, subject_public_key_info),
        )?;
        TextFile::from_path(&self.output).write_public(&certificate.to_pem()?)?;
        Ok(ClaviFaberResponse::CertificateAuthorityCertificateWritten(
            CertificateAuthorityCertificateWritten {
                output: self.output,
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct ServerCertificateCreation {
    pub certificate_authority_keygrip: String,
    pub certificate_authority_certificate: String,
    pub common_name: String,
    pub output_certificate: String,
    pub output_private_key: String,
}

impl ServerCertificateCreation {
    fn execute(self) -> Result<ClaviFaberResponse> {
        let certificate_authority =
            TextFile::from_path(&self.certificate_authority_certificate).read_certificate()?;
        let issuer = CertificateAuthorityIssuer::from_keygrip(self.certificate_authority_keygrip);
        let server_certificate = issuer.server_certificate(
            &certificate_authority,
            ServerCertificateSigningRequest::new(self.common_name),
        )?;
        ServerCertificateFiles {
            certificate: TextFile::from_path(&self.output_certificate),
            private_key: TextFile::from_path(&self.output_private_key),
        }
        .write(&server_certificate)?;
        Ok(ClaviFaberResponse::ServerCertificateWritten(
            ServerCertificateWritten {
                certificate: self.output_certificate,
                private_key: self.output_private_key,
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct NodeCertificateCreation {
    pub certificate_authority_keygrip: String,
    pub certificate_authority_certificate: String,
    pub open_ssh_public_key: String,
    pub common_name: String,
    pub output: String,
}

impl NodeCertificateCreation {
    fn execute(self) -> Result<ClaviFaberResponse> {
        let certificate_authority =
            TextFile::from_path(&self.certificate_authority_certificate).read_certificate()?;
        let subject_public_key_info =
            OpenSshPublicKey::from_text(self.open_ssh_public_key)?.subject_public_key_info()?;
        let issuer = CertificateAuthorityIssuer::from_keygrip(self.certificate_authority_keygrip);
        let certificate = issuer.node_certificate(
            &certificate_authority,
            NodeCertificateSigningRequest::new(self.common_name, subject_public_key_info),
        )?;
        TextFile::from_path(&self.output).write_public(&certificate.to_pem()?)?;
        Ok(ClaviFaberResponse::NodeCertificateWritten(
            NodeCertificateWritten {
                output: self.output,
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct IdentityDirectoryInitialization {
    pub directory: String,
}

impl IdentityDirectoryInitialization {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let identity = runtime
            .host_identity
            .ask(EnsureIdentity {
                directory: PathBuf::from(self.directory),
            })
            .await
            .map_err(translate_send_error)?;
        Ok(ClaviFaberResponse::PublicKeyProjection(
            PublicKeyProjection {
                open_ssh_public_key: identity.open_ssh_public_key(),
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct PublicKeyDerivation {
    pub directory: String,
}

impl PublicKeyDerivation {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let directory = PathBuf::from(self.directory);
        let identity = runtime
            .host_identity
            .ask(LoadIdentity {
                directory: directory.clone(),
            })
            .await
            .map_err(translate_send_error)?;
        let projection = runtime
            .ssh_host_key
            .ask(WritePublicKeyProjection {
                directory,
                identity,
            })
            .await
            .map_err(translate_send_error)?;
        Ok(ClaviFaberResponse::PublicKeyProjection(
            PublicKeyProjection {
                open_ssh_public_key: projection.open_ssh_public_key,
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct CertificateVerification {
    pub certificate_authority_certificate: String,
    pub certificate: String,
}

impl CertificateVerification {
    fn execute(self) -> Result<ClaviFaberResponse> {
        let certificate_authority =
            TextFile::from_path(&self.certificate_authority_certificate).read_certificate()?;
        let certificate = TextFile::from_path(&self.certificate).read_certificate()?;
        CertificateChain::from_certificates(&certificate_authority, &certificate).verify()?;
        Ok(ClaviFaberResponse::CertificateChainVerified(
            CertificateChainVerified {
                certificate: self.certificate,
            },
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct CertificateAuthorityCertificateWritten {
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct ServerCertificateWritten {
    pub certificate: String,
    pub private_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct NodeCertificateWritten {
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct PublicKeyProjection {
    pub open_ssh_public_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct CertificateChainVerified {
    pub certificate: String,
}

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

    pub fn inline_request(&self) -> Result<Option<ClaviFaberRequest>> {
        let Some(first) = self.arguments.first() else {
            return Ok(None);
        };
        if !CommandLineArgument::new(first).starts_inline_record() {
            return Ok(None);
        }
        Ok(Some(ClaviFaberRequest::from_nota(
            &self.inline_nota_text()?,
        )?))
    }

    fn inline_nota_text(&self) -> Result<String> {
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

struct CommandLineArgument<'argument> {
    argument: &'argument OsString,
}

impl<'argument> CommandLineArgument<'argument> {
    fn new(argument: &'argument OsString) -> Self {
        Self { argument }
    }

    fn starts_inline_record(&self) -> bool {
        self.argument.to_string_lossy().starts_with('(')
    }
}

struct GpgEd25519PublicKey {
    keygrip: String,
}

impl GpgEd25519PublicKey {
    fn from_keygrip(keygrip: &str) -> Self {
        Self {
            keygrip: keygrip.to_string(),
        }
    }

    fn bytes(&self) -> Result<Vec<u8>> {
        let output = std::process::Command::new("gpg")
            .args(["--batch", "--export-ssh-key", &format!("{}!", self.keygrip)])
            .output()
            .map_err(|error| Error::Gpg(format!("gpg --export-ssh-key: {error}")))?;

        if output.status.success() {
            let open_ssh_public_key_text =
                String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !open_ssh_public_key_text.is_empty() {
                return OpenSshPublicKey::from_text(open_ssh_public_key_text)?.raw_key_bytes();
            }
        }

        let mut agent = GpgAgent::connect()?;
        agent.readkey(&self.keygrip)
    }
}

struct TextFile {
    path: PathBuf,
}

impl TextFile {
    fn from_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn read(&self) -> Result<String> {
        std::fs::read_to_string(&self.path).map_err(|source| Error::Io {
            path: self.path.clone(),
            source,
        })
    }

    fn read_certificate(&self) -> Result<CertificateDer> {
        CertificateDer::from_pem(&self.read()?)
    }

    fn write_public(&self, contents: &str) -> Result<()> {
        AtomicFile::new(self.path.clone()).write_bytes(contents.as_bytes(), 0o644)
    }

    fn write_private(&self, contents: &str) -> Result<()> {
        AtomicFile::new(self.path.clone()).write_bytes(contents.as_bytes(), 0o600)
    }
}

struct ServerCertificateFiles {
    certificate: TextFile,
    private_key: TextFile,
}

impl ServerCertificateFiles {
    fn write(&self, server_certificate: &ServerCertificate) -> Result<()> {
        self.certificate
            .write_public(&server_certificate.certificate().to_pem()?)?;
        self.private_key
            .write_private(server_certificate.private_key_pem())
    }
}
