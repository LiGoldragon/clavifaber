use crate::actors::certificate_issuer::{
    IssueCertificateAuthority, IssueNodeCertificate, IssueServerCertificate, VerifyCertificateChain,
};
use crate::actors::gpg_agent_session::ReadEd25519PublicKey;
use crate::actors::host_identity::{EnsureIdentity, LoadIdentity};
use crate::actors::publication_collector::CollectPublication;
use crate::actors::runtime_root::RuntimeRoot;
use crate::actors::ssh_host_key::WritePublicKeyProjection;
use crate::actors::translate_send_error;
use crate::actors::wifi_certificate::{
    EnsureWifiClientCertificate, EnsureWifiServerCertificate, WifiClientCertificatePlan,
    WifiServerCertificatePlan,
};
use crate::error::{Error, Result};
use crate::publication::{PublicKeyPublication, PublicKeyPublicationRequest, yggdrasil_projection};
use crate::ssh_key::OpenSshPublicKey;
use crate::state::{ConvergenceLedgerEntry, InputHash, State};
use crate::util::AtomicFile;
use crate::x509::{
    CertificateAuthorityCertificateRequest, CertificateDer, Ed25519SubjectPublicKey,
    NodeCertificateSigningRequest, ServerCertificate, ServerCertificateSigningRequest,
};
use crate::yggdrasil::YggdrasilPlan;
use nota_codec::{Decoder, Encoder, NotaDecode, NotaEncode, NotaRecord, NotaSum};
use std::ffi::OsString;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, NotaSum)]
#[allow(clippy::large_enum_variant)]
pub enum ClaviFaberRequest {
    CertificateAuthorityInitialization(CertificateAuthorityInitialization),
    ServerCertificateCreation(ServerCertificateCreation),
    NodeCertificateCreation(NodeCertificateCreation),
    IdentityDirectoryInitialization(IdentityDirectoryInitialization),
    PublicKeyDerivation(PublicKeyDerivation),
    CertificateVerification(CertificateVerification),
    PublicKeyPublicationRequest(PublicKeyPublicationRequest),
    Converge(Converge),
    InspectState(InspectState),
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
            Self::CertificateAuthorityInitialization(request) => request.execute().await,
            Self::ServerCertificateCreation(request) => request.execute().await,
            Self::NodeCertificateCreation(request) => request.execute().await,
            Self::IdentityDirectoryInitialization(request) => request.execute().await,
            Self::PublicKeyDerivation(request) => request.execute().await,
            Self::CertificateVerification(request) => request.execute().await,
            Self::PublicKeyPublicationRequest(request) => Ok(
                ClaviFaberResponse::PublicKeyPublication(request.collect().await?),
            ),
            Self::Converge(request) => request.execute().await,
            Self::InspectState(request) => request.execute(),
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
    ConvergenceComplete(ConvergenceComplete),
    StateReport(StateReport),
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
    async fn execute(self) -> Result<ClaviFaberResponse> {
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
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let certificate_authority =
            TextFile::from_path(&self.certificate_authority_certificate).read_certificate()?;
        let server_certificate = runtime
            .certificate_issuer
            .ask(IssueServerCertificate {
                keygrip: self.certificate_authority_keygrip,
                certificate_authority,
                request: ServerCertificateSigningRequest::new(self.common_name),
            })
            .await
            .map_err(translate_send_error)?;
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
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let certificate_authority =
            TextFile::from_path(&self.certificate_authority_certificate).read_certificate()?;
        let subject_public_key_info =
            OpenSshPublicKey::from_text(self.open_ssh_public_key)?.subject_public_key_info()?;
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
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let runtime = RuntimeRoot::start(None);
        let certificate_authority =
            TextFile::from_path(&self.certificate_authority_certificate).read_certificate()?;
        let certificate = TextFile::from_path(&self.certificate).read_certificate()?;
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

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct Converge {
    pub identity_directory: String,
    pub node_name: String,
    pub publication_output: String,
    pub yggdrasil: Option<YggdrasilPlan>,
    pub wifi_client_certificate_pem: Option<String>,
    pub state_database: String,
    pub certificate_authority: Option<CertificateAuthorityPlan>,
    pub server_certificate: Option<ServerCertificatePlan>,
    pub node_certificates: Vec<NodeCertificatePlan>,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct CertificateAuthorityPlan {
    pub keygrip: String,
    pub common_name: String,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct ServerCertificatePlan {
    pub keygrip: String,
    pub certificate_authority: String,
    pub common_name: String,
    pub output_certificate: String,
    pub output_private_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct NodeCertificatePlan {
    pub keygrip: String,
    pub certificate_authority: String,
    pub open_ssh_public_key: String,
    pub common_name: String,
    pub output: String,
}

impl Converge {
    async fn execute(self) -> Result<ClaviFaberResponse> {
        let state = State::open(&self.state_database)?;
        let plan = self.plan_bytes()?;
        let current_hash = InputHash::of_bytes(&plan);
        if let Some(entry) = state.read_converge_entry()?
            && entry.last_input_hash == current_hash
        {
            return Ok(ClaviFaberResponse::ConvergenceComplete(
                ConvergenceComplete {
                    publication_output: self.publication_output,
                    work_performed: false,
                },
            ));
        }
        self.run_actors().await?;
        state.record_converge(&ConvergenceLedgerEntry {
            last_input_hash: current_hash,
        })?;
        Ok(ClaviFaberResponse::ConvergenceComplete(
            ConvergenceComplete {
                publication_output: self.publication_output,
                work_performed: true,
            },
        ))
    }

    async fn run_actors(&self) -> Result<()> {
        let runtime = RuntimeRoot::start(None);
        let directory = PathBuf::from(&self.identity_directory);
        runtime
            .host_identity
            .ask(EnsureIdentity {
                directory: directory.clone(),
            })
            .await
            .map_err(translate_send_error)?;
        if let Some(plan) = &self.certificate_authority {
            converge_certificate_authority(&runtime, plan).await?;
        }
        if let Some(plan) = &self.server_certificate {
            runtime
                .wifi_certificate
                .ask(EnsureWifiServerCertificate {
                    plan: WifiServerCertificatePlan {
                        keygrip: plan.keygrip.clone(),
                        certificate_authority: PathBuf::from(&plan.certificate_authority),
                        common_name: plan.common_name.clone(),
                        output_certificate: PathBuf::from(&plan.output_certificate),
                        output_private_key: PathBuf::from(&plan.output_private_key),
                    },
                })
                .await
                .map_err(translate_send_error)?;
        }
        for plan in &self.node_certificates {
            runtime
                .wifi_certificate
                .ask(EnsureWifiClientCertificate {
                    plan: WifiClientCertificatePlan {
                        keygrip: plan.keygrip.clone(),
                        certificate_authority: PathBuf::from(&plan.certificate_authority),
                        open_ssh_public_key: plan.open_ssh_public_key.clone(),
                        common_name: plan.common_name.clone(),
                        output: PathBuf::from(&plan.output),
                    },
                })
                .await
                .map_err(translate_send_error)?;
        }
        let yggdrasil = match &self.yggdrasil {
            Some(plan) => Some(yggdrasil_projection(&runtime, plan.clone()).await?),
            None => None,
        };
        let publication = runtime
            .publication_collector
            .ask(CollectPublication {
                node_name: self.node_name.clone(),
                directory,
                yggdrasil,
                wifi_client_certificate_pem: self.wifi_client_certificate_pem.clone(),
            })
            .await
            .map_err(translate_send_error)?;
        let mut encoder = Encoder::new();
        publication.encode(&mut encoder)?;
        let publication_text = encoder.into_string();
        AtomicFile::new(PathBuf::from(&self.publication_output))
            .write_bytes(publication_text.as_bytes(), 0o644)?;
        Ok(())
    }

    fn plan_bytes(&self) -> Result<Vec<u8>> {
        let mut encoder = Encoder::new();
        self.encode(&mut encoder)?;
        Ok(encoder.into_string().into_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct ConvergenceComplete {
    pub publication_output: String,
    pub work_performed: bool,
}

async fn converge_certificate_authority(
    runtime: &RuntimeRoot,
    plan: &CertificateAuthorityPlan,
) -> Result<()> {
    let public_key_bytes = runtime
        .gpg_agent_session
        .ask(ReadEd25519PublicKey {
            keygrip: plan.keygrip.clone(),
        })
        .await
        .map_err(translate_send_error)?;
    let subject_public_key_info =
        Ed25519SubjectPublicKey::from_bytes(public_key_bytes).subject_public_key_info()?;
    let certificate = runtime
        .certificate_issuer
        .ask(IssueCertificateAuthority {
            keygrip: plan.keygrip.clone(),
            request: CertificateAuthorityCertificateRequest::new(
                plan.common_name.clone(),
                subject_public_key_info,
            ),
        })
        .await
        .map_err(translate_send_error)?;
    TextFile::from_path(&plan.output).write_public(&certificate.to_pem()?)
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct InspectState {
    pub state_database: String,
}

impl InspectState {
    fn execute(self) -> Result<ClaviFaberResponse> {
        let state = State::open(&self.state_database)?;
        let entry = state.read_converge_entry()?;
        Ok(ClaviFaberResponse::StateReport(StateReport {
            converge: entry.map(|entry| ConvergeLedger {
                last_input_hash_hex: hex::encode(entry.last_input_hash.0),
            }),
        }))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct StateReport {
    pub converge: Option<ConvergeLedger>,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct ConvergeLedger {
    pub last_input_hash_hex: String,
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
