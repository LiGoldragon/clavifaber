use crate::actors::certificate_issuer::{
    CertificateIssuer, IssueNodeCertificate, IssueServerCertificate,
};
use crate::actors::trace_recorder::{TraceKind, TraceRecorder, emit};
use crate::actors::translate_send_error;
use crate::error::Error;
use crate::ssh_key::OpenSshPublicKey;
use crate::util::AtomicFile;
use crate::x509::{
    CertificateDer, NodeCertificateSigningRequest, ServerCertificate,
    ServerCertificateSigningRequest,
};
use kameo::Actor;
use kameo::actor::ActorRef;
use kameo::error::Infallible;
use kameo::message::{Context, Message};
use std::path::{Path, PathBuf};

pub struct WifiCertificate {
    certificate_issuer: ActorRef<CertificateIssuer>,
    tracer: Option<ActorRef<TraceRecorder>>,
}

impl WifiCertificate {
    pub fn new(
        certificate_issuer: ActorRef<CertificateIssuer>,
        tracer: Option<ActorRef<TraceRecorder>>,
    ) -> Self {
        Self {
            certificate_issuer,
            tracer,
        }
    }
}

impl Actor for WifiCertificate {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Infallible> {
        Ok(args)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiServerCertificatePlan {
    pub keygrip: String,
    pub certificate_authority: PathBuf,
    pub common_name: String,
    pub output_certificate: PathBuf,
    pub output_private_key: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiClientCertificatePlan {
    pub keygrip: String,
    pub certificate_authority: PathBuf,
    pub open_ssh_public_key: String,
    pub common_name: String,
    pub output: PathBuf,
}

#[derive(Debug)]
pub struct EnsureWifiServerCertificate {
    pub plan: WifiServerCertificatePlan,
}

impl Message<EnsureWifiServerCertificate> for WifiCertificate {
    type Reply = Result<(), Error>;

    async fn handle(
        &mut self,
        msg: EnsureWifiServerCertificate,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "WifiCertificate",
            TraceKind::MessageReceived("EnsureWifiServerCertificate"),
        )
        .await;
        let plan = msg.plan;
        if plan.output_certificate.exists() && plan.output_private_key.exists() {
            emit(
                self.tracer.as_ref(),
                "WifiCertificate",
                TraceKind::MessageReplied("EnsureWifiServerCertificate"),
            )
            .await;
            return Ok(());
        }
        let certificate_authority = read_certificate(&plan.certificate_authority)?;
        let server_certificate = self
            .certificate_issuer
            .ask(IssueServerCertificate {
                keygrip: plan.keygrip,
                certificate_authority,
                request: ServerCertificateSigningRequest::new(plan.common_name),
            })
            .await
            .map_err(translate_send_error)?;
        write_server_certificate(
            &plan.output_certificate,
            &plan.output_private_key,
            &server_certificate,
        )?;
        emit(
            self.tracer.as_ref(),
            "WifiCertificate",
            TraceKind::MessageReplied("EnsureWifiServerCertificate"),
        )
        .await;
        Ok(())
    }
}

#[derive(Debug)]
pub struct EnsureWifiClientCertificate {
    pub plan: WifiClientCertificatePlan,
}

impl Message<EnsureWifiClientCertificate> for WifiCertificate {
    type Reply = Result<(), Error>;

    async fn handle(
        &mut self,
        msg: EnsureWifiClientCertificate,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "WifiCertificate",
            TraceKind::MessageReceived("EnsureWifiClientCertificate"),
        )
        .await;
        let plan = msg.plan;
        if plan.output.exists() {
            emit(
                self.tracer.as_ref(),
                "WifiCertificate",
                TraceKind::MessageReplied("EnsureWifiClientCertificate"),
            )
            .await;
            return Ok(());
        }
        let certificate_authority = read_certificate(&plan.certificate_authority)?;
        let subject_public_key_info =
            OpenSshPublicKey::from_text(plan.open_ssh_public_key)?.subject_public_key_info()?;
        let certificate = self
            .certificate_issuer
            .ask(IssueNodeCertificate {
                keygrip: plan.keygrip,
                certificate_authority,
                request: NodeCertificateSigningRequest::new(
                    plan.common_name,
                    subject_public_key_info,
                ),
            })
            .await
            .map_err(translate_send_error)?;
        AtomicFile::new(plan.output).write_bytes(certificate.to_pem()?.as_bytes(), 0o644)?;
        emit(
            self.tracer.as_ref(),
            "WifiCertificate",
            TraceKind::MessageReplied("EnsureWifiClientCertificate"),
        )
        .await;
        Ok(())
    }
}

fn read_certificate(path: &Path) -> Result<CertificateDer, Error> {
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
) -> Result<(), Error> {
    AtomicFile::new(certificate_path.to_path_buf())
        .write_bytes(server_certificate.certificate().to_pem()?.as_bytes(), 0o644)?;
    AtomicFile::new(private_key_path.to_path_buf())
        .write_bytes(server_certificate.private_key_pem().as_bytes(), 0o600)
}
