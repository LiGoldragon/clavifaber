use crate::actors::gpg_agent_session::{GpgAgentSession, SignSha256Hash};
use crate::actors::trace_recorder::{TraceKind, TraceRecorder, emit};
use crate::actors::translate_send_error;
use crate::error::Error;
use crate::x509::{
    CertificateAuthorityCertificateRequest, CertificateAuthorityIssuer, CertificateChain,
    CertificateDer, NodeCertificateSigningRequest, ServerCertificate,
    ServerCertificateSigningRequest,
};
use kameo::Actor;
use kameo::actor::ActorRef;
use kameo::error::Infallible;
use kameo::message::{Context, Message};

pub struct CertificateIssuer {
    gpg_agent_session: ActorRef<GpgAgentSession>,
    tracer: Option<ActorRef<TraceRecorder>>,
}

impl CertificateIssuer {
    pub fn new(
        gpg_agent_session: ActorRef<GpgAgentSession>,
        tracer: Option<ActorRef<TraceRecorder>>,
    ) -> Self {
        Self {
            gpg_agent_session,
            tracer,
        }
    }
}

impl Actor for CertificateIssuer {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }
}

#[derive(Debug)]
pub struct IssueCertificateAuthority {
    pub keygrip: String,
    pub request: CertificateAuthorityCertificateRequest,
}

impl Message<IssueCertificateAuthority> for CertificateIssuer {
    type Reply = Result<CertificateDer, Error>;

    async fn handle(
        &mut self,
        msg: IssueCertificateAuthority,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "CertificateIssuer",
            TraceKind::MessageReceived("IssueCertificateAuthority"),
        )
        .await;
        let signer = make_signer(&self.gpg_agent_session, msg.keygrip);
        let certificate = CertificateAuthorityIssuer::new()
            .self_signed_certificate(msg.request, signer)
            .await?;
        emit(
            self.tracer.as_ref(),
            "CertificateIssuer",
            TraceKind::MessageReplied("IssueCertificateAuthority"),
        )
        .await;
        Ok(certificate)
    }
}

#[derive(Debug)]
pub struct IssueServerCertificate {
    pub keygrip: String,
    pub certificate_authority: CertificateDer,
    pub request: ServerCertificateSigningRequest,
}

impl Message<IssueServerCertificate> for CertificateIssuer {
    type Reply = Result<ServerCertificate, Error>;

    async fn handle(
        &mut self,
        msg: IssueServerCertificate,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "CertificateIssuer",
            TraceKind::MessageReceived("IssueServerCertificate"),
        )
        .await;
        let signer = make_signer(&self.gpg_agent_session, msg.keygrip);
        let server_certificate = CertificateAuthorityIssuer::new()
            .server_certificate(&msg.certificate_authority, msg.request, signer)
            .await?;
        emit(
            self.tracer.as_ref(),
            "CertificateIssuer",
            TraceKind::MessageReplied("IssueServerCertificate"),
        )
        .await;
        Ok(server_certificate)
    }
}

#[derive(Debug)]
pub struct IssueNodeCertificate {
    pub keygrip: String,
    pub certificate_authority: CertificateDer,
    pub request: NodeCertificateSigningRequest,
}

impl Message<IssueNodeCertificate> for CertificateIssuer {
    type Reply = Result<CertificateDer, Error>;

    async fn handle(
        &mut self,
        msg: IssueNodeCertificate,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "CertificateIssuer",
            TraceKind::MessageReceived("IssueNodeCertificate"),
        )
        .await;
        let signer = make_signer(&self.gpg_agent_session, msg.keygrip);
        let certificate = CertificateAuthorityIssuer::new()
            .node_certificate(&msg.certificate_authority, msg.request, signer)
            .await?;
        emit(
            self.tracer.as_ref(),
            "CertificateIssuer",
            TraceKind::MessageReplied("IssueNodeCertificate"),
        )
        .await;
        Ok(certificate)
    }
}

#[derive(Debug)]
pub struct VerifyCertificateChain {
    pub certificate_authority: CertificateDer,
    pub certificate: CertificateDer,
}

impl Message<VerifyCertificateChain> for CertificateIssuer {
    type Reply = Result<(), Error>;

    async fn handle(
        &mut self,
        msg: VerifyCertificateChain,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "CertificateIssuer",
            TraceKind::MessageReceived("VerifyCertificateChain"),
        )
        .await;
        CertificateChain::from_certificates(&msg.certificate_authority, &msg.certificate)
            .verify()?;
        emit(
            self.tracer.as_ref(),
            "CertificateIssuer",
            TraceKind::MessageReplied("VerifyCertificateChain"),
        )
        .await;
        Ok(())
    }
}

type SignerFuture =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, Error>> + Send>>;

fn make_signer(
    gpg_agent_session: &ActorRef<GpgAgentSession>,
    keygrip: String,
) -> impl FnOnce(String) -> SignerFuture {
    let session = gpg_agent_session.clone();
    move |hash_hex| {
        Box::pin(async move {
            session
                .ask(SignSha256Hash { keygrip, hash_hex })
                .await
                .map_err(translate_send_error)
        })
    }
}
