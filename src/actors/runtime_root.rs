use crate::actors::certificate_issuer::CertificateIssuer;
use crate::actors::gpg_agent_session::GpgAgentSession;
use crate::actors::host_identity::HostIdentity;
use crate::actors::publication_collector::PublicationCollector;
use crate::actors::ssh_host_key::SshHostKey;
use crate::actors::trace_recorder::TraceRecorder;
use crate::actors::yggdrasil_key::YggdrasilKey;
use kameo::Actor;
use kameo::actor::{ActorRef, Spawn};
use kameo::error::Infallible;

pub struct RuntimeRoot {
    pub host_identity: ActorRef<HostIdentity>,
    pub ssh_host_key: ActorRef<SshHostKey>,
    pub gpg_agent_session: ActorRef<GpgAgentSession>,
    pub certificate_issuer: ActorRef<CertificateIssuer>,
    pub publication_collector: ActorRef<PublicationCollector>,
    pub yggdrasil_key: ActorRef<YggdrasilKey>,
    pub tracer: Option<ActorRef<TraceRecorder>>,
}

impl RuntimeRoot {
    pub fn start(tracer: Option<ActorRef<TraceRecorder>>) -> Self {
        let host_identity = HostIdentity::spawn(HostIdentity::new(tracer.clone()));
        let ssh_host_key = SshHostKey::spawn(SshHostKey::new(tracer.clone()));
        let gpg_agent_session = GpgAgentSession::spawn(GpgAgentSession::new(tracer.clone()));
        let certificate_issuer = CertificateIssuer::spawn(CertificateIssuer::new(
            gpg_agent_session.clone(),
            tracer.clone(),
        ));
        let publication_collector = PublicationCollector::spawn(PublicationCollector::new(
            host_identity.clone(),
            tracer.clone(),
        ));
        let yggdrasil_key = YggdrasilKey::spawn(YggdrasilKey::new(tracer.clone()));
        Self {
            host_identity,
            ssh_host_key,
            gpg_agent_session,
            certificate_issuer,
            publication_collector,
            yggdrasil_key,
            tracer,
        }
    }
}

pub struct RuntimeRootSupervisor {
    children: RuntimeRoot,
}

impl RuntimeRootSupervisor {
    pub fn into_children(self) -> RuntimeRoot {
        self.children
    }
}

impl Actor for RuntimeRootSupervisor {
    type Args = Option<ActorRef<TraceRecorder>>;
    type Error = Infallible;

    async fn on_start(args: Self::Args, _: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(Self {
            children: RuntimeRoot::start(args),
        })
    }
}
