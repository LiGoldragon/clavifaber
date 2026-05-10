use crate::actors::gpg_agent_session::GpgAgentSession;
use crate::actors::trace_recorder::TraceRecorder;
use kameo::Actor;
use kameo::actor::ActorRef;
use kameo::error::Infallible;

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

    pub fn gpg_agent_session(&self) -> &ActorRef<GpgAgentSession> {
        &self.gpg_agent_session
    }

    pub fn tracer(&self) -> Option<&ActorRef<TraceRecorder>> {
        self.tracer.as_ref()
    }
}

impl Actor for CertificateIssuer {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }
}
