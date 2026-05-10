use crate::actors::host_identity::{HostIdentity, LoadIdentity};
use crate::actors::trace_recorder::{TraceKind, TraceRecorder, emit};
use crate::error::Error;
use crate::publication::PublicKeyPublication;
use crate::yggdrasil::YggdrasilProjection;
use kameo::Actor;
use kameo::actor::ActorRef;
use kameo::error::{Infallible, SendError};
use kameo::message::{Context, Message};
use std::path::PathBuf;

pub struct PublicationCollector {
    host_identity: ActorRef<HostIdentity>,
    tracer: Option<ActorRef<TraceRecorder>>,
}

impl PublicationCollector {
    pub fn new(
        host_identity: ActorRef<HostIdentity>,
        tracer: Option<ActorRef<TraceRecorder>>,
    ) -> Self {
        Self {
            host_identity,
            tracer,
        }
    }
}

impl Actor for PublicationCollector {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }
}

#[derive(Debug)]
pub struct CollectPublication {
    pub node_name: String,
    pub directory: PathBuf,
    pub yggdrasil: Option<YggdrasilProjection>,
    pub wifi_client_certificate_pem: Option<String>,
}

impl Message<CollectPublication> for PublicationCollector {
    type Reply = Result<PublicKeyPublication, Error>;

    async fn handle(
        &mut self,
        msg: CollectPublication,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "PublicationCollector",
            TraceKind::MessageReceived("CollectPublication"),
        )
        .await;
        let identity = match self
            .host_identity
            .ask(LoadIdentity {
                directory: msg.directory,
            })
            .await
        {
            Ok(identity) => identity,
            Err(SendError::HandlerError(error)) => return Err(error),
            Err(other) => return Err(Error::Parse(format!("host identity unavailable: {other}"))),
        };
        let (yggdrasil_address, yggdrasil_public_key) = match msg.yggdrasil {
            Some(projection) => (Some(projection.address), Some(projection.public_key)),
            None => (None, None),
        };
        let publication = PublicKeyPublication {
            node_name: msg.node_name,
            open_ssh_public_key: identity.open_ssh_public_key(),
            yggdrasil_address,
            yggdrasil_public_key,
            wifi_client_certificate_pem: msg.wifi_client_certificate_pem,
        };
        emit(
            self.tracer.as_ref(),
            "PublicationCollector",
            TraceKind::MessageReplied("CollectPublication"),
        )
        .await;
        Ok(publication)
    }
}
