use crate::actors::trace_recorder::{TraceKind, TraceRecorder, emit};
use crate::error::Error;
use crate::identity::{IdentityDirectory, NodeIdentity};
use kameo::Actor;
use kameo::actor::ActorRef;
use kameo::error::Infallible;
use kameo::message::{Context, Message};
use std::path::PathBuf;

pub struct HostIdentity {
    tracer: Option<ActorRef<TraceRecorder>>,
}

impl HostIdentity {
    pub fn new(tracer: Option<ActorRef<TraceRecorder>>) -> Self {
        Self { tracer }
    }
}

impl Actor for HostIdentity {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }
}

#[derive(Debug)]
pub struct EnsureIdentity {
    pub directory: PathBuf,
}

impl Message<EnsureIdentity> for HostIdentity {
    type Reply = Result<NodeIdentity, Error>;

    async fn handle(
        &mut self,
        msg: EnsureIdentity,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "HostIdentity",
            TraceKind::MessageReceived("EnsureIdentity"),
        )
        .await;
        let directory = IdentityDirectory::from_path(msg.directory);
        let identity = match directory.existing_identity()? {
            Some(identity) => identity,
            None => {
                let identity = NodeIdentity::generate();
                directory.write_identity(&identity)?;
                identity
            }
        };
        emit(
            self.tracer.as_ref(),
            "HostIdentity",
            TraceKind::MessageReplied("EnsureIdentity"),
        )
        .await;
        Ok(identity)
    }
}

#[derive(Debug)]
pub struct LoadIdentity {
    pub directory: PathBuf,
}

impl Message<LoadIdentity> for HostIdentity {
    type Reply = Result<NodeIdentity, Error>;

    async fn handle(
        &mut self,
        msg: LoadIdentity,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "HostIdentity",
            TraceKind::MessageReceived("LoadIdentity"),
        )
        .await;
        let directory = IdentityDirectory::from_path(msg.directory);
        let identity = directory.load_identity()?;
        emit(
            self.tracer.as_ref(),
            "HostIdentity",
            TraceKind::MessageReplied("LoadIdentity"),
        )
        .await;
        Ok(identity)
    }
}

#[derive(Debug)]
pub struct WritePublicKeyProjection {
    pub directory: PathBuf,
    pub identity: NodeIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKeyProjectionWritten {
    pub open_ssh_public_key: String,
}

impl Message<WritePublicKeyProjection> for HostIdentity {
    type Reply = Result<PublicKeyProjectionWritten, Error>;

    async fn handle(
        &mut self,
        msg: WritePublicKeyProjection,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "HostIdentity",
            TraceKind::MessageReceived("WritePublicKeyProjection"),
        )
        .await;
        let directory = IdentityDirectory::from_path(msg.directory);
        directory.write_public_key(&msg.identity)?;
        let open_ssh_public_key = msg.identity.open_ssh_public_key();
        emit(
            self.tracer.as_ref(),
            "HostIdentity",
            TraceKind::MessageReplied("WritePublicKeyProjection"),
        )
        .await;
        Ok(PublicKeyProjectionWritten {
            open_ssh_public_key,
        })
    }
}
