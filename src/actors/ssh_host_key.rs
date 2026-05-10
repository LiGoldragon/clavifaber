use crate::actors::trace_recorder::{TraceKind, TraceRecorder, emit};
use crate::error::Error;
use crate::identity::{IdentityDirectory, NodeIdentity};
use kameo::Actor;
use kameo::actor::ActorRef;
use kameo::error::Infallible;
use kameo::message::{Context, Message};
use std::path::PathBuf;

pub struct SshHostKey {
    tracer: Option<ActorRef<TraceRecorder>>,
}

impl SshHostKey {
    pub fn new(tracer: Option<ActorRef<TraceRecorder>>) -> Self {
        Self { tracer }
    }
}

impl Actor for SshHostKey {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
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

impl Message<WritePublicKeyProjection> for SshHostKey {
    type Reply = Result<PublicKeyProjectionWritten, Error>;

    async fn handle(
        &mut self,
        msg: WritePublicKeyProjection,
        _: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "SshHostKey",
            TraceKind::MessageReceived("WritePublicKeyProjection"),
        )
        .await;
        let directory = IdentityDirectory::from_path(msg.directory);
        directory.write_public_key(&msg.identity)?;
        let open_ssh_public_key = msg.identity.open_ssh_public_key();
        emit(
            self.tracer.as_ref(),
            "SshHostKey",
            TraceKind::MessageReplied("WritePublicKeyProjection"),
        )
        .await;
        Ok(PublicKeyProjectionWritten {
            open_ssh_public_key,
        })
    }
}
