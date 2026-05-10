use crate::actors::trace_recorder::{TraceKind, TraceRecorder, emit};
use crate::error::Error;
use crate::yggdrasil::{YggdrasilKeypairFile, YggdrasilProjection};
use kameo::Actor;
use kameo::actor::ActorRef;
use kameo::error::Infallible;
use kameo::message::{Context, Message};
use kameo::reply::DelegatedReply;
use std::path::PathBuf;

pub struct YggdrasilKey {
    yggdrasil_binary: String,
    tracer: Option<ActorRef<TraceRecorder>>,
}

impl YggdrasilKey {
    pub fn new(tracer: Option<ActorRef<TraceRecorder>>) -> Self {
        let yggdrasil_binary =
            std::env::var("CLAVIFABER_YGGDRASIL_BIN").unwrap_or_else(|_| "yggdrasil".to_string());
        Self {
            yggdrasil_binary,
            tracer,
        }
    }
}

impl Actor for YggdrasilKey {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }
}

#[derive(Debug)]
pub struct EnsureYggdrasilIdentity {
    pub keypair_path: PathBuf,
}

impl Message<EnsureYggdrasilIdentity> for YggdrasilKey {
    type Reply = DelegatedReply<Result<(), Error>>;

    async fn handle(
        &mut self,
        msg: EnsureYggdrasilIdentity,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "YggdrasilKey",
            TraceKind::MessageReceived("EnsureYggdrasilIdentity"),
        )
        .await;
        let tracer = self.tracer.clone();
        let yggdrasil_binary = self.yggdrasil_binary.clone();
        let (delegated, sender) = ctx.reply_sender();
        if let Some(tx) = sender {
            tokio::spawn(async move {
                let join = tokio::task::spawn_blocking(move || {
                    YggdrasilKeypairFile::from_path(msg.keypair_path).ensure(&yggdrasil_binary)
                })
                .await;
                let result = match join {
                    Ok(inner) => inner,
                    Err(_) => Err(Error::Yggdrasil(
                        "blocking yggdrasil task failed to join".to_string(),
                    )),
                };
                emit(
                    tracer.as_ref(),
                    "YggdrasilKey",
                    TraceKind::MessageReplied("EnsureYggdrasilIdentity"),
                )
                .await;
                tx.send(result);
            });
        }
        delegated
    }
}

#[derive(Debug)]
pub struct ReadYggdrasilProjection {
    pub keypair_path: PathBuf,
}

impl Message<ReadYggdrasilProjection> for YggdrasilKey {
    type Reply = DelegatedReply<Result<YggdrasilProjection, Error>>;

    async fn handle(
        &mut self,
        msg: ReadYggdrasilProjection,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "YggdrasilKey",
            TraceKind::MessageReceived("ReadYggdrasilProjection"),
        )
        .await;
        let tracer = self.tracer.clone();
        let yggdrasil_binary = self.yggdrasil_binary.clone();
        let (delegated, sender) = ctx.reply_sender();
        if let Some(tx) = sender {
            tokio::spawn(async move {
                let join = tokio::task::spawn_blocking(move || {
                    YggdrasilKeypairFile::from_path(msg.keypair_path).projection(&yggdrasil_binary)
                })
                .await;
                let result = match join {
                    Ok(inner) => inner,
                    Err(_) => Err(Error::Yggdrasil(
                        "blocking yggdrasil task failed to join".to_string(),
                    )),
                };
                emit(
                    tracer.as_ref(),
                    "YggdrasilKey",
                    TraceKind::MessageReplied("ReadYggdrasilProjection"),
                )
                .await;
                tx.send(result);
            });
        }
        delegated
    }
}
