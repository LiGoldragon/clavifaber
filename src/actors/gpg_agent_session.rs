use crate::actors::trace_recorder::{TraceKind, TraceRecorder, emit};
use crate::error::Error;
use crate::gpg_agent::GpgAgent;
use crate::ssh_key::OpenSshPublicKey;
use kameo::Actor;
use kameo::actor::ActorRef;
use kameo::error::Infallible;
use kameo::message::{Context, Message};
use kameo::reply::DelegatedReply;

pub struct GpgAgentSession {
    tracer: Option<ActorRef<TraceRecorder>>,
}

impl GpgAgentSession {
    pub fn new(tracer: Option<ActorRef<TraceRecorder>>) -> Self {
        Self { tracer }
    }
}

impl Actor for GpgAgentSession {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }
}

pub struct ReadEd25519PublicKey {
    pub keygrip: String,
}

impl Message<ReadEd25519PublicKey> for GpgAgentSession {
    type Reply = DelegatedReply<Result<Vec<u8>, Error>>;

    async fn handle(
        &mut self,
        msg: ReadEd25519PublicKey,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "GpgAgentSession",
            TraceKind::MessageReceived("ReadEd25519PublicKey"),
        )
        .await;
        let tracer = self.tracer.clone();
        let (delegated, sender) = ctx.reply_sender();
        if let Some(tx) = sender {
            tokio::spawn(async move {
                let join = tokio::task::spawn_blocking(move || {
                    let output = std::process::Command::new("gpg")
                        .args(["--batch", "--export-ssh-key", &format!("{}!", msg.keygrip)])
                        .output()
                        .map_err(|error| Error::Gpg(format!("gpg --export-ssh-key: {error}")))?;
                    if output.status.success() {
                        let open_ssh_public_key_text =
                            String::from_utf8_lossy(&output.stdout).trim().to_string();
                        if !open_ssh_public_key_text.is_empty() {
                            return OpenSshPublicKey::from_text(open_ssh_public_key_text)?
                                .raw_key_bytes();
                        }
                    }
                    GpgAgent::connect()?.readkey(&msg.keygrip)
                })
                .await;
                let result = match join {
                    Ok(inner) => inner,
                    Err(_) => Err(Error::Gpg(
                        "blocking gpg-agent task failed to join".to_string(),
                    )),
                };
                emit(
                    tracer.as_ref(),
                    "GpgAgentSession",
                    TraceKind::MessageReplied("ReadEd25519PublicKey"),
                )
                .await;
                tx.send(result);
            });
        }
        delegated
    }
}

pub struct SignSha256Hash {
    pub keygrip: String,
    pub hash_hex: String,
}

impl Message<SignSha256Hash> for GpgAgentSession {
    type Reply = DelegatedReply<Result<Vec<u8>, Error>>;

    async fn handle(
        &mut self,
        msg: SignSha256Hash,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        emit(
            self.tracer.as_ref(),
            "GpgAgentSession",
            TraceKind::MessageReceived("SignSha256Hash"),
        )
        .await;
        let tracer = self.tracer.clone();
        let (delegated, sender) = ctx.reply_sender();
        if let Some(tx) = sender {
            tokio::spawn(async move {
                let join = tokio::task::spawn_blocking(move || {
                    GpgAgent::connect()?.sign(&msg.keygrip, &msg.hash_hex)
                })
                .await;
                let result = match join {
                    Ok(inner) => inner,
                    Err(_) => Err(Error::Gpg(
                        "blocking gpg-agent task failed to join".to_string(),
                    )),
                };
                emit(
                    tracer.as_ref(),
                    "GpgAgentSession",
                    TraceKind::MessageReplied("SignSha256Hash"),
                )
                .await;
                tx.send(result);
            });
        }
        delegated
    }
}
