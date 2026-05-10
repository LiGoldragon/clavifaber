use kameo::Actor;
use kameo::actor::ActorRef;
use kameo::error::Infallible;
use kameo::message::{Context, Message};

pub struct TraceRecorder {
    events: Vec<TraceEvent>,
}

impl TraceRecorder {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }
}

impl Default for TraceRecorder {
    fn default() -> Self {
        Self::new()
    }
}

impl Actor for TraceRecorder {
    type Args = Self;
    type Error = Infallible;

    async fn on_start(args: Self, _: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(args)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceEvent {
    pub actor: &'static str,
    pub kind: TraceKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TraceKind {
    MessageReceived(&'static str),
    MessageReplied(&'static str),
}

impl Message<TraceEvent> for TraceRecorder {
    type Reply = ();

    async fn handle(&mut self, msg: TraceEvent, _: &mut Context<Self, Self::Reply>) {
        self.events.push(msg);
    }
}

pub struct ReportTrace;

impl Message<ReportTrace> for TraceRecorder {
    type Reply = Vec<TraceEvent>;

    async fn handle(&mut self, _: ReportTrace, _: &mut Context<Self, Self::Reply>) -> Self::Reply {
        self.events.clone()
    }
}

pub async fn emit(tracer: Option<&ActorRef<TraceRecorder>>, actor: &'static str, kind: TraceKind) {
    if let Some(recorder) = tracer {
        let _ = recorder.tell(TraceEvent { actor, kind }).await;
    }
}
