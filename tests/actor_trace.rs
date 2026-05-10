use clavifaber::actors::runtime_root::RuntimeRoot;
use clavifaber::actors::trace_recorder::{ReportTrace, TraceEvent, TraceKind, TraceRecorder};
use clavifaber::actors::yggdrasil_key::{EnsureYggdrasilIdentity, ReadYggdrasilProjection};
use kameo::actor::{ActorRef, Spawn};

struct Fixture {
    runtime: RuntimeRoot,
    tracer: ActorRef<TraceRecorder>,
}

impl Fixture {
    async fn start() -> Self {
        let tracer = TraceRecorder::spawn(TraceRecorder::new());
        let runtime = RuntimeRoot::start(Some(tracer.clone()));
        Self { runtime, tracer }
    }

    async fn trace(&self) -> Vec<TraceEvent> {
        self.tracer.ask(ReportTrace).await.expect("trace report")
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn yggdrasil_projection_runs_ensure_then_read() {
    let fixture = Fixture::start().await;
    let temporary_directory = tempfile::tempdir().expect("tempdir");
    let keypair_path = temporary_directory.path().join("yggdrasil/keypair.json");

    fixture
        .runtime
        .yggdrasil_key
        .ask(EnsureYggdrasilIdentity {
            keypair_path: keypair_path.clone(),
        })
        .await
        .expect("EnsureYggdrasilIdentity reply");

    fixture
        .runtime
        .yggdrasil_key
        .ask(ReadYggdrasilProjection {
            keypair_path: keypair_path.clone(),
        })
        .await
        .expect("ReadYggdrasilProjection reply");

    let trace = fixture.trace().await;
    let ensure_position = trace
        .iter()
        .position(|event| {
            event.actor == "YggdrasilKey"
                && matches!(
                    event.kind,
                    TraceKind::MessageReceived("EnsureYggdrasilIdentity")
                )
        })
        .expect("YggdrasilKey.EnsureYggdrasilIdentity received");
    let read_position = trace
        .iter()
        .position(|event| {
            event.actor == "YggdrasilKey"
                && matches!(
                    event.kind,
                    TraceKind::MessageReceived("ReadYggdrasilProjection")
                )
        })
        .expect("YggdrasilKey.ReadYggdrasilProjection received");
    assert!(
        ensure_position < read_position,
        "YggdrasilKey.EnsureYggdrasilIdentity must precede ReadYggdrasilProjection: {trace:?}"
    );
}
