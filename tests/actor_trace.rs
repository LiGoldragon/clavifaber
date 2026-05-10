use clavifaber::actors::host_identity::{EnsureIdentity, LoadIdentity, WritePublicKeyProjection};
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
async fn ensure_identity_witness_records_host_identity_receive_and_reply() {
    let fixture = Fixture::start().await;
    let temporary_directory = tempfile::tempdir().expect("tempdir");
    let directory = temporary_directory.path().join("identity");

    fixture
        .runtime
        .host_identity
        .ask(EnsureIdentity {
            directory: directory.clone(),
        })
        .await
        .expect("EnsureIdentity reply");

    let trace = fixture.trace().await;
    assert!(
        trace.iter().any(|event| event.actor == "HostIdentity"
            && matches!(event.kind, TraceKind::MessageReceived("EnsureIdentity"))),
        "trace missing HostIdentity.EnsureIdentity received: {trace:?}"
    );
    assert!(
        trace.iter().any(|event| event.actor == "HostIdentity"
            && matches!(event.kind, TraceKind::MessageReplied("EnsureIdentity"))),
        "trace missing HostIdentity.EnsureIdentity replied: {trace:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn open_ssh_public_key_derivation_runs_load_identity_then_write_projection() {
    let fixture = Fixture::start().await;
    let temporary_directory = tempfile::tempdir().expect("tempdir");
    let directory = temporary_directory.path().join("identity");

    fixture
        .runtime
        .host_identity
        .ask(EnsureIdentity {
            directory: directory.clone(),
        })
        .await
        .expect("seed identity reply");

    let identity = fixture
        .runtime
        .host_identity
        .ask(LoadIdentity {
            directory: directory.clone(),
        })
        .await
        .expect("LoadIdentity reply");

    fixture
        .runtime
        .host_identity
        .ask(WritePublicKeyProjection {
            directory,
            identity,
        })
        .await
        .expect("WritePublicKeyProjection reply");

    let trace = fixture.trace().await;
    let load_position = trace
        .iter()
        .position(|event| {
            event.actor == "HostIdentity"
                && matches!(event.kind, TraceKind::MessageReceived("LoadIdentity"))
        })
        .expect("HostIdentity.LoadIdentity received");
    let write_position = trace
        .iter()
        .position(|event| {
            event.actor == "HostIdentity"
                && matches!(
                    event.kind,
                    TraceKind::MessageReceived("WritePublicKeyProjection")
                )
        })
        .expect("HostIdentity.WritePublicKeyProjection received");
    assert!(
        load_position < write_position,
        "HostIdentity.LoadIdentity must precede HostIdentity.WritePublicKeyProjection: {trace:?}"
    );
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
