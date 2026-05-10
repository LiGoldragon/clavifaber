use clavifaber::actors::host_identity::{EnsureIdentity, LoadIdentity};
use clavifaber::actors::runtime_root::RuntimeRoot;
use clavifaber::actors::ssh_host_key::WritePublicKeyProjection;
use clavifaber::actors::trace_recorder::{ReportTrace, TraceEvent, TraceKind, TraceRecorder};
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
async fn public_key_derivation_runs_host_identity_then_ssh_host_key() {
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
        .ssh_host_key
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
            event.actor == "SshHostKey"
                && matches!(
                    event.kind,
                    TraceKind::MessageReceived("WritePublicKeyProjection")
                )
        })
        .expect("SshHostKey.WritePublicKeyProjection received");
    assert!(
        load_position < write_position,
        "HostIdentity.LoadIdentity must precede SshHostKey.WritePublicKeyProjection: {trace:?}"
    );
}
