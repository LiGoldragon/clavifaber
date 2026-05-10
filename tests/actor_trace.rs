use clavifaber::actors::host_identity::{EnsureIdentity, LoadIdentity};
use clavifaber::actors::runtime_root::RuntimeRoot;
use clavifaber::actors::ssh_host_key::WritePublicKeyProjection;
use clavifaber::actors::trace_recorder::{ReportTrace, TraceEvent, TraceKind, TraceRecorder};
use clavifaber::actors::wifi_certificate::{
    EnsureWifiClientCertificate, EnsureWifiServerCertificate, WifiClientCertificatePlan,
    WifiServerCertificatePlan,
};
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

#[tokio::test(flavor = "multi_thread")]
async fn wifi_certificate_records_server_certificate_request() {
    // The actor's idempotent-skip path returns Ok(()) without touching
    // gpg-agent or the CA file when the cert files already exist on
    // disk — so this trace witness runs purely against the actor's
    // mailbox.
    let fixture = Fixture::start().await;
    let temporary_directory = tempfile::tempdir().expect("tempdir");
    let certificate_path = temporary_directory.path().join("server.pem");
    let private_key_path = temporary_directory.path().join("server.key");
    std::fs::write(&certificate_path, b"MARKER").expect("seed cert file");
    std::fs::write(&private_key_path, b"MARKER").expect("seed key file");

    fixture
        .runtime
        .wifi_certificate
        .ask(EnsureWifiServerCertificate {
            plan: WifiServerCertificatePlan {
                keygrip: "BOGUS".to_string(),
                certificate_authority: temporary_directory.path().join("nonexistent-ca.pem"),
                common_name: "irrelevant".to_string(),
                output_certificate: certificate_path,
                output_private_key: private_key_path,
            },
        })
        .await
        .expect("EnsureWifiServerCertificate reply (skip path succeeds without gpg-agent)");

    let trace = fixture.trace().await;
    assert!(
        trace.iter().any(|event| event.actor == "WifiCertificate"
            && matches!(
                event.kind,
                TraceKind::MessageReceived("EnsureWifiServerCertificate")
            )),
        "trace missing WifiCertificate.EnsureWifiServerCertificate received: {trace:?}"
    );
    assert!(
        trace.iter().any(|event| event.actor == "WifiCertificate"
            && matches!(
                event.kind,
                TraceKind::MessageReplied("EnsureWifiServerCertificate")
            )),
        "trace missing WifiCertificate.EnsureWifiServerCertificate replied: {trace:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn wifi_certificate_records_client_certificate_request() {
    let fixture = Fixture::start().await;
    let temporary_directory = tempfile::tempdir().expect("tempdir");
    let certificate_path = temporary_directory.path().join("node.pem");
    std::fs::write(&certificate_path, b"MARKER").expect("seed cert file");

    fixture
        .runtime
        .wifi_certificate
        .ask(EnsureWifiClientCertificate {
            plan: WifiClientCertificatePlan {
                keygrip: "BOGUS".to_string(),
                certificate_authority: temporary_directory.path().join("nonexistent-ca.pem"),
                open_ssh_public_key: "ssh-ed25519 IGNORED node".to_string(),
                common_name: "irrelevant".to_string(),
                output: certificate_path,
            },
        })
        .await
        .expect("EnsureWifiClientCertificate reply (skip path succeeds without gpg-agent)");

    let trace = fixture.trace().await;
    assert!(
        trace.iter().any(|event| event.actor == "WifiCertificate"
            && matches!(
                event.kind,
                TraceKind::MessageReceived("EnsureWifiClientCertificate")
            )),
        "trace missing WifiCertificate.EnsureWifiClientCertificate received: {trace:?}"
    );
}
