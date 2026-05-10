use clavifaber::actors::certificate_issuer::CertificateIssuer;
use clavifaber::actors::gpg_agent_session::GpgAgentSession;
use clavifaber::actors::host_identity::HostIdentity;
use clavifaber::actors::publication_collector::PublicationCollector;
use clavifaber::actors::runtime_root::RuntimeRoot;
use clavifaber::actors::ssh_host_key::SshHostKey;
use clavifaber::actors::trace_recorder::TraceRecorder;
use clavifaber::actors::wifi_certificate::WifiCertificate;
use clavifaber::actors::yggdrasil_key::YggdrasilKey;
use std::mem;

#[test]
fn actor_types_carry_data_not_zero_size() {
    assert!(
        mem::size_of::<HostIdentity>() > 0,
        "HostIdentity is a public ZST — data-bearing actor type required"
    );
    assert!(
        mem::size_of::<SshHostKey>() > 0,
        "SshHostKey is a public ZST"
    );
    assert!(
        mem::size_of::<GpgAgentSession>() > 0,
        "GpgAgentSession is a public ZST"
    );
    assert!(
        mem::size_of::<CertificateIssuer>() > 0,
        "CertificateIssuer is a public ZST"
    );
    assert!(
        mem::size_of::<PublicationCollector>() > 0,
        "PublicationCollector is a public ZST"
    );
    assert!(
        mem::size_of::<WifiCertificate>() > 0,
        "WifiCertificate is a public ZST"
    );
    assert!(
        mem::size_of::<YggdrasilKey>() > 0,
        "YggdrasilKey is a public ZST"
    );
    assert!(
        mem::size_of::<TraceRecorder>() > 0,
        "TraceRecorder is a public ZST"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn runtime_root_spawns_every_named_actor() {
    let RuntimeRoot {
        host_identity,
        ssh_host_key,
        gpg_agent_session,
        certificate_issuer,
        publication_collector,
        wifi_certificate,
        yggdrasil_key,
        tracer,
    } = RuntimeRoot::start(None);
    let _ = (
        host_identity,
        ssh_host_key,
        gpg_agent_session,
        certificate_issuer,
        publication_collector,
        wifi_certificate,
        yggdrasil_key,
        tracer,
    );
}
