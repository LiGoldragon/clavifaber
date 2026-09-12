//! Datom round trips and inline-Datom CLI dispatch for every request variant.

use clavifaber::request::{
    CertificateAuthorityIssuance, CertificateChainVerification, ClaviFaberRequest,
    ClaviFaberResponse, ClientCertificateIssuance, CommandLine, OpenSshPublicKeyLocation,
    PublicKeyPublicationWriting, ServerCertificateIssuance, WifiClientCertificateLocation,
    YggdrasilKeypairLocation, YggdrasilKeypairSetup,
};
use clavifaber::text::DatomTexting;
use datom_codec::{Actualizing, Budget, Potential};

fn text(value: &str) -> String {
    value.to_owned()
}

fn budget() -> Budget {
    Budget {
        remaining: 4_096,
        reader: protos::ReaderBudget { remaining: 16_384 },
        depth: 0,
        maximum_depth: 4_096,
    }
}

fn publication_request() -> ClaviFaberRequest {
    ClaviFaberRequest::PublicKeyPublicationWriting(PublicKeyPublicationWriting {
        first_string: text("ouranos"),
        open_ssh_public_key_location: OpenSshPublicKeyLocation {
            string: text("/etc/ssh/ssh_host_ed25519_key.pub"),
        },
        yggdrasil_keypair_location_option: None,
        wifi_client_certificate_location_option: None,
        second_string: text("/etc/criomOS/complex/publication.datom"),
    })
}

#[test]
fn every_request_variant_round_trips_through_current_datom() {
    let variants = [
        ClaviFaberRequest::CertificateAuthorityIssuance(CertificateAuthorityIssuance {
            first_string: text("ABCDEF0123456789"),
            second_string: text("cluster authority"),
            third_string: text("/var/lib/clavifaber/ca.pem"),
        }),
        ClaviFaberRequest::ServerCertificateIssuance(ServerCertificateIssuance {
            first_string: text("ABCDEF0123456789"),
            second_string: text("/var/lib/clavifaber/ca.pem"),
            third_string: text("server"),
            fourth_string: text("/var/lib/clavifaber/server.pem"),
            fifth_string: text("/var/lib/clavifaber/server.key"),
        }),
        ClaviFaberRequest::ClientCertificateIssuance(ClientCertificateIssuance {
            first_string: text("ABCDEF0123456789"),
            second_string: text("/var/lib/clavifaber/ca.pem"),
            third_string: text("ssh-ed25519 AAAA host"),
            fourth_string: text("client"),
            fifth_string: text("/var/lib/clavifaber/client.pem"),
        }),
        ClaviFaberRequest::CertificateChainVerification(CertificateChainVerification {
            first_string: text("/var/lib/clavifaber/ca.pem"),
            second_string: text("/var/lib/clavifaber/client.pem"),
        }),
        ClaviFaberRequest::YggdrasilKeypairSetup(YggdrasilKeypairSetup {
            string: text("/var/lib/clavifaber/yggdrasil.json"),
        }),
        publication_request(),
    ];

    for request in variants {
        let encoded = request.datom_text();
        assert_eq!(
            ClaviFaberRequest::decode(&encoded).expect("request decodes"),
            request
        );
    }
}

#[test]
fn documented_operator_examples_decode_without_execution() {
    let examples = [
        "CertificateAuthorityIssuance.{ «ABC123» «Cluster CA» /var/lib/clavifaber/ca.pem }",
        "ServerCertificateIssuance.{ «ABC123» /var/lib/clavifaber/ca.pem faber.criome /var/lib/clavifaber/server.pem /var/lib/clavifaber/server.key }",
        "ClientCertificateIssuance.{ «ABC123» /var/lib/clavifaber/ca.pem «ssh-ed25519 AAAA host» probus@aedifico /var/lib/clavifaber/client.pem }",
        "CertificateChainVerification.{ /var/lib/clavifaber/ca.pem /var/lib/clavifaber/client.pem }",
        "YggdrasilKeypairSetup.{ /var/lib/clavifaber/yggdrasil/keypair.json }",
        "PublicKeyPublicationWriting.{ probus { /etc/ssh/ssh_host_ed25519_key.pub } Some.{ /var/lib/clavifaber/yggdrasil/keypair.json } None /var/lib/clavifaber/publication.datom }",
    ];

    for example in examples {
        assert!(
            ClaviFaberRequest::decode(example).is_ok(),
            "documented form must decode: {example}"
        );
    }
}

#[test]
fn cli_datoms_use_one_root_variant_with_a_structural_payload() {
    let encoded = publication_request().datom_text();
    assert_eq!(
        encoded,
        "PublicKeyPublicationWriting.{ ouranos { /etc/ssh/ssh_host_ed25519_key.pub } None None /etc/criomOS/complex/publication.datom }"
    );
    assert_eq!(
        ClaviFaberRequest::decode(&encoded).expect("canonical request decodes"),
        publication_request()
    );
}

#[test]
fn publication_request_rejects_flat_or_legacy_tagged_payloads() {
    assert!(ClaviFaberRequest::decode(
        "PublicKeyPublicationWriting.{ouranos /etc/ssh/ssh_host_ed25519_key.pub None None /etc/criomOS/complex/publication.datom}"
    )
    .is_err());
    assert!(ClaviFaberRequest::decode(
        "PublicKeyPublicationWriting.{{ouranos OpenSshPublicKeyLocation.{/etc/ssh/ssh_host_ed25519_key.pub} None None /etc/criomOS/complex/publication.datom}}"
    )
    .is_err());
}

#[test]
fn inline_cli_combines_arguments_only_into_one_datom_value() {
    let request = publication_request();
    let encoded = request.datom_text();
    let (head, tail) = encoded.split_once(" None ").expect("optional boundary");
    let first = format!("{head} None");
    let parsed = CommandLine::from_arguments([first, tail.to_owned()])
        .parse_request()
        .expect("one reconstructed Datom parses");
    assert_eq!(parsed, request);
}

#[test]
fn reply_round_trip_uses_the_same_generated_datom_boundary() {
    let reply = ClaviFaberResponse::PublicKeyPublicationWritten(
        clavifaber::request::PublicKeyPublicationWritten {
            string: text("/etc/criomOS/complex/publication.datom"),
        },
    );
    let encoded = reply.datom_text();
    let decoded = Potential::<ClaviFaberResponse>::from(encoded)
        .actualize(&mut budget())
        .expect("reply decodes");
    assert_eq!(decoded, reply);
}

#[test]
fn optional_publication_sources_remain_explicit() {
    let request = ClaviFaberRequest::PublicKeyPublicationWriting(PublicKeyPublicationWriting {
        first_string: text("probus"),
        open_ssh_public_key_location: OpenSshPublicKeyLocation {
            string: text("/etc/ssh/ssh_host_ed25519_key.pub"),
        },
        yggdrasil_keypair_location_option: Some(YggdrasilKeypairLocation {
            string: text("/var/lib/clavifaber/yggdrasil.json"),
        }),
        wifi_client_certificate_location_option: Some(WifiClientCertificateLocation {
            string: text("/var/lib/clavifaber/wifi.pem"),
        }),
        second_string: text("/var/lib/clavifaber/publication.datom"),
    });
    let encoded = request.datom_text();
    assert_eq!(
        encoded,
        "PublicKeyPublicationWriting.{ probus { /etc/ssh/ssh_host_ed25519_key.pub } Some.{ /var/lib/clavifaber/yggdrasil.json } Some.{ /var/lib/clavifaber/wifi.pem } /var/lib/clavifaber/publication.datom }"
    );
    assert_eq!(
        ClaviFaberRequest::decode(&encoded).expect("optional request decodes"),
        request
    );
}
