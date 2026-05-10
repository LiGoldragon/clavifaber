//! NOTA round-trip + inline-NOTA CLI dispatch for the request surface.

use clavifaber::request::{
    ClaviFaberRequest, ClientCertificateIssuance, OpenSshPublicKeyLocation,
    PublicKeyPublicationWriting,
};

#[test]
fn nota_request_round_trip_preserves_client_certificate_issuance() {
    let request = ClaviFaberRequest::ClientCertificateIssuance(ClientCertificateIssuance {
        certificate_authority_keygrip: "ABCDEF0123456789".to_string(),
        certificate_authority_certificate: "/var/lib/clavifaber/ca.pem".to_string(),
        open_ssh_public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAA probus".to_string(),
        common_name: "probus@aedifico".to_string(),
        output: "/var/lib/clavifaber/probus.pem".to_string(),
    });

    let encoded = request.to_nota().expect("request encodes");
    let decoded = ClaviFaberRequest::from_nota(&encoded).expect("request decodes");

    assert_eq!(decoded, request);
}

#[test]
fn nota_request_round_trip_preserves_public_key_publication_writing() {
    let request = ClaviFaberRequest::PublicKeyPublicationWriting(PublicKeyPublicationWriting {
        node_name: "probus".to_string(),
        open_ssh_public_key: OpenSshPublicKeyLocation {
            path: "/etc/ssh/ssh_host_ed25519_key.pub".to_string(),
        },
        yggdrasil_keypair: None,
        wifi_client_certificate: None,
        publication_output: "/var/lib/clavifaber/publication.nota".to_string(),
    });

    let encoded = request.to_nota().expect("request encodes");
    let decoded = ClaviFaberRequest::from_nota(&encoded).expect("request decodes");

    assert_eq!(decoded, request);
}
