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

#[test]
fn nota_request_with_apostrophe_text_uses_only_needed_delimiters() {
    let request = ClaviFaberRequest::CertificateAuthorityIssuance(
        clavifaber::request::CertificateAuthorityIssuance {
            keygrip: "ABCDEF0123456789".to_string(),
            common_name: "cluster's authority".to_string(),
            output: "/var/lib/clavifaber/ca's.pem".to_string(),
        },
    );

    let encoded = request.to_nota().expect("request encodes");

    assert!(
        !encoded.contains('"'),
        "encoded NOTA should not use quote string delimiters: {encoded}"
    );
    assert!(
        encoded.contains("[cluster's authority]"),
        "encoded NOTA should bracket whitespace text: {encoded}"
    );
    assert!(
        encoded.contains("/var/lib/clavifaber/ca's.pem"),
        "encoded NOTA should leave apostrophe-only paths bare: {encoded}"
    );
    assert_eq!(
        ClaviFaberRequest::from_nota(&encoded).expect("request decodes"),
        request
    );
}

/// The exact wire string CriomOS hand-writes for a node publication
/// request and feeds to the clavifaber CLI. The round-trip tests above
/// build a Rust value and never witness this literal, so they could not
/// catch CriomOS drifting the hand-written NOTA — which it did twice:
/// first the outer root was flattened to a 6-field form, then the inner
/// `open_ssh_public_key` carried an extra `(OpenSshPublicKeyLocation …)`
/// tag. This golden string pins the contract through the same entry the
/// CLI uses (`ClaviFaberRequest::from_nota`).
const CRIOMOS_PUBLICATION_GOLDEN: &str = "(PublicKeyPublicationWriting (ouranos (/etc/ssh/ssh_host_ed25519_key.pub) None None /etc/criomOS/complex/publication.nota))";

#[test]
fn criomos_publication_golden_string_decodes_to_expected_request() {
    let decoded =
        ClaviFaberRequest::from_nota(CRIOMOS_PUBLICATION_GOLDEN).expect("golden string decodes");

    let expected = ClaviFaberRequest::PublicKeyPublicationWriting(PublicKeyPublicationWriting {
        node_name: "ouranos".to_string(),
        open_ssh_public_key: OpenSshPublicKeyLocation {
            path: "/etc/ssh/ssh_host_ed25519_key.pub".to_string(),
        },
        yggdrasil_keypair: None,
        wifi_client_certificate: None,
        publication_output: "/etc/criomOS/complex/publication.nota".to_string(),
    });

    assert_eq!(
        decoded, expected,
        "golden string must decode to the canonical PublicKeyPublicationWriting"
    );

    // Field-by-field witness so a future drift names the exact field.
    let ClaviFaberRequest::PublicKeyPublicationWriting(writing) = decoded else {
        panic!("golden string decoded to the wrong request variant: {decoded:?}");
    };
    assert_eq!(writing.node_name, "ouranos");
    assert_eq!(
        writing.open_ssh_public_key,
        OpenSshPublicKeyLocation {
            path: "/etc/ssh/ssh_host_ed25519_key.pub".to_string(),
        }
    );
    assert_eq!(writing.yggdrasil_keypair, None);
    assert_eq!(writing.wifi_client_certificate, None);
    assert_eq!(
        writing.publication_output,
        "/etc/criomOS/complex/publication.nota"
    );
}

#[test]
fn criomos_publication_golden_string_round_trips_through_to_nota() {
    // `to_nota` must reproduce the exact literal CriomOS emits, so the
    // golden string is anchored from both sides: parse it, re-encode it,
    // and the bytes must come back identical.
    let decoded =
        ClaviFaberRequest::from_nota(CRIOMOS_PUBLICATION_GOLDEN).expect("golden string decodes");
    assert_eq!(
        decoded.to_nota().expect("re-encode"),
        CRIOMOS_PUBLICATION_GOLDEN,
        "to_nota must reproduce the canonical CriomOS wire string verbatim"
    );
}

#[test]
fn wrong_publication_shapes_are_rejected() {
    // The 6-field flat root that CriomOS first emitted (every field
    // hoisted directly under the variant tag, no inner record for the
    // open-ssh-pubkey). This is NOT a PublicKeyPublicationWriting and
    // must not decode as one.
    let flat_six_root = "(PublicKeyPublicationWriting ouranos /etc/ssh/ssh_host_ed25519_key.pub None None /etc/criomOS/complex/publication.nota)";
    assert!(
        ClaviFaberRequest::from_nota(flat_six_root).is_err(),
        "the 6-field flat root must be rejected, not silently accepted: {flat_six_root}"
    );

    // The 2-root inner form CriomOS emitted next: the open-ssh-pubkey
    // location wrapped in an explicit `(OpenSshPublicKeyLocation …)`
    // tag. The field is a positional record, not a tagged one, so this
    // must also be rejected.
    let tagged_inner = "(PublicKeyPublicationWriting (ouranos (OpenSshPublicKeyLocation /etc/ssh/ssh_host_ed25519_key.pub) None None /etc/criomOS/complex/publication.nota))";
    assert!(
        ClaviFaberRequest::from_nota(tagged_inner).is_err(),
        "the (OpenSshPublicKeyLocation …) tagged-inner form must be rejected: {tagged_inner}"
    );
}
