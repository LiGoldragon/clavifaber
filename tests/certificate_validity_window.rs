//! Witness for primary-4kr (security defect): CertificateChain::verify
//! must reject certificates whose validity window does not include the
//! current time.
//!
//! The test synthesises a self-issued CA cert + an end-entity cert with
//! chosen validity bounds and a deliberately-invalid signature. The
//! verify path checks issuer-DN match (ours match), then validity
//! window, then signature. So:
//!
//! - clock inside the validity window → validity check passes →
//!   signature check runs → fails (bogus signature) → returns
//!   "signature verification failed".
//! - clock outside the validity window → validity check fails first →
//!   returns "certificate expired" / "certificate not yet valid".
//!
//! That distinguishes the two failure modes and witnesses the new
//! validity-window check is reached.

use clavifaber::error::Error;
use clavifaber::x509::{CertificateChain, CertificateDer};
use der::asn1::{BitString, ObjectIdentifier, SetOfVec};
use der::{Any, Decode, Encode, Tag};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use std::time::{Duration, SystemTime};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate};

const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

fn distinguished_name(common_name: &str) -> Name {
    let value = Any::new(Tag::Utf8String, common_name.as_bytes()).expect("CN encoding");
    let attribute = AttributeTypeAndValue {
        oid: COMMON_NAME_OID,
        value,
    };
    let set = SetOfVec::try_from(vec![attribute]).expect("CN RDN");
    let rdn = RelativeDistinguishedName::from(set);
    let mut sequence = RdnSequence::default();
    sequence.0.push(rdn);
    sequence
}

fn empty_subject_public_key_info() -> SubjectPublicKeyInfoOwned {
    SubjectPublicKeyInfoOwned {
        algorithm: AlgorithmIdentifierOwned {
            oid: ED25519_OID,
            parameters: None,
        },
        subject_public_key: BitString::from_bytes(&[0u8; 32]).expect("32-byte SPKI"),
    }
}

fn synth_certificate(
    issuer: Name,
    subject: Name,
    not_before: SystemTime,
    not_after: SystemTime,
) -> CertificateDer {
    let tbs = TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: SerialNumber::new(&[0x01]).expect("serial"),
        signature: AlgorithmIdentifierOwned {
            oid: ED25519_OID,
            parameters: None,
        },
        issuer,
        validity: Validity {
            not_before: Time::try_from(not_before).expect("not_before"),
            not_after: Time::try_from(not_after).expect("not_after"),
        },
        subject,
        subject_public_key_info: empty_subject_public_key_info(),
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: None,
    };
    let certificate = Certificate {
        tbs_certificate: tbs,
        signature_algorithm: AlgorithmIdentifierOwned {
            oid: ED25519_OID,
            parameters: None,
        },
        signature: BitString::from_bytes(&[0u8; 64]).expect("signature placeholder"),
    };
    let bytes = certificate.to_der().expect("encode certificate");
    // Round-trip through Decode to make sure x509-cert accepts the bytes.
    let _: Certificate = Certificate::from_der(&bytes).expect("decoded certificate");
    CertificateDer::from_bytes(bytes)
}

struct ChainFixture {
    ca: CertificateDer,
    leaf: CertificateDer,
    not_before: SystemTime,
    not_after: SystemTime,
}

impl ChainFixture {
    fn build(not_before: SystemTime, not_after: SystemTime) -> Self {
        let ca_name = distinguished_name("Test CA");
        let leaf_name = distinguished_name("leaf");
        let ca_lifetime_far_future =
            SystemTime::UNIX_EPOCH + Duration::from_secs(20 * 365 * 24 * 3600);
        let ca = synth_certificate(
            ca_name.clone(),
            ca_name.clone(),
            SystemTime::UNIX_EPOCH + Duration::from_secs(60),
            ca_lifetime_far_future,
        );
        let leaf = synth_certificate(ca_name, leaf_name, not_before, not_after);
        Self {
            ca,
            leaf,
            not_before,
            not_after,
        }
    }

    fn chain(&self) -> CertificateChain<'_> {
        CertificateChain::from_certificates(&self.ca, &self.leaf)
    }
}

#[test]
fn verify_rejects_certificate_whose_not_after_is_before_clock() {
    let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
    let after_window = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000);

    let fixture = ChainFixture::build(not_before, not_after);
    let result = fixture.chain().verify_with_clock(after_window);

    match result {
        Err(Error::Certificate(message)) => {
            assert!(
                message.contains("expired"),
                "expected expired error, got: {message}"
            );
        }
        Err(other) => panic!("expected Error::Certificate(expired), got: {other:?}"),
        Ok(()) => panic!(
            "expired certificate must not verify (not_after = {:?})",
            fixture.not_after
        ),
    }
}

#[test]
fn verify_rejects_certificate_whose_not_before_is_after_clock() {
    let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);
    let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000);
    let before_window = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);

    let fixture = ChainFixture::build(not_before, not_after);
    let result = fixture.chain().verify_with_clock(before_window);

    match result {
        Err(Error::Certificate(message)) => {
            assert!(
                message.contains("not yet valid"),
                "expected not-yet-valid error, got: {message}"
            );
        }
        Err(other) => panic!("expected Error::Certificate(not yet valid), got: {other:?}"),
        Ok(()) => panic!(
            "future-only certificate must not verify (not_before = {:?})",
            fixture.not_before
        ),
    }
}

#[test]
fn verify_within_window_runs_signature_check_after_validity() {
    // Synth cert has a placeholder signature, so the signature check
    // must fail. That demonstrates validity passed and the signature
    // step ran — i.e., the validity-window check did not short-circuit
    // a healthy cert.
    let not_before = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
    let not_after = SystemTime::UNIX_EPOCH + Duration::from_secs(3_000_000);
    let inside_window = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000);

    let fixture = ChainFixture::build(not_before, not_after);
    let result = fixture.chain().verify_with_clock(inside_window);

    match result {
        Err(Error::Certificate(message)) => {
            assert!(
                message.contains("signature"),
                "expected signature error after validity passed, got: {message}"
            );
            assert!(
                !message.contains("expired") && !message.contains("not yet valid"),
                "in-window cert must not report validity failure: {message}"
            );
        }
        Err(other) => panic!("expected Error::Certificate(signature), got: {other:?}"),
        Ok(()) => {
            panic!("synth cert has placeholder signature — verify must fail at signature step")
        }
    }
}
