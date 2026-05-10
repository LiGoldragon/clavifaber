use crate::error::{Error, Result};
use const_oid::db::rfc5280::{
    ID_CE_BASIC_CONSTRAINTS, ID_CE_KEY_USAGE, ID_CE_SUBJECT_KEY_IDENTIFIER,
};
use der::asn1::{BitString, ObjectIdentifier, OctetString, SetOfVec};
use der::{Any, Decode, Encode, Tag};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::attr::AttributeTypeAndValue;
use x509_cert::name::{Name, RdnSequence, RelativeDistinguishedName};
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};
use x509_cert::{Certificate, TbsCertificate};

const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const EC_PUBLIC_KEY_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const COMMON_NAME_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");
const ORGANIZATION_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.10");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateDer {
    bytes: Vec<u8>,
}

impl CertificateDer {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn from_pem(pem: &str) -> Result<Self> {
        let (label, bytes) = pem_rfc7468::decode_vec(pem.as_bytes())
            .map_err(|error| Error::Certificate(format!("PEM decode: {error}")))?;
        if label != "CERTIFICATE" {
            return Err(Error::Certificate(format!(
                "expected CERTIFICATE label, got: {label}"
            )));
        }
        Ok(Self { bytes })
    }

    pub fn to_pem(&self) -> Result<String> {
        pem_rfc7468::encode_string("CERTIFICATE", pem_rfc7468::LineEnding::LF, &self.bytes)
            .map_err(|error| Error::Certificate(format!("PEM encode: {error}")))
    }

    fn certificate(&self, name: &str) -> Result<Certificate> {
        Certificate::from_der(&self.bytes)
            .map_err(|error| Error::Certificate(format!("parse {name}: {error}")))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ed25519SubjectPublicKey {
    bytes: Vec<u8>,
}

impl Ed25519SubjectPublicKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
        Ok(SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: ED25519_OID,
                parameters: None,
            },
            subject_public_key: BitString::from_bytes(&self.bytes)
                .map_err(|error| Error::Certificate(format!("BitString: {error}")))?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthorityIssuer;

impl CertificateAuthorityIssuer {
    pub fn new() -> Self {
        Self
    }

    pub async fn self_signed_certificate<F, Fut>(
        &self,
        request: CertificateAuthorityCertificateRequest,
        signer: F,
    ) -> Result<CertificateDer>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>>>,
    {
        let subject_public_key_info_der = SubjectPublicKeyInfoDer::from_subject_public_key_info(
            &request.subject_public_key_info,
        )?;
        let subject = DistinguishedName::new(&request.common_name).name()?;
        let unsigned = UnsignedCertificate {
            certificate: TbsCertificate {
                version: x509_cert::Version::V3,
                serial_number: subject_public_key_info_der.serial_number()?,
                signature: AlgorithmIdentifierOwned {
                    oid: ED25519_OID,
                    parameters: None,
                },
                issuer: subject.clone(),
                validity: CertificateLifetime::years(10).validity()?,
                subject,
                subject_public_key_info: request.subject_public_key_info,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(vec![
                    BasicConstraints::certificate_authority().extension()?,
                    KeyUsage::certificate_authority().extension()?,
                    subject_public_key_info_der.subject_key_identifier_extension()?,
                ]),
            },
        };
        let signature = signer(unsigned.hash_hex()?).await?;
        unsigned.assemble(signature)
    }

    pub async fn node_certificate<F, Fut>(
        &self,
        certificate_authority: &CertificateDer,
        request: NodeCertificateSigningRequest,
        signer: F,
    ) -> Result<CertificateDer>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>>>,
    {
        let parsed_certificate_authority =
            certificate_authority.certificate("certificate authority")?;
        let subject_public_key_info_der = SubjectPublicKeyInfoDer::from_subject_public_key_info(
            &request.subject_public_key_info,
        )?;
        let unsigned = UnsignedCertificate {
            certificate: TbsCertificate {
                version: x509_cert::Version::V3,
                serial_number: subject_public_key_info_der.serial_number()?,
                signature: AlgorithmIdentifierOwned {
                    oid: ED25519_OID,
                    parameters: None,
                },
                issuer: parsed_certificate_authority.tbs_certificate.subject,
                validity: CertificateLifetime::years(2).validity()?,
                subject: DistinguishedName::new(&request.common_name).name()?,
                subject_public_key_info: request.subject_public_key_info,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(vec![
                    BasicConstraints::end_entity().extension()?,
                    KeyUsage::digital_signature().extension()?,
                    subject_public_key_info_der.subject_key_identifier_extension()?,
                ]),
            },
        };
        let signature = signer(unsigned.hash_hex()?).await?;
        unsigned.assemble(signature)
    }

    pub async fn server_certificate<F, Fut>(
        &self,
        certificate_authority: &CertificateDer,
        request: ServerCertificateSigningRequest,
        signer: F,
    ) -> Result<ServerCertificate>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<Vec<u8>>>,
    {
        let parsed_certificate_authority =
            certificate_authority.certificate("certificate authority")?;
        let server_key_pair = ServerKeyPair::generate();
        let subject_public_key_info = server_key_pair.subject_public_key_info()?;
        let subject_public_key_info_der =
            SubjectPublicKeyInfoDer::from_subject_public_key_info(&subject_public_key_info)?;
        let unsigned = UnsignedCertificate {
            certificate: TbsCertificate {
                version: x509_cert::Version::V3,
                serial_number: subject_public_key_info_der.serial_number()?,
                signature: AlgorithmIdentifierOwned {
                    oid: ED25519_OID,
                    parameters: None,
                },
                issuer: parsed_certificate_authority.tbs_certificate.subject,
                validity: CertificateLifetime::years(2).validity()?,
                subject: DistinguishedName::new(&request.common_name).name()?,
                subject_public_key_info,
                issuer_unique_id: None,
                subject_unique_id: None,
                extensions: Some(vec![
                    BasicConstraints::end_entity().extension()?,
                    KeyUsage::digital_signature().extension()?,
                    subject_public_key_info_der.subject_key_identifier_extension()?,
                ]),
            },
        };
        let signature = signer(unsigned.hash_hex()?).await?;
        Ok(ServerCertificate {
            certificate: unsigned.assemble(signature)?,
            private_key_pem: server_key_pair.private_key_pem()?,
        })
    }
}

impl Default for CertificateAuthorityIssuer {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertificateAuthorityCertificateRequest {
    common_name: String,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
}

impl CertificateAuthorityCertificateRequest {
    pub fn new(
        common_name: impl Into<String>,
        subject_public_key_info: SubjectPublicKeyInfoOwned,
    ) -> Self {
        Self {
            common_name: common_name.into(),
            subject_public_key_info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeCertificateSigningRequest {
    common_name: String,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
}

impl NodeCertificateSigningRequest {
    pub fn new(
        common_name: impl Into<String>,
        subject_public_key_info: SubjectPublicKeyInfoOwned,
    ) -> Self {
        Self {
            common_name: common_name.into(),
            subject_public_key_info,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCertificateSigningRequest {
    common_name: String,
}

impl ServerCertificateSigningRequest {
    pub fn new(common_name: impl Into<String>) -> Self {
        Self {
            common_name: common_name.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCertificate {
    certificate: CertificateDer,
    private_key_pem: String,
}

impl ServerCertificate {
    pub fn certificate(&self) -> &CertificateDer {
        &self.certificate
    }

    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }
}

pub struct CertificateChain<'certificate> {
    certificate_authority: &'certificate CertificateDer,
    certificate: &'certificate CertificateDer,
}

impl<'certificate> CertificateChain<'certificate> {
    pub fn from_certificates(
        certificate_authority: &'certificate CertificateDer,
        certificate: &'certificate CertificateDer,
    ) -> Self {
        Self {
            certificate_authority,
            certificate,
        }
    }

    pub fn verify(&self) -> Result<()> {
        let certificate_authority = self
            .certificate_authority
            .certificate("certificate authority")?;
        let certificate = self.certificate.certificate("certificate")?;

        let certificate_authority_subject_der = certificate_authority
            .tbs_certificate
            .subject
            .to_der()
            .map_err(|error| Error::Certificate(format!("CA subject encode: {error}")))?;
        let certificate_issuer_der = certificate
            .tbs_certificate
            .issuer
            .to_der()
            .map_err(|error| Error::Certificate(format!("cert issuer encode: {error}")))?;

        if certificate_authority_subject_der != certificate_issuer_der {
            return Err(Error::Certificate(
                "issuer does not match CA subject".into(),
            ));
        }

        CertificateSignature {
            certificate_authority,
            certificate,
        }
        .verify()
    }
}

struct SubjectPublicKeyInfoDer {
    bytes: Vec<u8>,
}

impl SubjectPublicKeyInfoDer {
    fn from_subject_public_key_info(
        subject_public_key_info: &SubjectPublicKeyInfoOwned,
    ) -> Result<Self> {
        let bytes = subject_public_key_info
            .to_der()
            .map_err(|error| Error::Certificate(format!("SPKI encode: {error}")))?;
        Ok(Self { bytes })
    }

    fn serial_number(&self) -> Result<SerialNumber> {
        let mut hasher = Sha256::new();
        hasher.update(&self.bytes);
        hasher.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
                .to_le_bytes(),
        );
        let hash = hasher.finalize();
        let mut serial_bytes = hash[..20].to_vec();
        serial_bytes[0] &= 0x7F;
        if serial_bytes[0] == 0 {
            serial_bytes[0] = 0x01;
        }
        SerialNumber::new(&serial_bytes)
            .map_err(|error| Error::Certificate(format!("serial: {error}")))
    }

    fn subject_key_identifier_extension(&self) -> Result<x509_cert::ext::Extension> {
        let hash = Sha256::digest(&self.bytes);
        let subject_key_identifier = &hash[..20];
        let mut subject_key_identifier_der = vec![0x04, subject_key_identifier.len() as u8];
        subject_key_identifier_der.extend_from_slice(subject_key_identifier);
        Ok(x509_cert::ext::Extension {
            extn_id: ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical: false,
            extn_value: OctetString::new(subject_key_identifier_der)
                .map_err(|error| Error::Certificate(format!("SKI: {error}")))?,
        })
    }
}

struct DistinguishedName<'name> {
    common_name: &'name str,
    organization: Option<&'name str>,
}

impl<'name> DistinguishedName<'name> {
    fn new(common_name: &'name str) -> Self {
        Self {
            common_name,
            organization: Some("CriomOS"),
        }
    }

    fn name(&self) -> Result<Name> {
        let mut relative_distinguished_names = Vec::new();

        if let Some(organization) = self.organization {
            relative_distinguished_names.push(
                NameAttribute::new(ORGANIZATION_OID, organization).relative_distinguished_name()?,
            );
        }

        relative_distinguished_names.push(
            NameAttribute::new(COMMON_NAME_OID, self.common_name).relative_distinguished_name()?,
        );

        Ok(Name::from(RdnSequence::from(relative_distinguished_names)))
    }
}

struct NameAttribute<'attribute> {
    oid: ObjectIdentifier,
    value: &'attribute str,
}

impl<'attribute> NameAttribute<'attribute> {
    fn new(oid: ObjectIdentifier, value: &'attribute str) -> Self {
        Self { oid, value }
    }

    fn relative_distinguished_name(&self) -> Result<RelativeDistinguishedName> {
        let value = Any::new(Tag::Utf8String, self.value.as_bytes())
            .map_err(|error| Error::Certificate(format!("name attribute encoding: {error}")))?;
        let attribute = AttributeTypeAndValue {
            oid: self.oid,
            value,
        };
        let set = SetOfVec::try_from(vec![attribute])
            .map_err(|error| Error::Certificate(format!("name RDN: {error}")))?;
        Ok(RelativeDistinguishedName::from(set))
    }
}

struct CertificateLifetime {
    years: u32,
}

impl CertificateLifetime {
    fn years(years: u32) -> Self {
        Self { years }
    }

    fn validity(&self) -> Result<Validity> {
        use std::time::{Duration, SystemTime};

        let not_before = SystemTime::now();
        let not_after = not_before + Duration::from_secs(self.years as u64 * 365 * 24 * 3600);

        Ok(Validity {
            not_before: Time::try_from(not_before)
                .map_err(|error| Error::Certificate(format!("not_before: {error}")))?,
            not_after: Time::try_from(not_after)
                .map_err(|error| Error::Certificate(format!("not_after: {error}")))?,
        })
    }
}

struct BasicConstraints {
    certificate_authority: bool,
}

impl BasicConstraints {
    fn certificate_authority() -> Self {
        Self {
            certificate_authority: true,
        }
    }

    fn end_entity() -> Self {
        Self {
            certificate_authority: false,
        }
    }

    fn extension(&self) -> Result<x509_cert::ext::Extension> {
        let value = if self.certificate_authority {
            vec![0x30, 0x03, 0x01, 0x01, 0xFF]
        } else {
            vec![0x30, 0x00]
        };
        Ok(x509_cert::ext::Extension {
            extn_id: ID_CE_BASIC_CONSTRAINTS,
            critical: true,
            extn_value: OctetString::new(value)
                .map_err(|error| Error::Certificate(format!("basic constraints: {error}")))?,
        })
    }
}

struct KeyUsage {
    digital_signature: bool,
    certificate_signing: bool,
}

impl KeyUsage {
    fn certificate_authority() -> Self {
        Self {
            digital_signature: false,
            certificate_signing: true,
        }
    }

    fn digital_signature() -> Self {
        Self {
            digital_signature: true,
            certificate_signing: false,
        }
    }

    fn extension(&self) -> Result<x509_cert::ext::Extension> {
        let mut bits = 0_u8;
        if self.digital_signature {
            bits |= 0x80;
        }
        if self.certificate_signing {
            bits |= 0x04;
        }
        let unused_bits = bits.trailing_zeros().min(7) as u8;
        let value = vec![0x03, 0x02, unused_bits, bits];
        Ok(x509_cert::ext::Extension {
            extn_id: ID_CE_KEY_USAGE,
            critical: true,
            extn_value: OctetString::new(value)
                .map_err(|error| Error::Certificate(format!("key usage: {error}")))?,
        })
    }
}

struct UnsignedCertificate {
    certificate: TbsCertificate,
}

impl UnsignedCertificate {
    fn hash_hex(&self) -> Result<String> {
        let certificate_der = self
            .certificate
            .to_der()
            .map_err(|error| Error::Certificate(format!("TBS encode: {error}")))?;
        let hash = Sha256::digest(&certificate_der);
        Ok(hex::encode(hash))
    }

    fn assemble(self, signature: Vec<u8>) -> Result<CertificateDer> {
        let certificate = Certificate {
            tbs_certificate: self.certificate,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: ED25519_OID,
                parameters: None,
            },
            signature: BitString::from_bytes(&signature)
                .map_err(|error| Error::Certificate(format!("signature BitString: {error}")))?,
        };
        let bytes = certificate
            .to_der()
            .map_err(|error| Error::Certificate(format!("cert encode: {error}")))?;
        Ok(CertificateDer::from_bytes(bytes))
    }
}

struct ServerKeyPair {
    signing_key: p256::ecdsa::SigningKey,
}

impl ServerKeyPair {
    fn generate() -> Self {
        Self {
            signing_key: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
        }
    }

    fn private_key_pem(&self) -> Result<String> {
        use p256::pkcs8::EncodePrivateKey;

        let secret_key = p256::SecretKey::from(self.signing_key.clone());
        secret_key
            .to_pkcs8_pem(pem_rfc7468::LineEnding::LF)
            .map(|private_key_pem| private_key_pem.to_string())
            .map_err(|error| Error::Certificate(format!("server key encode: {error}")))
    }

    fn subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
        let verifying_key = self.signing_key.verifying_key();
        let public_point = verifying_key.to_encoded_point(false);

        let oid_der = SECP256R1_OID
            .to_der()
            .map_err(|error| Error::Certificate(format!("OID encode: {error}")))?;
        let parameters = Any::from_der(&oid_der)
            .map_err(|error| Error::Certificate(format!("param encode: {error}")))?;

        Ok(SubjectPublicKeyInfoOwned {
            algorithm: AlgorithmIdentifierOwned {
                oid: EC_PUBLIC_KEY_OID,
                parameters: Some(parameters),
            },
            subject_public_key: BitString::from_bytes(public_point.as_bytes())
                .map_err(|error| Error::Certificate(format!("pubkey BitString: {error}")))?,
        })
    }
}

struct CertificateSignature {
    certificate_authority: Certificate,
    certificate: Certificate,
}

impl CertificateSignature {
    fn verify(&self) -> Result<()> {
        let certificate_authority_public_key =
            CertificateAuthorityPublicKey::from_certificate(&self.certificate_authority)?;
        let certificate_body_der = self
            .certificate
            .tbs_certificate
            .to_der()
            .map_err(|error| Error::Certificate(format!("TBS encode: {error}")))?;
        let certificate_body_hash = Sha256::digest(&certificate_body_der);
        let signature = self.signature()?;

        certificate_authority_public_key
            .verify_strict(&certificate_body_hash, &signature)
            .map_err(|error| {
                Error::Certificate(format!("signature verification failed: {error}"))
            })?;

        Ok(())
    }

    fn signature(&self) -> Result<ed25519_dalek::Signature> {
        let signature_raw = self.certificate.signature.raw_bytes();
        let signature_bytes: [u8; 64] = signature_raw.try_into().map_err(|_| {
            Error::Certificate(format!(
                "signature is {} bytes, expected 64",
                signature_raw.len()
            ))
        })?;
        Ok(ed25519_dalek::Signature::from_bytes(&signature_bytes))
    }
}

struct CertificateAuthorityPublicKey;

impl CertificateAuthorityPublicKey {
    fn from_certificate(
        certificate_authority: &Certificate,
    ) -> Result<ed25519_dalek::VerifyingKey> {
        let public_key_bits = &certificate_authority
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key;
        let public_key_raw = public_key_bits.raw_bytes();

        let public_key_bytes: [u8; 32] = public_key_raw.try_into().map_err(|_| {
            Error::Certificate(format!(
                "CA public key is {} bytes, expected 32",
                public_key_raw.len()
            ))
        })?;
        ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes)
            .map_err(|error| Error::Certificate(format!("CA public key invalid: {error}")))
    }
}
