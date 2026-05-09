use crate::error::{Error, Result};
use der::asn1::{BitString, ObjectIdentifier};
use spki::SubjectPublicKeyInfoOwned;
use ssh_key::public::KeyData;

const ED25519_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

pub struct OpenSshPublicKey {
    public_key: ssh_key::PublicKey,
}

impl OpenSshPublicKey {
    pub fn from_text(text: impl AsRef<str>) -> Result<Self> {
        let raw_text = text.as_ref();
        let public_key = ssh_key::PublicKey::from_openssh(raw_text)
            .or_else(|_| {
                let full_text = if raw_text.contains(' ') {
                    raw_text.to_string()
                } else {
                    format!("ssh-ed25519 {raw_text}")
                };
                ssh_key::PublicKey::from_openssh(&full_text)
            })
            .map_err(|error| Error::Parse(format!("invalid SSH public key: {error}")))?;
        Ok(Self { public_key })
    }

    pub fn subject_public_key_info(&self) -> Result<SubjectPublicKeyInfoOwned> {
        match self.public_key.key_data() {
            KeyData::Ed25519(ed25519_key) => Ok(SubjectPublicKeyInfoOwned {
                algorithm: spki::AlgorithmIdentifierOwned {
                    oid: ED25519_OID,
                    parameters: None,
                },
                subject_public_key: BitString::from_bytes(ed25519_key.as_ref())
                    .map_err(|error| Error::Parse(format!("BitString: {error}")))?,
            }),
            _ => Err(Error::Parse("only Ed25519 SSH keys are supported".into())),
        }
    }

    pub fn raw_key_bytes(&self) -> Result<Vec<u8>> {
        match self.public_key.key_data() {
            KeyData::Ed25519(ed25519_key) => Ok(ed25519_key.as_ref().to_vec()),
            _ => Err(Error::Parse("only Ed25519 SSH keys are supported".into())),
        }
    }
}
