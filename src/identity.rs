use crate::error::{Error, Result};
use crate::util::AtomicFile;
use base64ct::Encoding;
use ed25519_dalek::SigningKey;
use ed25519_dalek::pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rand::rngs::OsRng;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct IdentityDirectory {
    path: PathBuf,
}

impl IdentityDirectory {
    pub fn from_path(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn existing_identity(&self) -> Result<Option<NodeIdentity>> {
        if !self.private_key_path().exists() {
            return Ok(None);
        }

        match self.load_identity() {
            Ok(identity) => Ok(Some(identity)),
            Err(error) => {
                self.quarantine_broken_identity(&error)?;
                Ok(None)
            }
        }
    }

    pub fn load_identity(&self) -> Result<NodeIdentity> {
        let private_key_path = self.private_key_path();
        let private_key_pem =
            fs::read_to_string(&private_key_path).map_err(|source| Error::Io {
                path: private_key_path.clone(),
                source,
            })?;
        NodeIdentity::from_private_key_pem(&private_key_pem, &private_key_path)
    }

    pub fn write_identity(&self, identity: &NodeIdentity) -> Result<()> {
        fs::create_dir_all(&self.path).map_err(|source| Error::Io {
            path: self.path.clone(),
            source,
        })?;
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o700)).map_err(|source| {
            Error::Io {
                path: self.path.clone(),
                source,
            }
        })?;

        AtomicFile::new(self.private_key_path())
            .write_bytes(identity.private_key_pem()?.as_bytes(), 0o600)?;
        self.write_public_key(identity)?;
        Ok(())
    }

    pub fn write_public_key(&self, identity: &NodeIdentity) -> Result<()> {
        AtomicFile::new(self.public_key_path())
            .write_bytes(identity.open_ssh_public_key().as_bytes(), 0o644)
    }

    pub fn public_key_path(&self) -> PathBuf {
        self.path.join("ssh.pub")
    }

    fn private_key_path(&self) -> PathBuf {
        self.path.join("key.pem")
    }

    fn quarantine_broken_identity(&self, error: &Error) -> Result<()> {
        let private_key_path = self.private_key_path();
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let broken_private_key_path = self.path.join(format!("key.pem.broken.{seconds}"));
        fs::rename(&private_key_path, &broken_private_key_path).map_err(|source| {
            Error::Corrupt {
                path: private_key_path.clone(),
                detail: format!(
                    "{error}; rename to {} failed: {source}",
                    broken_private_key_path.display()
                ),
            }
        })?;

        eprintln!(
            "warning: corrupt key renamed to {} ({error})",
            broken_private_key_path.display()
        );

        let public_key_path = self.public_key_path();
        if public_key_path.exists() {
            let _ = fs::rename(
                &public_key_path,
                self.path.join(format!("ssh.pub.broken.{seconds}")),
            );
        }

        Ok(())
    }
}

pub struct NodeIdentity {
    signing_key: SigningKey,
}

impl NodeIdentity {
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_private_key_pem(private_key_pem: &str, private_key_path: &Path) -> Result<Self> {
        let signing_key = SigningKey::from_pkcs8_pem(private_key_pem).map_err(|error| {
            Error::Parse(format!(
                "PKCS#8 decode {}: {error}",
                private_key_path.display()
            ))
        })?;
        Ok(Self { signing_key })
    }

    pub fn private_key_pem(&self) -> Result<String> {
        let private_key_der = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|error| Error::Parse(format!("PKCS#8 encode: {error}")))?;

        private_key_der
            .to_pem("PRIVATE KEY", pem_rfc7468::LineEnding::LF)
            .map(|private_key_pem| private_key_pem.to_string())
            .map_err(|error| Error::Parse(format!("PEM encode: {error}")))
    }

    pub fn open_ssh_public_key(&self) -> String {
        let verifying_key = self.signing_key.verifying_key();
        let key_type = b"ssh-ed25519";
        let mut key_blob = Vec::new();
        push_ssh_string(&mut key_blob, key_type);
        push_ssh_string(&mut key_blob, verifying_key.as_bytes());
        let encoded_public_key = base64ct::Base64::encode_string(&key_blob);
        format!("ssh-ed25519 {encoded_public_key} complex")
    }
}

fn push_ssh_string(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}
