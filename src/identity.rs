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

    /// Resolve the on-disk identity if one is present and usable.
    ///
    /// Three on-disk states distinguished:
    ///
    /// - **Absent** (no `key.pem`): return `Ok(None)`; caller
    ///   generates a fresh identity.
    /// - **Present and corrupt** — content is not a parseable PEM
    ///   block at all (no `-----BEGIN ... -----` markers): rename to
    ///   `key.pem.broken.<unix-seconds>` and return `Ok(None)`. Caller
    ///   generates a fresh identity. The broken file is preserved
    ///   for forensic inspection. This is the conservative case —
    ///   the file is clearly not a usable key.
    /// - **Present and structured but not ours** — content parses
    ///   as PEM with the wrong label, or as PKCS#8 with the wrong
    ///   algorithm: return `Err(Error::Corrupt {..})`. **Do not
    ///   quarantine.** Refusing to overwrite a structurally-typed
    ///   file we don't recognise lets an operator investigate
    ///   instead of having the host's identity silently rotated by
    ///   a parser disagreement.
    pub fn existing_identity(&self) -> Result<Option<NodeIdentity>> {
        let private_key_path = self.private_key_path();
        if !private_key_path.exists() {
            return Ok(None);
        }

        let private_key_pem =
            fs::read_to_string(&private_key_path).map_err(|source| Error::Io {
                path: private_key_path.clone(),
                source,
            })?;

        match Self::classify_existing_private_key(&private_key_pem) {
            ExistingPrivateKey::Usable => {
                NodeIdentity::from_private_key_pem(&private_key_pem, &private_key_path).map(Some)
            }
            ExistingPrivateKey::Garbage(detail) => {
                self.quarantine_broken_identity(&detail)?;
                Ok(None)
            }
            ExistingPrivateKey::StructuredButNotOurs(detail) => Err(Error::Corrupt {
                path: private_key_path,
                detail,
            }),
        }
    }

    /// Decide which on-disk-state bucket the bytes fall into.
    ///
    /// We do a cheap PEM-shape check (`-----BEGIN ... -----` /
    /// `-----END ... -----`) and only quarantine when the content
    /// is **clearly not a PEM block at all**. PEM blocks with the
    /// wrong label, or with body bytes that don't decode as
    /// Ed25519 PKCS#8, get the "structured but not ours" verdict —
    /// the caller refuses to overwrite. This narrows the
    /// quarantine path so a transient parser disagreement on a
    /// good key can't silently rotate the host's identity (per
    /// report 112).
    fn classify_existing_private_key(content: &str) -> ExistingPrivateKey {
        let trimmed = content.trim_start_matches('\u{feff}');
        let has_begin = trimmed.contains("-----BEGIN ");
        let has_end = trimmed.contains("-----END ");
        if !has_begin || !has_end {
            return ExistingPrivateKey::Garbage("private key file is not a PEM block".to_string());
        }

        // PEM-shaped. Find the label and decide.
        let label = pem_label(trimmed);
        if label.as_deref() != Some("PRIVATE KEY") {
            return ExistingPrivateKey::StructuredButNotOurs(format!(
                "private key file PEM label is {:?}, expected \"PRIVATE KEY\"",
                label.unwrap_or_default()
            ));
        }

        // PEM with right label. The PKCS#8 parse will reject if the
        // algorithm is wrong; surface that as StructuredButNotOurs.
        match SigningKey::from_pkcs8_pem(content) {
            Ok(_) => ExistingPrivateKey::Usable,
            Err(error) => ExistingPrivateKey::StructuredButNotOurs(format!(
                "PEM body is not Ed25519 PKCS#8: {error}"
            )),
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

    fn quarantine_broken_identity(&self, detail: &str) -> Result<()> {
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
                    "{detail}; rename to {} failed: {source}",
                    broken_private_key_path.display()
                ),
            }
        })?;

        eprintln!(
            "warning: corrupt key renamed to {} ({detail})",
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum ExistingPrivateKey {
    /// PEM-shaped, "PRIVATE KEY" label, parseable as Ed25519 PKCS#8.
    Usable,
    /// Not a PEM block. Safe to quarantine and regenerate; nothing
    /// structural to preserve.
    Garbage(String),
    /// PEM-shaped but the wrong label, or PEM with the right label
    /// but decode fails. Refuse to overwrite — surface the error.
    StructuredButNotOurs(String),
}

fn pem_label(content: &str) -> Option<String> {
    let begin = content.find("-----BEGIN ")?;
    let after_begin = &content[begin + "-----BEGIN ".len()..];
    let end_of_label = after_begin.find("-----")?;
    Some(after_begin[..end_of_label].to_string())
}

#[derive(Debug)]
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
