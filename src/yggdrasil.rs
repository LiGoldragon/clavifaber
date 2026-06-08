//! Yggdrasil host identity material.
//!
//! ClaviFaber owns the per-host Yggdrasil keypair file and projects it
//! to the public IPv6 address + hex public key consumed by other hosts.
//!
//! On-disk shape (mode 0600): a JSON object `{"PrivateKey": "<128 hex>"}`
//! — the same shape CriomOS's existing `network/yggdrasil.nix` consumes
//! via `preCriadJson` (it merges this file with the runtime network
//! overlay before invoking yggdrasild).
//!
//! Public projection is derived **statically** by invoking
//! `yggdrasil -useconffile <keypair_path> -publickey -address`. The
//! daemon is never started by clavifaber.

use crate::error::{Error, Result};
use crate::util::AtomicFile;
use nota_next::{NotaDecode, NotaEncode};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The static public projection of the per-host Yggdrasil keypair:
/// IPv6 address (200::/7 range) + 64-hex public key. Derived from
/// the keypair file by invoking `yggdrasil -useconffile <file>
/// -publickey -address` (no daemon).
#[derive(Debug, Clone, PartialEq, Eq, NotaDecode, NotaEncode)]
pub struct YggdrasilProjection {
    pub address: String,
    pub public_key: String,
}

pub struct YggdrasilKeypairFile {
    path: PathBuf,
}

impl YggdrasilKeypairFile {
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Generate the keypair file if it does not already exist. The file
    /// is written atomically with mode 0600. Idempotent: returns
    /// quickly when the file is already present.
    pub fn ensure(&self, yggdrasil_binary: &str) -> Result<()> {
        if self.exists() {
            return Ok(());
        }
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| Error::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        let output = Command::new(yggdrasil_binary)
            .args(["-genconf", "-json"])
            .output()
            .map_err(|error| {
                Error::Yggdrasil(format!("invoke {yggdrasil_binary} -genconf: {error}"))
            })?;
        if !output.status.success() {
            return Err(Error::Yggdrasil(format!(
                "{yggdrasil_binary} -genconf exited {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        let private_key = extract_private_key(&output.stdout)?;
        let keypair_json = format!("{{\"PrivateKey\":\"{private_key}\"}}\n");
        AtomicFile::new(self.path.clone()).write_bytes(keypair_json.as_bytes(), 0o600)
    }

    /// Derive the public projection by invoking yggdrasil statically
    /// against the persisted keypair file. Requires the keypair file
    /// to exist; call `ensure` first.
    pub fn projection(&self, yggdrasil_binary: &str) -> Result<YggdrasilProjection> {
        let public_key = self.derive(yggdrasil_binary, "-publickey")?;
        let address = self.derive(yggdrasil_binary, "-address")?;
        Ok(YggdrasilProjection {
            public_key,
            address,
        })
    }

    fn derive(&self, yggdrasil_binary: &str, flag: &str) -> Result<String> {
        let output = Command::new(yggdrasil_binary)
            .arg("-useconffile")
            .arg(&self.path)
            .arg(flag)
            .output()
            .map_err(|error| {
                Error::Yggdrasil(format!("invoke {yggdrasil_binary} {flag}: {error}"))
            })?;
        if !output.status.success() {
            return Err(Error::Yggdrasil(format!(
                "{yggdrasil_binary} {flag} exited {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            )));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    }
}

fn extract_private_key(json_bytes: &[u8]) -> Result<String> {
    let value: serde_json::Value = serde_json::from_slice(json_bytes).map_err(|error| {
        Error::Yggdrasil(format!(
            "yggdrasil -genconf output is not valid JSON: {error}"
        ))
    })?;
    let private_key = value
        .get("PrivateKey")
        .and_then(|field| field.as_str())
        .ok_or_else(|| {
            Error::Yggdrasil(
                "yggdrasil -genconf output missing string PrivateKey field".to_string(),
            )
        })?;
    if private_key.is_empty() {
        return Err(Error::Yggdrasil("PrivateKey is empty".to_string()));
    }
    Ok(private_key.to_string())
}
