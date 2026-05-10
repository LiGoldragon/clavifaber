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
use nota_codec::NotaRecord;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Per-host Yggdrasil identity plan declared in the Converge or
/// PublicKeyPublication request: where the persisted keypair file
/// lives. Mode 0600 enforced at write time.
#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct YggdrasilPlan {
    pub keypair_path: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YggdrasilProjection {
    pub public_key: String,
    pub address: String,
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
    let text = std::str::from_utf8(json_bytes).map_err(|error| {
        Error::Yggdrasil(format!("yggdrasil -genconf output not utf-8: {error}"))
    })?;
    let needle = "\"PrivateKey\"";
    let start = text.find(needle).ok_or_else(|| {
        Error::Yggdrasil("yggdrasil -genconf missing PrivateKey field".to_string())
    })?;
    let after_key = &text[start + needle.len()..];
    let after_colon = after_key
        .find(':')
        .ok_or_else(|| Error::Yggdrasil("PrivateKey missing colon".to_string()))?;
    let after_open = after_key[after_colon + 1..]
        .find('"')
        .ok_or_else(|| Error::Yggdrasil("PrivateKey missing opening quote".to_string()))?;
    let value_start = after_colon + 1 + after_open + 1;
    let close = after_key[value_start..]
        .find('"')
        .ok_or_else(|| Error::Yggdrasil("PrivateKey missing closing quote".to_string()))?;
    let value = &after_key[value_start..value_start + close];
    if value.is_empty() {
        return Err(Error::Yggdrasil("PrivateKey is empty".to_string()));
    }
    Ok(value.to_string())
}
