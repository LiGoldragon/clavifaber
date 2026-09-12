//! Yggdrasil host identity material.

use crate::error::{Error, Result};
use crate::util::AtomicFile;
use std::path::{Path, PathBuf};
use std::process::Command;

pub use crate::generated::clavifaber::YggdrasilProjection;

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
        AtomicFile::new(self.path.clone()).write_bytes(
            format!("{{\"PrivateKey\":\"{private_key}\"}}\n").as_bytes(),
            0o600,
        )
    }

    pub fn projection(&self, yggdrasil_binary: &str) -> Result<YggdrasilProjection> {
        let public_key = self.derive(yggdrasil_binary, "-publickey")?;
        let address = self.derive(yggdrasil_binary, "-address")?;
        Ok(YggdrasilProjection {
            first_string: address,
            second_string: public_key,
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
