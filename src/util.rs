use crate::error::{Error, Result};
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

pub struct AtomicFile {
    path: PathBuf,
}

impl AtomicFile {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn write_bytes(&self, contents: &[u8], mode: u32) -> Result<()> {
        let temporary_path = self.path.with_extension("tmp");
        let mut temporary_file = fs::File::create(&temporary_path).map_err(|source| Error::Io {
            path: temporary_path.clone(),
            source,
        })?;
        temporary_file
            .write_all(contents)
            .map_err(|source| Error::Io {
                path: temporary_path.clone(),
                source,
            })?;
        temporary_file.sync_all().map_err(|source| Error::Io {
            path: temporary_path.clone(),
            source,
        })?;
        drop(temporary_file);
        fs::set_permissions(&temporary_path, fs::Permissions::from_mode(mode)).map_err(
            |source| Error::Io {
                path: temporary_path.clone(),
                source,
            },
        )?;
        fs::rename(&temporary_path, &self.path).map_err(|source| Error::Io {
            path: self.path.clone(),
            source,
        })?;
        Ok(())
    }
}

pub struct AssuanLine<'a> {
    bytes: &'a [u8],
}

impl<'a> AssuanLine<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn decoded_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.bytes.len());
        let mut index = 0;
        while index < self.bytes.len() {
            if self.bytes[index] == b'%'
                && index + 2 < self.bytes.len()
                && let (Some(high), Some(low)) = (
                    hexadecimal_value(self.bytes[index + 1]),
                    hexadecimal_value(self.bytes[index + 2]),
                )
            {
                result.push(high << 4 | low);
                index += 3;
                continue;
            }
            result.push(self.bytes[index]);
            index += 1;
        }
        result
    }
}

fn hexadecimal_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
