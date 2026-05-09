use crate::error::{Error, Result};
use crate::util::AssuanLine;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::process::Command;

/// Client for gpg-agent's Assuan protocol.
pub struct GpgAgent {
    stream: BufReader<UnixStream>,
}

impl GpgAgent {
    pub fn connect() -> Result<Self> {
        let output = Command::new("gpgconf")
            .args(["--list-dirs", "agent-socket"])
            .output()
            .map_err(|e| Error::Gpg(format!("gpgconf: {e}")))?;

        let socket_path = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if socket_path.is_empty() {
            return Err(Error::Gpg(
                "gpgconf returned empty agent-socket path".into(),
            ));
        }

        let raw = UnixStream::connect(&socket_path)
            .map_err(|e| Error::Gpg(format!("connect to {socket_path}: {e}")))?;
        let mut agent = Self {
            stream: BufReader::new(raw),
        };

        let greeting = agent.read_line()?;
        if !greeting.starts_with("OK") {
            return Err(Error::Gpg(format!("unexpected greeting: {greeting}")));
        }

        Ok(agent)
    }

    /// Sign a hash using the specified keygrip.
    /// Returns raw signature bytes (Ed25519: 64 bytes, ECDSA: DER-encoded).
    pub fn sign(&mut self, keygrip: &str, hash_hex: &str) -> Result<Vec<u8>> {
        self.send_command(&format!("SIGKEY {keygrip}"))?;
        self.expect_ok()?;

        self.send_command(&format!("SETHASH --hash=sha256 {hash_hex}"))?;
        self.expect_ok()?;

        self.send_command("PKSIGN")?;
        let signature_expression = self.read_data_response()?;
        SignatureExpression::new(&signature_expression).signature_bytes()
    }

    /// Read a public key from gpg-agent using the READKEY command.
    /// Returns the raw Ed25519 public key bytes (32 bytes).
    pub fn readkey(&mut self, keygrip: &str) -> Result<Vec<u8>> {
        self.send_command(&format!("READKEY {keygrip}"))?;
        let data = self.read_data_response()?;
        extract_sexp_q_value(&data).ok_or_else(|| {
            Error::Gpg("could not extract public key from READKEY S-expression".into())
        })
    }

    fn send_command(&mut self, cmd: &str) -> Result<()> {
        let stream = self.stream.get_mut();
        stream
            .write_all(format!("{cmd}\n").as_bytes())
            .map_err(|e| Error::Gpg(format!("write: {e}")))?;
        stream
            .flush()
            .map_err(|e| Error::Gpg(format!("flush: {e}")))
    }

    fn read_line(&mut self) -> Result<String> {
        let mut line = String::new();
        self.stream
            .read_line(&mut line)
            .map_err(|e| Error::Gpg(format!("read: {e}")))?;
        Ok(line.trim_end().to_string())
    }

    fn read_raw_line(&mut self) -> Result<Vec<u8>> {
        let mut raw_line = Vec::new();
        self.stream
            .read_until(b'\n', &mut raw_line)
            .map_err(|e| Error::Gpg(format!("read: {e}")))?;
        while raw_line.last() == Some(&b'\n') || raw_line.last() == Some(&b'\r') {
            raw_line.pop();
        }
        Ok(raw_line)
    }

    fn expect_ok(&mut self) -> Result<()> {
        let line = self.read_line()?;
        if line.starts_with("OK") {
            Ok(())
        } else if line.starts_with("ERR") {
            Err(Error::Gpg(line))
        } else {
            Err(Error::Gpg(format!("unexpected response: {line}")))
        }
    }

    fn read_data_response(&mut self) -> Result<Vec<u8>> {
        let mut data = Vec::new();
        loop {
            let line = self.read_raw_line()?;
            if line.starts_with(b"D ") {
                data.extend(AssuanLine::new(&line[2..]).decoded_bytes());
            } else if line.starts_with(b"OK") {
                break;
            } else if line.starts_with(b"ERR") {
                return Err(Error::Gpg(String::from_utf8_lossy(&line).into_owned()));
            } else if line.starts_with(b"INQUIRE") {
                self.send_command("END")?;
            }
        }
        Ok(data)
    }
}

struct SignatureExpression<'a> {
    data: &'a [u8],
}

impl<'a> SignatureExpression<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    fn signature_bytes(&self) -> Result<Vec<u8>> {
        let first_component = extract_sexp_value(self.data, b"r")
            .ok_or_else(|| Error::Gpg("missing 'r' in signature S-expression".into()))?;
        let second_component = extract_sexp_value(self.data, b"s")
            .ok_or_else(|| Error::Gpg("missing 's' in signature S-expression".into()))?;

        let mut signature = Vec::with_capacity(first_component.len() + second_component.len());
        signature.extend_from_slice(first_component);
        signature.extend_from_slice(second_component);
        Ok(signature)
    }
}

fn extract_sexp_value<'a>(data: &'a [u8], tag: &[u8]) -> Option<&'a [u8]> {
    let needle_prefix = format!("(1:{}", String::from_utf8_lossy(tag));
    let needle = needle_prefix.as_bytes();

    let pos = data.windows(needle.len()).position(|w| w == needle)?;
    let mut i = pos + needle.len();

    let mut len_str = String::new();
    while i < data.len() && data[i].is_ascii_digit() {
        len_str.push(data[i] as char);
        i += 1;
    }
    if i >= data.len() || data[i] != b':' {
        return None;
    }
    i += 1;

    let len: usize = len_str.parse().ok()?;
    if i + len > data.len() {
        return None;
    }
    Some(&data[i..i + len])
}

/// Extract Ed25519 public key from READKEY S-expression.
fn extract_sexp_q_value(data: &[u8]) -> Option<Vec<u8>> {
    let needle = b"(1:q";
    let pos = data.windows(needle.len()).position(|w| w == needle)?;
    let mut i = pos + needle.len();

    let mut len_str = String::new();
    while i < data.len() && data[i].is_ascii_digit() {
        len_str.push(data[i] as char);
        i += 1;
    }
    if i >= data.len() || data[i] != b':' {
        return None;
    }
    i += 1;

    let len: usize = len_str.parse().ok()?;
    if i + len > data.len() {
        return None;
    }

    let mut key_data = data[i..i + len].to_vec();
    if key_data.len() == 33 && key_data[0] == 0x40 {
        key_data.remove(0);
    }
    Some(key_data)
}
