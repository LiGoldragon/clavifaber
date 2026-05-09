use clap::{Args, Parser, Subcommand};
use clavifaber::error::{Error, Result};
use clavifaber::identity::{IdentityDirectory, NodeIdentity};
use clavifaber::ssh_key::OpenSshPublicKey;
use clavifaber::{gpg_agent, x509};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "clavifaber",
    about = "GPG to X.509 certificate tool for CriomOS WiFi PKI"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

impl Cli {
    fn run(self) -> Result<()> {
        self.command.run()
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Create a self-signed CA certificate from a GPG Ed25519 key
    CaInit(CertificateAuthorityInitialization),

    /// Generate a P-256 server keypair + certificate signed by the CA
    ServerCert(ServerCertificateRequest),

    /// Create an X.509 client certificate for a node's Ed25519 SSH pubkey
    NodeCert(NodeCertificateRequest),

    /// Generate node identity complex (Ed25519 keypair) at first install
    ComplexInit(IdentityDirectoryInitialization),

    /// Re-derive ssh.pub from the private key (run on every boot)
    DerivePubkey(PublicKeyDerivation),

    /// Verify a certificate chains to the CA
    Verify(CertificateVerification),
}

impl Commands {
    fn run(self) -> Result<()> {
        match self {
            Self::CaInit(command) => command.run(),
            Self::ServerCert(command) => command.run(),
            Self::NodeCert(command) => command.run(),
            Self::ComplexInit(command) => command.run(),
            Self::DerivePubkey(command) => command.run(),
            Self::Verify(command) => command.run(),
        }
    }
}

#[derive(Args)]
struct CertificateAuthorityInitialization {
    #[arg(long)]
    keygrip: String,

    #[arg(long = "cn")]
    common_name: String,

    #[arg(long = "out")]
    output: PathBuf,
}

impl CertificateAuthorityInitialization {
    fn run(self) -> Result<()> {
        eprintln!("Creating CA certificate: CN={}", self.common_name);

        let public_key_bytes = export_ed25519_public_key_from_keygrip(&self.keygrip)?;

        let subject_public_key_info = spki::SubjectPublicKeyInfoOwned {
            algorithm: spki::AlgorithmIdentifierOwned {
                oid: der::asn1::ObjectIdentifier::new_unwrap("1.3.101.112"),
                parameters: None,
            },
            subject_public_key: der::asn1::BitString::from_bytes(&public_key_bytes)
                .map_err(|error| Error::Certificate(format!("BitString: {error}")))?,
        };

        let certificate_der =
            x509::create_ca_cert(&self.keygrip, &self.common_name, subject_public_key_info)?;
        let certificate_pem = x509::cert_to_pem(&certificate_der)?;

        fs::write(&self.output, &certificate_pem).map_err(|source| Error::Io {
            path: self.output.clone(),
            source,
        })?;
        eprintln!("CA certificate written to {}", self.output.display());
        Ok(())
    }
}

#[derive(Args)]
struct ServerCertificateRequest {
    #[arg(long = "ca-keygrip")]
    certificate_authority_keygrip: String,

    #[arg(long = "ca-cert")]
    certificate_authority_certificate: PathBuf,

    #[arg(long = "cn")]
    common_name: String,

    #[arg(long = "out-cert")]
    output_certificate: PathBuf,

    #[arg(long = "out-key")]
    output_private_key: PathBuf,
}

impl ServerCertificateRequest {
    fn run(self) -> Result<()> {
        eprintln!("Creating server certificate: CN={}", self.common_name);

        let certificate_authority_pem = fs::read_to_string(&self.certificate_authority_certificate)
            .map_err(|source| Error::Io {
                path: self.certificate_authority_certificate.clone(),
                source,
            })?;
        let certificate_authority_der = x509::pem_to_cert_der(&certificate_authority_pem)?;

        let (certificate_der, private_key_pem) = x509::create_server_cert(
            &self.certificate_authority_keygrip,
            &certificate_authority_der,
            &self.common_name,
        )?;
        let certificate_pem = x509::cert_to_pem(&certificate_der)?;

        fs::write(&self.output_certificate, &certificate_pem).map_err(|source| Error::Io {
            path: self.output_certificate.clone(),
            source,
        })?;
        fs::write(&self.output_private_key, &private_key_pem).map_err(|source| Error::Io {
            path: self.output_private_key.clone(),
            source,
        })?;

        eprintln!("Server certificate: {}", self.output_certificate.display());
        eprintln!("Server private key: {}", self.output_private_key.display());
        Ok(())
    }
}

#[derive(Args)]
struct NodeCertificateRequest {
    #[arg(long = "ca-keygrip")]
    certificate_authority_keygrip: String,

    #[arg(long = "ca-cert")]
    certificate_authority_certificate: PathBuf,

    #[arg(long = "ssh-pubkey")]
    open_ssh_public_key: String,

    #[arg(long = "cn")]
    common_name: String,

    #[arg(long = "out")]
    output: PathBuf,
}

impl NodeCertificateRequest {
    fn run(self) -> Result<()> {
        eprintln!("Creating node certificate: CN={}", self.common_name);

        let certificate_authority_pem = fs::read_to_string(&self.certificate_authority_certificate)
            .map_err(|source| Error::Io {
                path: self.certificate_authority_certificate.clone(),
                source,
            })?;
        let certificate_authority_der = x509::pem_to_cert_der(&certificate_authority_pem)?;

        let subject_public_key_info =
            OpenSshPublicKey::from_text(self.open_ssh_public_key)?.subject_public_key_info()?;
        let certificate_der = x509::create_node_cert(
            &self.certificate_authority_keygrip,
            &certificate_authority_der,
            subject_public_key_info,
            &self.common_name,
        )?;
        let certificate_pem = x509::cert_to_pem(&certificate_der)?;

        fs::write(&self.output, &certificate_pem).map_err(|source| Error::Io {
            path: self.output.clone(),
            source,
        })?;
        eprintln!("Node certificate written to {}", self.output.display());
        Ok(())
    }
}

#[derive(Args)]
struct IdentityDirectoryInitialization {
    #[arg(long = "dir")]
    directory: PathBuf,
}

impl IdentityDirectoryInitialization {
    fn run(self) -> Result<()> {
        let identity_directory = IdentityDirectory::from_path(self.directory.clone());
        match identity_directory.existing_identity()? {
            Some(existing_identity) => {
                let open_ssh_public_key = existing_identity.open_ssh_public_key();
                eprintln!(
                    "identity directory already exists at {}",
                    self.directory.display()
                );
                println!("{open_ssh_public_key}");
            }
            None => {
                eprintln!(
                    "Generating node identity directory at {}",
                    self.directory.display()
                );
                let identity = NodeIdentity::generate();
                identity_directory.write_identity(&identity)?;
                let open_ssh_public_key = identity.open_ssh_public_key();
                eprintln!("Identity generated. SSH public key:");
                println!("{open_ssh_public_key}");
            }
        }
        Ok(())
    }
}

#[derive(Args)]
struct PublicKeyDerivation {
    #[arg(long = "dir")]
    directory: PathBuf,
}

impl PublicKeyDerivation {
    fn run(self) -> Result<()> {
        let identity_directory = IdentityDirectory::from_path(self.directory);
        let identity = identity_directory.load_identity()?;
        let open_ssh_public_key = identity.open_ssh_public_key();
        identity_directory.write_public_key(&identity)?;
        println!("{open_ssh_public_key}");
        Ok(())
    }
}

#[derive(Args)]
struct CertificateVerification {
    #[arg(long = "ca-cert")]
    certificate_authority_certificate: PathBuf,

    #[arg(long = "cert")]
    certificate: PathBuf,
}

impl CertificateVerification {
    fn run(self) -> Result<()> {
        let certificate_authority_pem = fs::read_to_string(&self.certificate_authority_certificate)
            .map_err(|source| Error::Io {
                path: self.certificate_authority_certificate.clone(),
                source,
            })?;
        let certificate_pem =
            fs::read_to_string(&self.certificate).map_err(|source| Error::Io {
                path: self.certificate.clone(),
                source,
            })?;

        let certificate_authority_der = x509::pem_to_cert_der(&certificate_authority_pem)?;
        let certificate_der = x509::pem_to_cert_der(&certificate_pem)?;

        x509::verify_cert_chain(&certificate_authority_der, &certificate_der)?;
        eprintln!("OK: certificate chains to CA");
        Ok(())
    }
}

fn main() {
    if let Err(error) = Cli::parse().run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

/// Extract Ed25519 public key bytes from GPG via keygrip.
/// Tries `gpg --export-ssh-key` first, falls back to READKEY via agent.
fn export_ed25519_public_key_from_keygrip(keygrip: &str) -> Result<Vec<u8>> {
    let output = std::process::Command::new("gpg")
        .args(["--batch", "--export-ssh-key", &format!("{keygrip}!")])
        .output()
        .map_err(|error| Error::Gpg(format!("gpg --export-ssh-key: {error}")))?;

    if output.status.success() {
        let open_ssh_public_key_text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !open_ssh_public_key_text.is_empty() {
            return OpenSshPublicKey::from_text(open_ssh_public_key_text)?.raw_key_bytes();
        }
    }

    let mut agent = gpg_agent::GpgAgent::connect()?;
    agent.readkey(keygrip)
}
