use clap::{Args, Parser, Subcommand};
use clavifaber::error::{Error, Result};
use clavifaber::request::{
    CertificateAuthorityInitialization, CertificateVerification, ClaviFaberRequest,
    ClaviFaberResponse, CommandLine, IdentityDirectoryInitialization, NodeCertificateCreation,
    PublicKeyDerivation, ServerCertificateCreation,
};

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
        self.command.compatibility_command().run()
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Create a self-signed CA certificate from a GPG Ed25519 key
    CaInit(CertificateAuthorityInitializationArguments),

    /// Generate a P-256 server keypair + certificate signed by the CA
    ServerCert(ServerCertificateCreationArguments),

    /// Create an X.509 client certificate for a node's Ed25519 SSH pubkey
    NodeCert(NodeCertificateCreationArguments),

    /// Generate node identity complex (Ed25519 keypair) at first install
    ComplexInit(IdentityDirectoryInitializationArguments),

    /// Re-derive ssh.pub from the private key (run on every boot)
    DerivePubkey(PublicKeyDerivationArguments),

    /// Verify a certificate chains to the CA
    Verify(CertificateVerificationArguments),
}

impl Commands {
    fn compatibility_command(self) -> CompatibilityCommand {
        match self {
            Self::CaInit(arguments) => arguments.compatibility_command(),
            Self::ServerCert(arguments) => arguments.compatibility_command(),
            Self::NodeCert(arguments) => arguments.compatibility_command(),
            Self::ComplexInit(arguments) => arguments.compatibility_command(),
            Self::DerivePubkey(arguments) => arguments.compatibility_command(),
            Self::Verify(arguments) => arguments.compatibility_command(),
        }
    }
}

#[derive(Args)]
struct CertificateAuthorityInitializationArguments {
    #[arg(long)]
    keygrip: String,

    #[arg(long = "cn")]
    common_name: String,

    #[arg(long = "out")]
    output: String,
}

impl CertificateAuthorityInitializationArguments {
    fn compatibility_command(self) -> CompatibilityCommand {
        CompatibilityCommand {
            request: ClaviFaberRequest::CertificateAuthorityInitialization(
                CertificateAuthorityInitialization {
                    keygrip: self.keygrip,
                    common_name: self.common_name,
                    output: self.output,
                },
            ),
            mode: CompatibilityMode::CertificateAuthority,
        }
    }
}

#[derive(Args)]
struct ServerCertificateCreationArguments {
    #[arg(long = "ca-keygrip")]
    certificate_authority_keygrip: String,

    #[arg(long = "ca-cert")]
    certificate_authority_certificate: String,

    #[arg(long = "cn")]
    common_name: String,

    #[arg(long = "out-cert")]
    output_certificate: String,

    #[arg(long = "out-key")]
    output_private_key: String,
}

impl ServerCertificateCreationArguments {
    fn compatibility_command(self) -> CompatibilityCommand {
        CompatibilityCommand {
            request: ClaviFaberRequest::ServerCertificateCreation(ServerCertificateCreation {
                certificate_authority_keygrip: self.certificate_authority_keygrip,
                certificate_authority_certificate: self.certificate_authority_certificate,
                common_name: self.common_name,
                output_certificate: self.output_certificate,
                output_private_key: self.output_private_key,
            }),
            mode: CompatibilityMode::ServerCertificate,
        }
    }
}

#[derive(Args)]
struct NodeCertificateCreationArguments {
    #[arg(long = "ca-keygrip")]
    certificate_authority_keygrip: String,

    #[arg(long = "ca-cert")]
    certificate_authority_certificate: String,

    #[arg(long = "ssh-pubkey")]
    open_ssh_public_key: String,

    #[arg(long = "cn")]
    common_name: String,

    #[arg(long = "out")]
    output: String,
}

impl NodeCertificateCreationArguments {
    fn compatibility_command(self) -> CompatibilityCommand {
        CompatibilityCommand {
            request: ClaviFaberRequest::NodeCertificateCreation(NodeCertificateCreation {
                certificate_authority_keygrip: self.certificate_authority_keygrip,
                certificate_authority_certificate: self.certificate_authority_certificate,
                open_ssh_public_key: self.open_ssh_public_key,
                common_name: self.common_name,
                output: self.output,
            }),
            mode: CompatibilityMode::NodeCertificate,
        }
    }
}

#[derive(Args)]
struct IdentityDirectoryInitializationArguments {
    #[arg(long = "dir")]
    directory: String,
}

impl IdentityDirectoryInitializationArguments {
    fn compatibility_command(self) -> CompatibilityCommand {
        CompatibilityCommand {
            request: ClaviFaberRequest::IdentityDirectoryInitialization(
                IdentityDirectoryInitialization {
                    directory: self.directory,
                },
            ),
            mode: CompatibilityMode::PublicKeyProjection,
        }
    }
}

#[derive(Args)]
struct PublicKeyDerivationArguments {
    #[arg(long = "dir")]
    directory: String,
}

impl PublicKeyDerivationArguments {
    fn compatibility_command(self) -> CompatibilityCommand {
        CompatibilityCommand {
            request: ClaviFaberRequest::PublicKeyDerivation(PublicKeyDerivation {
                directory: self.directory,
            }),
            mode: CompatibilityMode::PublicKeyProjection,
        }
    }
}

#[derive(Args)]
struct CertificateVerificationArguments {
    #[arg(long = "ca-cert")]
    certificate_authority_certificate: String,

    #[arg(long = "cert")]
    certificate: String,
}

impl CertificateVerificationArguments {
    fn compatibility_command(self) -> CompatibilityCommand {
        CompatibilityCommand {
            request: ClaviFaberRequest::CertificateVerification(CertificateVerification {
                certificate_authority_certificate: self.certificate_authority_certificate,
                certificate: self.certificate,
            }),
            mode: CompatibilityMode::CertificateVerification,
        }
    }
}

struct CompatibilityCommand {
    request: ClaviFaberRequest,
    mode: CompatibilityMode,
}

impl CompatibilityCommand {
    fn run(self) -> Result<()> {
        let response = self.request.execute()?;
        self.mode.print(response)
    }
}

enum CompatibilityMode {
    CertificateAuthority,
    ServerCertificate,
    NodeCertificate,
    PublicKeyProjection,
    CertificateVerification,
}

impl CompatibilityMode {
    fn print(self, response: ClaviFaberResponse) -> Result<()> {
        match (self, response) {
            (
                Self::CertificateAuthority,
                ClaviFaberResponse::CertificateAuthorityCertificateWritten(written),
            ) => {
                eprintln!("CA certificate written to {}", written.output);
                Ok(())
            }
            (Self::ServerCertificate, ClaviFaberResponse::ServerCertificateWritten(written)) => {
                eprintln!("Server certificate: {}", written.certificate);
                eprintln!("Server private key: {}", written.private_key);
                Ok(())
            }
            (Self::NodeCertificate, ClaviFaberResponse::NodeCertificateWritten(written)) => {
                eprintln!("Node certificate written to {}", written.output);
                Ok(())
            }
            (Self::PublicKeyProjection, ClaviFaberResponse::PublicKeyProjection(projection)) => {
                println!("{}", projection.open_ssh_public_key);
                Ok(())
            }
            (Self::CertificateVerification, ClaviFaberResponse::CertificateChainVerified(_)) => {
                eprintln!("OK: certificate chains to CA");
                Ok(())
            }
            (_, unexpected) => Err(Error::Parse(format!(
                "unexpected response for compatibility command: {unexpected:?}"
            ))),
        }
    }
}

struct Process {
    command_line: CommandLine,
}

impl Process {
    fn from_env() -> Self {
        Self {
            command_line: CommandLine::from_env(),
        }
    }

    fn run(self) -> Result<()> {
        if let Some(request) = self.command_line.inline_request()? {
            let response = request.execute()?;
            println!("{}", response.to_nota()?);
            return Ok(());
        }

        Cli::parse().run()
    }
}

fn main() {
    if let Err(error) = Process::from_env().run() {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
