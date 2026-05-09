use crate::error::Result;
use crate::identity::IdentityDirectory;
use nota_codec::NotaRecord;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct PublicKeyPublication {
    pub node_name: String,
    pub open_ssh_public_key: String,
    pub yggdrasil_address: Option<String>,
    pub yggdrasil_public_key: Option<String>,
    pub wifi_client_certificate_pem: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaRecord)]
pub struct PublicKeyPublicationRequest {
    pub node_name: String,
    pub directory: String,
    pub yggdrasil_address: Option<String>,
    pub yggdrasil_public_key: Option<String>,
    pub wifi_client_certificate_pem: Option<String>,
}

impl PublicKeyPublicationRequest {
    pub fn collect(self) -> Result<PublicKeyPublication> {
        let identity_directory = IdentityDirectory::from_path(PathBuf::from(&self.directory));
        let identity = identity_directory.load_identity()?;
        Ok(PublicKeyPublication {
            node_name: self.node_name,
            open_ssh_public_key: identity.open_ssh_public_key(),
            yggdrasil_address: self.yggdrasil_address,
            yggdrasil_public_key: self.yggdrasil_public_key,
            wifi_client_certificate_pem: self.wifi_client_certificate_pem,
        })
    }
}
