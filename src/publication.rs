use crate::actors::publication_collector::CollectPublication;
use crate::actors::runtime_root::RuntimeRoot;
use crate::actors::translate_send_error;
use crate::error::Result;
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
    pub async fn collect(self) -> Result<PublicKeyPublication> {
        let runtime = RuntimeRoot::start(None);
        runtime
            .publication_collector
            .ask(CollectPublication {
                node_name: self.node_name,
                directory: PathBuf::from(self.directory),
                yggdrasil_address: self.yggdrasil_address,
                yggdrasil_public_key: self.yggdrasil_public_key,
                wifi_client_certificate_pem: self.wifi_client_certificate_pem,
            })
            .await
            .map_err(translate_send_error)
    }
}
