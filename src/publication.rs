//! The typed `publication.nota` record clavifaber writes to a host's
//! public-readable directory. Other hosts (or whatever the cluster
//! consumer becomes) read this file to learn the host's public key
//! material.
//!
//! Today the only writer is `PublicKeyPublicationWriting` in
//! `src/request.rs`. Today the only reader is `cat publication.nota`
//! during diagnostic and `tests/publication.rs` (round-trip).

use crate::yggdrasil::YggdrasilProjection;
use nota_next::{NotaDecode, NotaEncode};

#[derive(Debug, Clone, PartialEq, Eq, NotaDecode, NotaEncode)]
pub struct PublicKeyPublication {
    pub node_name: String,
    pub open_ssh_public_key: String,
    pub yggdrasil: Option<YggdrasilProjection>,
    pub wifi_client_certificate: Option<WifiClientCertificate>,
}

#[derive(Debug, Clone, PartialEq, Eq, NotaDecode, NotaEncode)]
pub struct WifiClientCertificate {
    pub pem: String,
}
