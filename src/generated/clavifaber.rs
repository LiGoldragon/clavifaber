#![allow(dead_code, non_camel_case_types, non_snake_case)]
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub enum ClaviFaberRequest {
    CertificateAuthorityIssuance(CertificateAuthorityIssuance),
    ServerCertificateIssuance(ServerCertificateIssuance),
    ClientCertificateIssuance(ClientCertificateIssuance),
    CertificateChainVerification(CertificateChainVerification),
    YggdrasilKeypairSetup(YggdrasilKeypairSetup),
    PublicKeyPublicationWriting(PublicKeyPublicationWriting),
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub enum ClaviFaberResponse {
    CertificateAuthorityCertificateWritten(CertificateAuthorityCertificateWritten),
    ServerCertificateWritten(ServerCertificateWritten),
    ClientCertificateWritten(ClientCertificateWritten),
    CertificateChainVerified(CertificateChainVerified),
    YggdrasilKeypairSet(YggdrasilKeypairSet),
    PublicKeyPublicationWritten(PublicKeyPublicationWritten),
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct CertificateAuthorityIssuance {
    pub first_string: String,
    pub second_string: String,
    pub third_string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct CertificateAuthorityCertificateWritten {
    pub string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct ServerCertificateIssuance {
    pub first_string: String,
    pub second_string: String,
    pub third_string: String,
    pub fourth_string: String,
    pub fifth_string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct ServerCertificateWritten {
    pub first_string: String,
    pub second_string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct ClientCertificateIssuance {
    pub first_string: String,
    pub second_string: String,
    pub third_string: String,
    pub fourth_string: String,
    pub fifth_string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct ClientCertificateWritten {
    pub string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct CertificateChainVerification {
    pub first_string: String,
    pub second_string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct CertificateChainVerified {
    pub string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct YggdrasilKeypairSetup {
    pub string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct YggdrasilKeypairSet {
    pub string: String,
    pub yggdrasil_projection: YggdrasilProjection,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct PublicKeyPublicationWriting {
    pub first_string: String,
    pub open_ssh_public_key_location: OpenSshPublicKeyLocation,
    pub yggdrasil_keypair_location_option: Option<YggdrasilKeypairLocation>,
    pub wifi_client_certificate_location_option: Option<WifiClientCertificateLocation>,
    pub second_string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct OpenSshPublicKeyLocation {
    pub string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct YggdrasilKeypairLocation {
    pub string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct WifiClientCertificateLocation {
    pub string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct PublicKeyPublicationWritten {
    pub string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct PublicKeyPublication {
    pub first_string: String,
    pub second_string: String,
    pub yggdrasil_projection_option: Option<YggdrasilProjection>,
    pub wifi_client_certificate_option: Option<WifiClientCertificate>,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct WifiClientCertificate {
    pub string: String,
}
#[rustfmt::skip]
#[derive(datom_codec::Datomizable, datom_codec::Compositional, Clone, Debug, PartialEq)]
pub struct YggdrasilProjection {
    pub first_string: String,
    pub second_string: String,
}
