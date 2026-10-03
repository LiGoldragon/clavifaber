//! Generated values archive with rkyv and read back equal.

use clavifaber::request::{ClaviFaberRequest, YggdrasilKeypairSetup};

#[test]
fn generated_request_round_trips_through_rkyv() {
    let request = ClaviFaberRequest::YggdrasilKeypairSetup(YggdrasilKeypairSetup {
        string: "/var/lib/clavifaber/yggdrasil/keypair.json".to_owned(),
    });
    let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&request).unwrap();
    let read = rkyv::from_bytes::<ClaviFaberRequest, rkyv::rancor::Error>(&bytes).unwrap();
    assert_eq!(read, request);
}
