//! The datom text a corporate value carries out.

use datom_codec::{Datomizable, Path};
use protos::{Compactable, Protosizable};

/// The whole ascent for a datomizable value: datomize, protosize, print on one line.
pub trait DatomTexting {
    fn datom_text(&self) -> String;
}

impl<T: Datomizable> DatomTexting for T {
    fn datom_text(&self) -> String {
        self.datomize(Path::new()).protosize().compact()
    }
}
