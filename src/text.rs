//! The datom text a corporate value carries out.

use datom_codec::{Datomizable, Path};
use protos::{Protosizable, Textualizable};

/// The whole ascent for a datomizable value: datomize, protosize, print.
pub trait DatomTexting {
    fn datom_text(&self) -> String;
}

impl<T: Datomizable> DatomTexting for T {
    fn datom_text(&self) -> String {
        self.datomize(Path::new()).protosize().textualize()
    }
}
