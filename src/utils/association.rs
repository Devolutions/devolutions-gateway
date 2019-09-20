use futures::{Future, Async};
use crate::jet_client::JetAssociationsMap;
use uuid::Uuid;

pub const ACCEPT_REQUEST_TIMEOUT_SEC: u32 = 5 * 60;

pub struct RemoveAssociation {
    jet_associations: JetAssociationsMap,
    association: Uuid,
}

impl RemoveAssociation {
    pub fn new(jet_associations: JetAssociationsMap, association: Uuid) -> Self {
        RemoveAssociation {
            jet_associations,
            association,
        }
    }
}

impl Future for RemoveAssociation {
    type Item = bool;
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
            let removed = jet_associations.remove(&self.association).is_some();
            Ok(Async::Ready(removed))
        } else {
            Ok(Async::NotReady)
        }
    }
}
