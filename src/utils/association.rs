use futures::{Future, Async};
use slog_scope::debug;
use uuid::Uuid;
use crate::jet::candidate::CandidateState;
use crate::jet_client::JetAssociationsMap;

pub const ACCEPT_REQUEST_TIMEOUT_SEC: u32 = 5 * 60;

pub struct RemoveAssociation {
    jet_associations: JetAssociationsMap,
    association_id: Uuid,
    candidate_id: Option<Uuid>,
}

impl RemoveAssociation {
    pub fn new(jet_associations: JetAssociationsMap, association_id: Uuid, candidate_id: Option<Uuid>) -> Self {
        RemoveAssociation {
            jet_associations,
            association_id,
            candidate_id
        }
    }
}

impl Future for RemoveAssociation {
    type Item = bool;
    type Error = ();

    fn poll(&mut self) -> Result<Async<<Self as Future>::Item>, <Self as Future>::Error> {
        if let Ok(mut jet_associations) = self.jet_associations.try_lock() {
            if let Some(association) = jet_associations.get_mut(&self.association_id) {
                if let Some(candidate_id) = self.candidate_id {
                    if let Some(candidate) = association.get_candidate_mut(candidate_id) {
                       candidate.set_state(CandidateState::Final);
                    }
                }
                if !association.is_connected() {
                    debug!("Association is removed!");
                    let removed = jet_associations.remove(&self.association_id).is_some();
                    return Ok(Async::Ready(removed));
                }
                else {
                    debug!("Association still connected!");
                }
            }

            // Jet association already removed or still connected
            Ok(Async::Ready(false))
        } else {
            // We want to be called again.
            futures::task::current().notify();
            Ok(Async::NotReady)
        }
    }
}
