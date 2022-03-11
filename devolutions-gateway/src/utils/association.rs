use crate::jet::candidate::CandidateState;
use crate::jet_client::JetAssociationsMap;
use tokio::time::Duration;
use uuid::Uuid;

pub const ACCEPT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub fn remove_jet_association(
    jet_associations: &JetAssociationsMap,
    association_id: Uuid,
    candidate_id: Option<Uuid>,
) -> bool {
    let mut jet_associations = jet_associations.lock();

    if let Some(association) = jet_associations.get_mut(&association_id) {
        if let Some(candidate_id) = candidate_id {
            if let Some(candidate) = association.get_candidate_mut(candidate_id) {
                candidate.set_state(CandidateState::Final);
            }
        }
        if !association.is_connected() {
            debug!("Association {} is removed!", association_id);
            let removed = jet_associations.remove(&association_id).is_some();
            return removed;
        } else {
            debug!("Association still connected!");
        }
    }

    // Jet association already removed or still connected
    false
}
