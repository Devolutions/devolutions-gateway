use saphir::Method;
use saphir::*;
use crate::config::Config;
use crate::jet_client::JetAssociationsMap;
use uuid::Uuid;
use crate::jet::association::Association;
use jet_proto::JET_VERSION_V2;
use crate::jet::candidate::Candidate;
use crate::jet_client::JET_INSTANCE;

struct ControllerData {
    config: Config,
    jet_associations: JetAssociationsMap,
}

pub struct JetController {
    dispatch: ControllerDispatch<ControllerData>,
}

impl JetController {
    pub fn new(config: Config, jet_associations: JetAssociationsMap) -> Self {
        let dispatch = ControllerDispatch::new(ControllerData {config, jet_associations});
        dispatch.add(Method::POST, "/association/<association_id>", ControllerData::create_association);
        dispatch.add(Method::POST, "/gather/<association_id>", ControllerData::gather_candidate);

        JetController { dispatch }
    }
}

impl Controller for JetController {
    fn handle(&self, req: &mut SyncRequest, res: &mut SyncResponse) {
        self.dispatch.dispatch(req, res);
    }

    fn base_path(&self) -> &str {
        "/jet"
    }
}

impl ControllerData {
    fn create_association(&self, req: &SyncRequest, res: &mut SyncResponse) {
        res.status(StatusCode::BAD_REQUEST);

        if let Some(association_id) = req.captures().get("association_id") {
            if let Ok(uuid) = Uuid::parse_str(association_id) {
                if let Ok(mut jet_associations) = self.jet_associations.lock() {
                    if !jet_associations.contains_key(&uuid) {
                        jet_associations.insert(uuid, Association::new(uuid, JET_VERSION_V2));
                        res.status(StatusCode::OK);
                    }
                }
            }
        }
    }

    fn gather_candidate(&self, req: &SyncRequest, res: &mut SyncResponse) {
        res.status(StatusCode::BAD_REQUEST);

        if let Some(association_id) = req.captures().get("association_id") {
            if let Ok(uuid) = Uuid::parse_str(association_id) {
                if let Ok(mut jet_associations) = self.jet_associations.lock() {
                    if let Some(association) = jet_associations.get_mut(&uuid) {

                        if association.get_candidates().len() == 0 {
                            for listener in self.config.listeners() {
                                if let Some(candidate) = Candidate::new(&format!("{}://{}:{}", listener.scheme(), JET_INSTANCE.clone(), listener.port_or_known_default().unwrap_or(8080))) {
                                    association.add_candidate(candidate);
                                }
                            }
                        }

                        let body = association.gather_candidate();
                        res.body(body.to_string());
                        res.status(StatusCode::OK);
                    }
                }
            }
        }
    }
}

