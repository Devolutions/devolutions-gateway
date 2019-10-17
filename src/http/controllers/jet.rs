use saphir::Method;
use saphir::*;
use uuid::Uuid;
use jet_proto::JET_VERSION_V2;
use std::time::{Duration, Instant};
use log::info;
use tokio::runtime::TaskExecutor;
use futures::future::{ok};

use crate::jet::association::Association;
use crate::config::Config;
use crate::jet_client::JetAssociationsMap;
use crate::utils::association::{RemoveAssociation, ACCEPT_REQUEST_TIMEOUT_SEC};
use crate::jet::candidate::Candidate;
use tokio::timer::Delay;
use futures::Future;
use crate::http::controllers::utils::SyncResponseUtil;

struct ControllerData {
    config: Config,
    jet_associations: JetAssociationsMap,
    executor_handle: TaskExecutor,
}

pub struct JetController {
    dispatch: ControllerDispatch<ControllerData>,
}

impl JetController {
    pub fn new(config: Config, jet_associations: JetAssociationsMap, executor_handle: TaskExecutor) -> Self {
        let dispatch = ControllerDispatch::new(ControllerData {config, jet_associations, executor_handle});
        dispatch.add(Method::GET, "/association", ControllerData::get_associations);
        dispatch.add(Method::POST, "/association/<association_id>", ControllerData::create_association);
        dispatch.add(Method::POST, "/association/<association_id>/candidates", ControllerData::gather_association_candidates);

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
    fn get_associations(&self, _req: &SyncRequest, res: &mut SyncResponse) {
        res.status(StatusCode::BAD_REQUEST);

        if let Ok(associations) = self.jet_associations.lock() {
            let associations_vec: Vec<&Association> = associations.values().collect();
            let quantity = associations_vec.len();

            let body = json!({"associations": associations_vec,
                              "associations_qty": quantity});

            if let Ok(body) = serde_json::to_string(&body) {
                res.json_body(body);
                res.status(StatusCode::OK);
            }
        } else {
            res.status(StatusCode::INTERNAL_SERVER_ERROR);
            return;
        }
    }

    fn create_association(&self, req: &SyncRequest, res: &mut SyncResponse) {
        res.status(StatusCode::BAD_REQUEST);

        if let Some(association_id) = req.captures().get("association_id") {
            if let Ok(uuid) = Uuid::parse_str(association_id) {
                if let Ok(mut jet_associations) = self.jet_associations.lock() {
                    if !jet_associations.contains_key(&uuid) {
                        jet_associations.insert(uuid, Association::new(uuid, JET_VERSION_V2));
                        res.status(StatusCode::OK);

                        // Start timeout to remove the association if no connect is received
                        let jet_associations = self.jet_associations.clone();
                        let timeout = Delay::new(Instant::now() + Duration::from_secs(ACCEPT_REQUEST_TIMEOUT_SEC as u64));
                        self.executor_handle.spawn(timeout.then(move |_| {
                            RemoveAssociation::new(jet_associations, uuid, None).then(move |res| {
                                if let Ok(true) = res {
                                    info!(
                                        "No connect request received with association {}. Association removed!",
                                        uuid
                                    );
                                }
                                ok(())
                            })
                        }));

                    }
                }
            }
        }
    }

    fn gather_association_candidates(&self, req: &SyncRequest, res: &mut SyncResponse) {
        res.status(StatusCode::BAD_REQUEST);

        if let Some(association_id) = req.captures().get("association_id") {
            if let Ok(uuid) = Uuid::parse_str(association_id) {
                if let Ok(mut jet_associations) = self.jet_associations.lock() {
                    if let Some(association) = jet_associations.get_mut(&uuid) {

                        if association.get_candidates().len() == 0 {
                            for listener in self.config.listeners() {
                                if let Some(candidate) = Candidate::new(&format!("{}://{}:{}", listener.scheme(), self.config.jet_instance(), listener.port_or_known_default().unwrap_or(8080))) {
                                    association.add_candidate(candidate);
                                }
                            }
                        }

                        let body = association.gather_candidate();
                        res.json_body(body.to_string());
                        res.status(StatusCode::OK);
                    }
                }
            }
        }
    }
}

