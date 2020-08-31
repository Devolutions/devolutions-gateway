use jet_proto::JET_VERSION_V2;
use saphir::{Method, *};
use slog_scope::info;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::runtime::TaskExecutor;
use uuid::Uuid;

use crate::{
    config::Config,
    http::controllers::{health::build_health_response, utils::SyncResponseUtil},
    jet::{
        association::{Association, AssociationResponse},
        candidate::Candidate,
    },
    jet_client::JetAssociationsMap,
    utils::association::{RemoveAssociation, ACCEPT_REQUEST_TIMEOUT_SEC},
};
use futures::Future;
use std::collections::HashMap;
use tokio::timer::Delay;

struct ControllerData {
    config: Arc<Config>,
    jet_associations: JetAssociationsMap,
    executor_handle: TaskExecutor,
}

pub struct JetController {
    dispatch: ControllerDispatch<ControllerData>,
}

impl JetController {
    pub fn new(config: Arc<Config>, jet_associations: JetAssociationsMap, executor_handle: TaskExecutor) -> Self {
        let dispatch = ControllerDispatch::new(ControllerData {
            config,
            jet_associations,
            executor_handle,
        });
        dispatch.add(Method::GET, "/association", ControllerData::get_associations);
        dispatch.add(
            Method::POST,
            "/association/<association_id>",
            ControllerData::create_association,
        );
        dispatch.add(
            Method::POST,
            "/association/<association_id>/candidates",
            ControllerData::gather_association_candidates,
        );
        dispatch.add(Method::GET, "/health", ControllerData::health);

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
    fn get_associations(&self, req: &SyncRequest, res: &mut SyncResponse) {
        res.status(StatusCode::BAD_REQUEST);

        let mut with_detail = false;

        if let Some(query) = req.uri().query() {
            if let Ok(params) = ::serde_urlencoded::from_str::<HashMap<String, String>>(query) {
                if let Some(detail) = params.get("detail") {
                    with_detail = detail.parse::<bool>().unwrap_or(false);
                }
            }
        }

        let associations_response: Vec<AssociationResponse>;
        if let Ok(associations) = self.jet_associations.lock() {
            associations_response = associations
                .values()
                .map(|association| AssociationResponse::from(association, with_detail))
                .collect();
        } else {
            res.status(StatusCode::INTERNAL_SERVER_ERROR);
            return;
        }

        if let Ok(body) = serde_json::to_string(&associations_response) {
            res.json_body(body);
            res.status(StatusCode::OK);
        }
    }

    fn create_association(&self, req: &SyncRequest, res: &mut SyncResponse) {
        res.status(StatusCode::BAD_REQUEST);

        if let Some(association_id) = req.captures().get("association_id") {
            if let Ok(uuid) = Uuid::parse_str(association_id) {
                if let Ok(mut jet_associations) = self.jet_associations.lock() {
                    if !jet_associations.contains_key(&uuid) {
                        jet_associations.insert(uuid, Association::new(uuid, JET_VERSION_V2));
                        start_remove_association_future(
                            self.executor_handle.clone(),
                            self.jet_associations.clone(),
                            uuid,
                        );

                        res.status(StatusCode::OK);
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
                    let association = match jet_associations.get_mut(&uuid) {
                        Some(association) => association,
                        None => {
                            // The create could be done on a JET and the gather on a different one. We create it as workaround for now.
                            jet_associations.insert(uuid, Association::new(uuid, JET_VERSION_V2));
                            start_remove_association_future(
                                self.executor_handle.clone(),
                                self.jet_associations.clone(),
                                uuid,
                            );
                            jet_associations
                                .get_mut(&uuid)
                                .expect("We just added the association, it should be there!")
                        }
                    };

                    if association.get_candidates().is_empty() {
                        for listener in self.config.listeners() {
                            if let Some(candidate) =
                                Candidate::new(&listener.external_url.to_string().trim_end_matches('/'))
                            {
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

    fn health(&self, _req: &SyncRequest, res: &mut SyncResponse) {
        build_health_response(res, self.config.jet_instance());
    }
}

pub fn start_remove_association_future(
    executor_handle: TaskExecutor,
    jet_associations: JetAssociationsMap,
    uuid: Uuid,
) {
    executor_handle.spawn(create_remove_association_future(jet_associations, uuid));
}

pub fn create_remove_association_future(
    jet_associations: JetAssociationsMap,
    uuid: Uuid,
) -> impl Future<Item = (), Error = ()> + Send {
    // Start timeout to remove the association if no connect is received
    let timeout = Delay::new(Instant::now() + Duration::from_secs(ACCEPT_REQUEST_TIMEOUT_SEC as u64));

    timeout.then(move |_| {
        RemoveAssociation::new(jet_associations, uuid, None).then(move |res| {
            if let Ok(true) = res {
                info!(
                    "No connect request received with association {}. Association removed!",
                    uuid
                );
            }

            Ok(())
        })
    })
}
