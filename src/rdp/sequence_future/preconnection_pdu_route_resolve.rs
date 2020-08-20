use std::{
    io,
    sync::Arc,
    borrow::Cow
};

use slog_scope::{debug, warn};
use tokio::codec::Framed;
use tokio::net::tcp::TcpStream;
use url::Url;

use ironrdp::PreconnectionPdu;

use picky::jose::jwt::{Jwt, JwtDate, JwtValidator};

use chrono::Utc;

use crate::{
    transport::preconnection::{PreconnectionPduTransport, PreconnectionPduFutureResult},
    rdp::sequence_future::{FutureState, NextStream, SequenceFutureProperties},
    config::Config,
};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct RoutingClaims {
    dst_hst: Cow<'static, str>,
    jet_ap: Cow<'static, str>,
}

pub struct PreconnectionPduRoute {
    pub dest_host: Url,
}

pub struct PreconnectionPduRouteResolveFeature {
    route: Option<PreconnectionPduRoute>,

    config: Arc<Config>,
}

impl PreconnectionPduRouteResolveFeature {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            route: None,
            config,
        }
    }
}

impl SequenceFutureProperties<TcpStream, PreconnectionPduTransport> for PreconnectionPduRouteResolveFeature {
    type Item = (TcpStream, Option<PreconnectionPduRoute>);

    fn process_pdu(&mut self, request: PreconnectionPduFutureResult) -> io::Result<Option<PreconnectionPdu>> {
        match request {
            PreconnectionPduFutureResult::PreconnectionPduDetected(preconnection_pdu) => {
                preconnection_pdu.payload.map_or(Ok(None), |jwt_token_base64| {

                    let current_timestamp = JwtDate::new(Utc::now().timestamp());

                    let validator = if let Some(provisioner_key) = &self.config.provisioner_public_key {
                        JwtValidator::strict(provisioner_key, &current_timestamp)
                    } else {
                        warn!("Provisioner key is not specified; Skipping signature validation");
                        JwtValidator::dangerous()
                            .current_date(&current_timestamp)
                            .expiration_check_required()
                            .not_before_check_required()
                    };

                    let jwt_token = Jwt::<RoutingClaims>::decode(&jwt_token_base64, &validator).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Failed to resolve route via JWT routing token: {}", e))
                    })?;

                    let claims = jwt_token.view_claims();

                    if &claims.jet_ap != "rdp" {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            "Non-rdp jwt-based routing via preconnection PDU is not supported"));
                    }


                    let route_url_str = if claims.dst_hst.starts_with("tcp://") {
                        claims.dst_hst.clone().into()
                    } else {
                        let mut url_str = String::from("tcp://");
                        url_str.push_str(&claims.dst_hst);
                        url_str
                    };

                    let dest_host = Url::parse(&route_url_str).map_err(|e| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!("Failed to parse routing url in JWT token: {}", e))
                    })?;

                    self.route = Some(PreconnectionPduRoute { dest_host });

                    // Response is not required at all
                    Ok(None)
                })
            },
            PreconnectionPduFutureResult::DifferentProtocolDetected => {
                Ok(None)
            },
        }
    }

    fn return_item(
        &mut self,
        mut client: Option<Framed<TcpStream, PreconnectionPduTransport>>,
        _server: Option<Framed<TcpStream, PreconnectionPduTransport>>,
    ) -> Self::Item {
        debug!("Successfully processed Preconnection PDU");
        (
            client
                .take()
                .expect("The client's stream must exist in a return_item method for Preconnection PDU")
                .into_inner(),
            self.route
                .take(),
        )
    }
    fn next_sender(&self) -> NextStream {
        NextStream::Client
    }
    fn next_receiver(&self) -> NextStream {
        NextStream::Client
    }
    fn sequence_finished(&self, future_state: FutureState) -> bool {
        // No response should be sent
        future_state == FutureState::ParseMessage
    }
}

