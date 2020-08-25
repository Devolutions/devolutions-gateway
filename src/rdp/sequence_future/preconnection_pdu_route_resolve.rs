use std::{
    io,
    sync::Arc,
    borrow::Cow
};

use slog_scope::{debug, warn};
use tokio::{
    codec::Framed,
    net::tcp::TcpStream,
};
use url::Url;
use ironrdp::nego::Request as NegotiationRequest;
use picky::jose::jwt::{Jwt, JwtDate, JwtValidator};
use chrono::Utc;
use bytes::BytesMut;

use crate::{
    transport::{
        connection_accept::{ConnectionAcceptTransport, ConnectionAcceptTransportResult},
    },
    rdp::sequence_future::{FutureState, NextStream, SequenceFutureProperties},
    config::Config,
};

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct RoutingClaims {
    dst_hst: Cow<'static, str>,
    jet_ap: Cow<'static, str>,
}

pub struct PreconnectionPduRoute {
    pub dest_host: Url
}

pub enum PreconnectionPduRouteResolveFeatureResult {
    RoutingRequest(TcpStream, PreconnectionPduRoute, BytesMut),
    NegotiationRequest(TcpStream, NegotiationRequest),
}

pub struct PreconnectionPduRouteResolveFeature {
    routing_info: Option<(PreconnectionPduRoute, BytesMut)>,
    negotiation_pdu: Option<NegotiationRequest>,

    config: Arc<Config>,
}

impl PreconnectionPduRouteResolveFeature {
    pub fn new(config: Arc<Config>) -> Self {
        Self {
            routing_info: None,
            negotiation_pdu: None,
            config,
        }
    }
}

impl SequenceFutureProperties<TcpStream, ConnectionAcceptTransport> for PreconnectionPduRouteResolveFeature {
    type Item = PreconnectionPduRouteResolveFeatureResult;

    fn process_pdu(&mut self, request: ConnectionAcceptTransportResult) -> io::Result<Option<()>> {
        debug!("Processing PDU...");
        match request {
            ConnectionAcceptTransportResult::PreconnectionPdu(preconnection_pdu, leftover_data) => {
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

                    self.routing_info = Some((PreconnectionPduRoute { dest_host }, leftover_data));
                    // Response is not required at all
                    Ok(None)
                })
            },
            ConnectionAcceptTransportResult::NegotiationWithClient(pdu) => {
                self.negotiation_pdu = Some(pdu);
                Ok(None)
            },
        }
    }

    fn return_item(
        &mut self,
        mut client: Option<Framed<TcpStream, ConnectionAcceptTransport>>,
        _server: Option<Framed<TcpStream, ConnectionAcceptTransport>>,
    ) -> Self::Item {
        debug!("Successfully processed Preconnection PDU");

        let client = client
            .take()
            .expect("The client's stream must exist in a return_item method for Preconnection PDU")
            .into_inner();

        if self.routing_info.is_some() {
            let (route, leftover_data) = self.routing_info.take().unwrap();
            return PreconnectionPduRouteResolveFeatureResult::RoutingRequest(client, route, leftover_data);
        }

        let negotiation_pdu = self.negotiation_pdu
            .take()
            .expect("Invalid state: future parsing stage should set either negotiation pdu or preconnection pdu route");

        PreconnectionPduRouteResolveFeatureResult::NegotiationRequest(client, negotiation_pdu)
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

