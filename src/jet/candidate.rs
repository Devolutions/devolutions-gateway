use uuid::Uuid;
use url::Url;
use std::convert::{TryFrom, TryInto};
use crate::jet::TransportType;
use crate::transport::JetTransport;

#[derive(Clone)]
pub struct Candidate {
    id: Uuid,
    url: Option<Url>,
    ctype: CandidateType,
    state: CandidateState,
    association_id: Uuid,
    transport_type: TransportType,
    server_transport: Option<JetTransport>,
    client_transport: Option<JetTransport>,
}

impl Candidate {
    pub fn set_id(&mut self, id: Uuid) {
        self.id = id;
    }
    pub fn new_v1() -> Self {
        Candidate {
            id: Uuid::new_v4(),
            url: None,
            ctype: CandidateType::Relay,
            state: CandidateState::Initial,
            association_id: Uuid::nil(),
            transport_type: TransportType::Tcp,
            server_transport: None,
            client_transport: None,
        }
    }

    pub fn new(url: &str) -> Option<Self> {
        if let Ok(url) = Url::parse(url) {
            if let Ok(transport_type) = url.scheme().try_into() {
                return Some(Candidate {
                    id: Uuid::new_v4(),
                    url: Some(url),
                    ctype: CandidateType::Relay,
                    state: CandidateState::Initial,
                    association_id: Uuid::nil(),
                    transport_type: transport_type,
                    server_transport: None,
                    client_transport: None,
                });
            }
        }

        None
    }

    pub fn id(&self) -> Uuid {
        self.id.clone()
    }

    pub fn url(&self) -> Option<Url> {
        self.url.clone()
    }
    pub fn client_transport(&self) -> Option<JetTransport> {
        self.client_transport.clone()
    }

    pub fn server_transport(&self) -> Option<JetTransport> {
        self.server_transport.clone()
    }

    pub fn set_association_id(&mut self, association_id: Uuid) {
        self.association_id = association_id.clone();
    }

    pub fn set_server_transport(&mut self, transport: JetTransport) {
        self.server_transport = Some(transport);
    }

    pub fn set_client_transport(&mut self, transport: JetTransport) {
        self.client_transport = Some(transport);
    }
}

#[derive(Debug,Clone,PartialEq)]
pub enum CandidateType {
    Host,
    Relay,
}

impl TryFrom<&str> for CandidateType {
    type Error = &'static str;
    fn try_from(val: &str) -> Result<Self, Self::Error> {
        let ival = val.to_lowercase();
        match ival.as_str() {
            "host" => Ok(CandidateType::Host),
            "relay" => Ok(CandidateType::Relay),
            _ => Err("Invalid CandidateType"),
        }
    }
}

impl From<CandidateType> for &str {
    fn from(val: CandidateType) -> Self {
        match val {
            CandidateType::Host => "Host",
            CandidateType::Relay => "Relay",
        }
    }
}

#[derive(Debug,Clone,PartialEq)]
pub enum CandidateState {
    Initial,
    Created,
    Accepted,
    Connected,
    Selected,
    Discarded,
    Failed,
    Final,
}

impl From<CandidateState> for &str {
    fn from(val: CandidateState) -> Self {
        match val {
            CandidateState::Initial => "Initial",
            CandidateState::Created => "Created",
            CandidateState::Accepted => "Accepted",
            CandidateState::Connected => "Connected",
            CandidateState::Selected => "Selected",
            CandidateState::Discarded => "Discarded",
            CandidateState::Failed => "Failed",
            CandidateState::Final => "Final",
        }
    }
}