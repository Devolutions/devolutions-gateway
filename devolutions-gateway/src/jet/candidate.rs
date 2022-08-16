use crate::jet::TransportType;
use bytes::Bytes;
use std::convert::TryInto;
use transport::Transport;
use url::Url;
use uuid::Uuid;

#[derive(Serialize, Deserialize)]
pub struct CandidateResponse {
    id: Uuid,
    url: Option<Url>,
    state: CandidateState,
    association_id: Uuid,
    transport_type: TransportType,

    // legacy: always set to 0 (re-evaluate if we need that later)
    bytes_sent: u64,
    bytes_recv: u64,
}

impl From<&Candidate> for CandidateResponse {
    fn from(c: &Candidate) -> Self {
        CandidateResponse {
            id: c.id,
            url: c.url.clone(),
            state: c.state.clone(),
            association_id: c.association_id,
            transport_type: c.transport_type.clone(),
            bytes_sent: 0,
            bytes_recv: 0,
        }
    }
}

pub struct Candidate {
    id: Uuid,
    url: Option<Url>,
    state: CandidateState,
    association_id: Uuid,
    transport_type: TransportType,
    transport: Option<(Transport, Option<Bytes>)>,
}

impl Candidate {
    pub fn new_v1() -> Self {
        Candidate {
            id: Uuid::new_v4(),
            url: None,
            state: CandidateState::Initial,
            association_id: Uuid::nil(),
            transport_type: TransportType::Tcp,
            transport: None,
        }
    }

    pub fn new(url: &str) -> Option<Self> {
        if let Ok(url) = Url::parse(url) {
            if let Ok(transport_type) = url.scheme().try_into() {
                return Some(Candidate {
                    id: Uuid::new_v4(),
                    url: Some(url),
                    state: CandidateState::Initial,
                    association_id: Uuid::nil(),
                    transport_type,
                    transport: None,
                });
            }
        } else {
            error!("Candidate can't be built. Invalid URL {}", url);
        }

        None
    }

    pub fn id(&self) -> Uuid {
        self.id
    }

    pub fn state(&self) -> CandidateState {
        self.state.clone()
    }

    pub fn transport_type(&self) -> TransportType {
        self.transport_type.clone()
    }

    pub fn url(&self) -> Option<Url> {
        self.url.clone()
    }

    pub fn association_id(&self) -> Uuid {
        self.association_id
    }

    pub fn set_association_id(&mut self, association_id: Uuid) {
        self.association_id = association_id;
    }

    pub fn set_transport(&mut self, transport: Transport, leftover: Option<Bytes>) {
        self.transport = Some((transport, leftover));
    }

    pub fn take_transport(&mut self) -> Option<(Transport, Option<Bytes>)> {
        self.transport.take()
    }

    pub fn has_transport(&self) -> bool {
        self.transport.is_some()
    }

    pub fn set_state(&mut self, state: CandidateState) {
        self.state = state;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CandidateState {
    Initial,
    Accepted,
    Connected,
    Final,
}

impl From<CandidateState> for &str {
    fn from(val: CandidateState) -> Self {
        match val {
            CandidateState::Initial => "Initial",
            CandidateState::Accepted => "Accepted",
            CandidateState::Connected => "Connected",
            CandidateState::Final => "Final",
        }
    }
}
