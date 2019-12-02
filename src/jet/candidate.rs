use uuid::Uuid;
use url::Url;
use std::convert::TryInto;
use slog_scope::error;
use crate::jet::TransportType;
use crate::transport::JetTransport;

#[derive(Serialize, Deserialize)]
pub struct CandidateResponse {
    id: Uuid,
    #[serde(with = "url_serde")]
    url: Option<Url>,
    state: CandidateState,
    association_id: Uuid,
    transport_type: TransportType,
    bytes_sent: u64,
    bytes_recv: u64,
}

impl From<Candidate> for CandidateResponse {
    fn from(c: Candidate) -> Self {
        let (bytes_sent, bytes_recv) =
            c.client_transport.map(|transport|(transport.get_nb_bytes_read(), transport.get_nb_bytes_written()))
                .unwrap_or((0, 0));

        CandidateResponse {
            id: c.id,
            url: c.url,
            state: c.state,
            association_id: c.association_id,
            transport_type: c.transport_type,
            bytes_sent,
            bytes_recv,
        }
    }
}
#[derive(Clone)]
pub struct Candidate {
    id: Uuid,
    url: Option<Url>,
    state: CandidateState,
    association_id: Uuid,
    transport_type: TransportType,
    server_transport: Option<JetTransport>,
    client_transport: Option<JetTransport>,
}

impl Candidate {
    pub fn new_v1() -> Self {
        Candidate {
            id: Uuid::new_v4(),
            url: None,
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
                    state: CandidateState::Initial,
                    association_id: Uuid::nil(),
                    transport_type: transport_type,
                    server_transport: None,
                    client_transport: None,
                });
            }
        } else {
            error!("Candidate can't be built. Invalid URL {}", url);
        }

        None
    }

    pub fn id(&self) -> Uuid {
        self.id.clone()
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
    pub fn client_transport(&self) -> Option<JetTransport> {
        self.client_transport.clone()
    }

    pub fn server_transport(&self) -> Option<JetTransport> {
        self.server_transport.clone()
    }

    pub fn association_id(&self) -> Uuid {
        self.association_id.clone()
    }

    pub fn set_association_id(&mut self, association_id: Uuid) {
        self.association_id = association_id.clone();
    }

    pub fn set_client_transport(&mut self, transport: JetTransport) {
        self.client_transport = Some(transport);
    }

    pub fn set_server_transport(&mut self, transport: JetTransport) {
        self.server_transport = Some(transport);
    }

    pub fn set_state(&mut self, state: CandidateState) {
        self.state = state;
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
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
