use std::{
    convert::TryInto,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use slog_scope::error;
use url::Url;
use uuid::Uuid;

use crate::{jet::TransportType, transport::JetTransport};

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

impl From<&Candidate> for CandidateResponse {
    fn from(c: &Candidate) -> Self {
        let (bytes_sent, bytes_recv) = match (c.client_nb_bytes_read(), c.client_nb_bytes_written()) {
            (Some(client_bytes_sent), Some(client_bytes_recv)) => (client_bytes_sent, client_bytes_recv),
            _ => (0, 0),
        };

        CandidateResponse {
            id: c.id,
            url: c.url.clone(),
            state: c.state.clone(),
            association_id: c.association_id,
            transport_type: c.transport_type.clone(),
            bytes_sent,
            bytes_recv,
        }
    }
}

pub struct Candidate {
    id: Uuid,
    url: Option<Url>,
    state: CandidateState,
    association_id: Uuid,
    transport_type: TransportType,
    transport: Option<JetTransport>,
    client_nb_bytes_read: Option<Arc<AtomicU64>>,
    client_nb_bytes_written: Option<Arc<AtomicU64>>,
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
            client_nb_bytes_read: None,
            client_nb_bytes_written: None,
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
                    client_nb_bytes_read: None,
                    client_nb_bytes_written: None,
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

    pub fn set_transport(&mut self, transport: JetTransport) {
        self.transport = Some(transport);
    }

    pub fn take_transport(&mut self) -> Option<JetTransport> {
        self.transport.take()
    }

    pub fn set_client_nb_bytes_read(&mut self, client_nb_bytes_read: Arc<AtomicU64>) {
        self.client_nb_bytes_read = Some(client_nb_bytes_read);
    }

    pub fn client_nb_bytes_read(&self) -> Option<u64> {
        self.client_nb_bytes_read.clone().map(|v| v.load(Ordering::Relaxed))
    }

    pub fn set_client_nb_bytes_written(&mut self, client_nb_bytes_written: Arc<AtomicU64>) {
        self.client_nb_bytes_written = Some(client_nb_bytes_written);
    }

    pub fn client_nb_bytes_written(&self) -> Option<u64> {
        self.client_nb_bytes_written.clone().map(|v| v.load(Ordering::Relaxed))
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
