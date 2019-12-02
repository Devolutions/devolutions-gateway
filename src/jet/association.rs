use chrono::serde::ts_seconds;
use uuid::Uuid;
use indexmap::IndexMap;
use crate::jet::candidate::{Candidate, CandidateState, CandidateResponse};
use serde_json::Value;
use chrono::{Utc, DateTime};


pub struct Association {
    id: Uuid,
    version: u8,
    creation_timestamp: DateTime<Utc>,
    candidates: IndexMap<Uuid, Candidate>,
}

impl Association {
    pub fn new(id: Uuid, version: u8) -> Self {
        Association {
            id: id,
            version: version,
            creation_timestamp: Utc::now(),
            candidates: IndexMap::new(),
        }
    }

    pub fn get_candidates(&self) -> &IndexMap<Uuid, Candidate> {
        &self.candidates
    }

    pub fn add_candidate(&mut self, mut candidate: Candidate) {
        candidate.set_association_id(self.id);
        self.candidates.insert(candidate.id(), candidate);
    }

    pub fn get_candidate_mut(&mut self, id: Uuid) -> Option<&mut Candidate> {
        self.candidates.get_mut(&id)
    }

    pub fn get_candidate_by_index(&mut self, index: usize) -> Option<&mut Candidate> {
        if let Some((_, candidate)) = self.candidates.get_index_mut(index) {
            Some(candidate)
        }
        else {
            None
        }
    }

    pub fn gather_candidate(&self) -> Value {
        let mut candidates = json!({
            "id": self.id.to_string()
        });

        let mut candidate_list = Vec::new();
        for (id, candidate) in &self.candidates {
            if let Some(url) = candidate.url() {
                let json_candidate = json!({
                    "id": id.to_string(),
                    "url": url.to_string()
                });

                candidate_list.push(json_candidate);
            }
        }

        candidates.as_object_mut().unwrap().insert("candidates".into(), candidate_list.into());

        candidates
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn is_connected(&self) -> bool {
        self.candidates.iter().find(|(_, candidate)| {
            candidate.state() == CandidateState::Connected
        }).is_some()
    }
}

#[derive(Serialize, Deserialize)]
pub struct AssociationResponse {
    id: Uuid,
    version: u8,
    bytes_sent: u64,
    bytes_recv: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    candidates: Option<Vec<CandidateResponse>>,
    #[serde(with = "ts_seconds")]
    creation_timestamp: DateTime<Utc>,
}

impl AssociationResponse {
    pub fn from(association: &Association, with_detail: bool) -> Self {
        let (client_bytes_sent, client_bytes_recv) = association.candidates.iter().find_map(|(_, candidate)| {
            if let Some(transport) = candidate.client_transport() {
                let client_bytes_sent = transport.get_nb_bytes_read();
                let client_bytes_recv = transport.get_nb_bytes_written();
                if client_bytes_sent != 0 || client_bytes_recv != 0 {
                    return Some((client_bytes_sent, client_bytes_recv))
                }
            }
            None
        }).unwrap_or((0, 0));

        let candidates: Option<Vec<CandidateResponse>> = if with_detail {
            Some(association.candidates.iter().map(|(_, candidate)| candidate.clone().into()).collect())
        } else {
            None
        };

        AssociationResponse {
            id: association.id,
            version: association.version,
            bytes_sent: client_bytes_sent,
            bytes_recv: client_bytes_recv,
            candidates,
            creation_timestamp: association.creation_timestamp,
        }
    }
}