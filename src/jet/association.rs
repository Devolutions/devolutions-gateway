use uuid::Uuid;
use indexmap::IndexMap;
use crate::jet::candidate::Candidate;
use serde_json::Value;

pub struct Association {
    id: Uuid,
    version: u8,
    candidates: IndexMap<Uuid, Candidate>,
}

impl Association {
    pub fn new(id: Uuid, version: u8) -> Self {
        Association {
            id: id,
            version: version,
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
                    "url": url.to_string(),
                    "id": id.to_string()
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
}