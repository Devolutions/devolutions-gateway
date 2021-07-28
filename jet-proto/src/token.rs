use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Deserialize)]
pub struct JetSessionTokenClaims {
    /// Jet association ID
    #[serde(default = "Uuid::new_v4")]
    pub jet_aid: Uuid,

    /// Destination Host <host>:<port>
    pub dst_hst: Option<String>,

    /// Application protocol
    pub jet_ap: String,

    #[serde(default)]
    pub jet_rec: bool,

    /// Connection Mode
    #[serde(default)]
    pub jet_cm: JetConnectionMode,

    #[serde(flatten)]
    pub creds: Option<CredsClaims>,
}

impl JetSessionTokenClaims {
    pub fn get_jet_ap(&self) -> String {
        self.jet_ap.clone()
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum JetConnectionMode {
    Rdv,
    Fwd,
}

impl Default for JetConnectionMode {
    fn default() -> Self {
        JetConnectionMode::Rdv
    }
}

#[derive(Clone, Deserialize, Debug)]
pub struct CredsClaims {
    // Proxy credentials (client <-> jet)
    pub prx_usr: String,
    pub prx_pwd: String,

    // Target credentials (jet <-> server)
    pub dst_usr: String,
    pub dst_pwd: String,
}
