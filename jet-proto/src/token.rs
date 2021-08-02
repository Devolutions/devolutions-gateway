use uuid::Uuid;

#[derive(Clone, Deserialize)]
#[serde(untagged)]
pub enum JetAccessTokenClaims {
    Session(JetSessionTokenClaims),
    Scope(JetScopeTokenClaims),
}

#[derive(Clone, Deserialize)]
pub struct JetSessionTokenClaims {
    /// Jet Association ID
    #[serde(default = "Uuid::new_v4")]
    pub jet_aid: Uuid,

    /// Jet Application protocol
    pub jet_ap: String,

    /// Destination Host <host>:<port>
    pub dst_hst: Option<String>,

    /// Jet Connection Mode
    #[serde(default)]
    pub jet_cm: JetConnectionMode,

    /// Jet Recording Policy
    #[serde(default)]
    pub jet_rec: bool,

    /// Jet Filtering Policy
    #[serde(default)]
    pub jet_flt: bool,

    /// Jet Creds
    #[serde(flatten)]
    pub creds: Option<CredsClaims>,
}

impl JetSessionTokenClaims {
    pub fn get_jet_ap(&self) -> String {
        self.jet_ap.clone()
    }
}

#[derive(Serialize, Deserialize, Clone)]
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

#[derive(Clone, Deserialize)]
pub struct JetScopeTokenClaims {
    pub scope: JetAccessScope,
}

#[derive(Clone, Deserialize, PartialEq)]
pub enum JetAccessScope {
    #[serde(rename = "gateway.sessions.read")]
    GatewaySessionsRead,
}
