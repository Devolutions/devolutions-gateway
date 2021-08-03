use uuid::Uuid;

#[derive(Clone, Deserialize)]
#[serde(tag = "type")]
#[serde(rename_all = "lowercase")]
pub enum JetAccessTokenClaims {
    Association(JetAssociationTokenClaims),
    Scope(JetScopeTokenClaims),
    Bridge(JetBridgeTokenClaims),
}

#[derive(Clone, Deserialize)]
pub struct JetAssociationTokenClaims {
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
    #[serde(rename = "gateway.associations.read")]
    GatewayAssociationsRead,
}

#[derive(Clone, Deserialize)]
pub struct JetBridgeTokenClaims {
    pub target: String,
}
