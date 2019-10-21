use std::{fs::File, io, io::prelude::*, sync::Arc};

use serde_derive::{Deserialize, Serialize};
use sspi::{internal::credssp, AuthIdentity};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FullCredentials {
    pub username: String,
    pub password: String,
    pub domain: String,
}

impl From<FullCredentials> for AuthIdentity {
    fn from(identity: FullCredentials) -> Self {
        Self {
            username: identity.username,
            password: identity.password,
            domain: Some(identity.domain),
        }
    }
}

impl From<FullCredentials> for ironrdp::rdp::Credentials {
    fn from(identity: FullCredentials) -> Self {
        Self {
            username: identity.username,
            password: identity.password,
            domain: Some(identity.domain),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RdpIdentity {
    pub proxy: AuthIdentity,
    pub target: FullCredentials,
    pub destination: String,
}

impl RdpIdentity {
    pub fn from_file(filename: &str) -> io::Result<Vec<Self>> {
        let mut f = File::open(filename)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(serde_json::from_str(&contents).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read the json data: {}", e),
            )
        })?)
    }
}

#[derive(Clone, Debug)]
pub struct IdentitiesProxy {
    rdp_identities: Arc<Vec<RdpIdentity>>,
}

impl IdentitiesProxy {
    pub fn new(rdp_identities: Arc<Vec<RdpIdentity>>) -> Self {
        Self { rdp_identities }
    }

    pub fn identity_by_proxy(&self, username: &str, _domain: Option<&str>) -> io::Result<RdpIdentity> {
        self.rdp_identities
            .iter()
            .find(|c| c.proxy.username == username)
            .cloned()
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("failed to find RDP identity by proxy username '{}'", username),
                )
            })
    }
}

impl credssp::CredentialsProxy for IdentitiesProxy {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: String, domain: Option<String>) -> io::Result<Self::AuthenticationData> {
        let identity = self
            .rdp_identities
            .iter()
            .find(|identity| identity.proxy.username == username);

        if let Some(identity) = identity {
            let mut credentials = identity.proxy.clone();
            credentials.domain = domain;

            Ok(credentials)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to find identity with the username '{}'", username),
            ))
        }
    }
}
