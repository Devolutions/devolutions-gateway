use std::{fs::File, io, io::prelude::*};

use serde_derive::{Deserialize, Serialize};
use sspi::{internal::credssp, AuthIdentity};

pub trait RdpIdentityGetter {
    fn get_rdp_identity(&self) -> RdpIdentity;
}

#[derive(Clone, Serialize, Deserialize)]
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

#[derive(Clone, Serialize, Deserialize)]
pub struct RdpIdentity {
    pub proxy: AuthIdentity,
    pub target: FullCredentials,
    pub destination: String,
}

pub struct IdentitiesProxy {
    pub rdp_identity: Option<RdpIdentity>,
    rdp_identities_filename: String,
}

impl RdpIdentity {
    fn from_file(filename: &str) -> io::Result<Vec<Self>> {
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

impl IdentitiesProxy {
    pub fn new(rdp_identities_filename: String) -> Self {
        Self {
            rdp_identities_filename,
            rdp_identity: None,
        }
    }
}

impl RdpIdentityGetter for IdentitiesProxy {
    fn get_rdp_identity(&self) -> RdpIdentity {
        self.rdp_identity
            .as_ref()
            .expect("RdpIdentity must be set before the call")
            .clone()
    }
}

impl credssp::CredentialsProxy for IdentitiesProxy {
    type AuthenticationData = AuthIdentity;

    fn auth_data_by_user(&mut self, username: String, domain: Option<String>) -> io::Result<Self::AuthenticationData> {
        let mut rdp_identities = RdpIdentity::from_file(self.rdp_identities_filename.as_ref())?;
        let identity_position = rdp_identities
            .iter()
            .position(|identity| identity.proxy.username == username);

        if let Some(position) = identity_position {
            self.rdp_identity = Some(rdp_identities.remove(position));
            self.rdp_identity.as_mut().unwrap().proxy.domain = domain;

            Ok(self.rdp_identity.as_ref().unwrap().proxy.clone())
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("failed to find identity with the username '{}'", username),
            ))
        }
    }
}
