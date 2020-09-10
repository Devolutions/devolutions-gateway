use serde_derive::Deserialize;
use sspi::{internal::credssp, AuthIdentity};
use std::{fs::File, io, io::prelude::*};

#[derive(Clone, Debug, Deserialize)]
pub struct RdpIdentity {
    pub proxy: AuthIdentity,
    pub target: AuthIdentity,
    pub destination: String,
}

#[derive(Clone, Debug)]
pub struct IdentitiesProxy(Vec<RdpIdentity>);

impl Default for IdentitiesProxy {
    fn default() -> Self {
        Self(Vec::default())
    }
}

impl IdentitiesProxy {
    pub fn add_identity(&mut self, identity: RdpIdentity) {
        self.0.push(identity);
    }

    pub fn from_file(filename: &str) -> io::Result<Self> {
        let mut f = File::open(filename)?;
        let mut contents = String::new();
        f.read_to_string(&mut contents)?;

        Ok(Self(serde_json::from_str(&contents).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Failed to read the json data: {}", e),
            )
        })?))
    }

    pub fn identity_by_proxy(&self, username: &str, _domain: Option<&str>) -> io::Result<RdpIdentity> {
        self.0
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
        let identity = self.0.iter().find(|identity| identity.proxy.username == username);

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
