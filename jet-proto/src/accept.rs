use uuid::Uuid;
use crate::{Error, get_uuid_in_path, JET_HEADER_VERSION, JET_HEADER_INSTANCE, JET_HEADER_ASSOCIATION, JET_HEADER_TIMEOUT};
use std::str::{FromStr};
use crate::utils::{RequestHelper, ResponseHelper};
use std::io;

#[derive(Debug, Clone, PartialEq)]
pub struct JetAcceptReq {
    pub version: u32,
    pub host: String,
    pub association: Uuid,
    pub candidate: Uuid,
}

impl JetAcceptReq {
    pub fn to_payload(&self, mut stream: impl io::Write) -> Result<(), Error> {
        if self.version == 1 {
            stream.write_fmt(format_args!("GET / HTTP/1.1\r\n"))?;
            stream.write_fmt(format_args!("Host: {}\r\n", &self.host))?;
            stream.write_fmt(format_args!("Connection: Keep-Alive\r\n"))?;
            stream.write_fmt(format_args!("Jet-Method: {}\r\n", "Accept"))?;
            stream.write_fmt(format_args!("Jet-Version: {}\r\n", &self.version.to_string()))?;
            stream.write_fmt(format_args!("\r\n"))?;
        } else { // version = 2
            stream.write_fmt(format_args!("GET /jet/accept/{} HTTP/1.1\r\n", &self.association.to_string()))?;
            stream.write_fmt(format_args!("Host: {}\r\n", &self.host))?;
            stream.write_fmt(format_args!("Connection: Keep-Alive\r\n"))?;
            stream.write_fmt(format_args!("Jet-Version: {}\r\n", &self.version.to_string()))?;
            stream.write_fmt(format_args!("\r\n"))?;
        }
        Ok(())
    }

    pub fn from_request(request: &httparse::Request) -> Result<Self, Error> {
        if request.is_get_method() {

            let version_opt = request.get_header_value("jet-version").map_or(None, |version| version.parse::<u32>().ok());
            let host_opt = request.get_header_value("host");

            if let (Some(version), Some(host)) = (version_opt, host_opt) {
                if let Some(path) = request.path {
                    if path.starts_with("/jet/accept") {
                        if let (Some(association_id), Some(candidate_id)) = (get_uuid_in_path(path, 2), get_uuid_in_path(path, 3)) {
                            return Ok(JetAcceptReq {
                                version: version,
                                host: host.to_string(),
                                association: association_id,
                                candidate: candidate_id,
                            })
                        }
                    } else if path.eq("/") {
                        if let Some(jet_method) = request.get_header_value("jet-method") {
                            if jet_method.to_lowercase().eq("accept") {
                                return Ok(JetAcceptReq {
                                    version: version,
                                    host: host.to_string(),
                                    association: Uuid::nil(),
                                    candidate: Uuid::nil(),
                                })
                            }
                        }
                    }
                }
            }
        }
        Err(format!("Invalid accept request: {:?}", request).into())
    }
}
#[derive(Debug, Clone, PartialEq)]
pub struct JetAcceptRsp {
    pub status_code: u16,
    pub version: u32,
    pub association: Uuid,
    pub timeout: u32,
    pub instance: String,
}

impl JetAcceptRsp {
    pub fn to_payload(&self, mut stream: impl io::Write) -> Result<(), Error> {
        if self.version == 1 {
            stream.write_fmt(format_args!("HTTP/1.1 {} TODO\r\n", &self.status_code))?;
            stream.write_fmt(format_args!("{}: {}\r\n", JET_HEADER_VERSION, &self.version.to_string()))?;
            stream.write_fmt(format_args!("{}: {}\r\n", JET_HEADER_INSTANCE, &self.instance))?;
            stream.write_fmt(format_args!("{}: {}\r\n", JET_HEADER_ASSOCIATION, &self.association.to_string()))?;
            stream.write_fmt(format_args!("{}: {}\r\n", JET_HEADER_TIMEOUT, &self.timeout.to_string()))?;
            stream.write_fmt(format_args!("\r\n"))?;
        } else { // version = 2
            stream.write_fmt(format_args!("HTTP/1.1 {} TODO\r\n", &self.status_code))?;
            stream.write_fmt(format_args!("{}: {}\r\n", JET_HEADER_VERSION, &self.version.to_string()))?;
            stream.write_fmt(format_args!("\r\n"))?;
        }
        Ok(())
    }

    pub fn from_response(response: &httparse::Response) -> Result<Self, Error> {
        if let Some(code) = response.code {
            let version_opt = response.get_header_value(JET_HEADER_VERSION).map_or(None, |version| version.parse::<u32>().ok());

            match version_opt {
                Some(1) => {
                    let association_opt = response.get_header_value(JET_HEADER_ASSOCIATION).map_or(None, |association| Uuid::from_str(association).ok());
                    let timeout_opt = response.get_header_value(JET_HEADER_TIMEOUT).map_or(None, |timeout| timeout.parse::<u32>().ok());
                    let instance_opt = response.get_header_value(JET_HEADER_INSTANCE);

                    if let (Some(association), Some(timeout), Some(instance)) = (association_opt, timeout_opt, instance_opt) {
                        return Ok(JetAcceptRsp {
                            status_code: code,
                            version: 1,
                            association,
                            timeout,
                            instance: instance.into()
                        });
                    }

                }
                Some(2) => {
                    return Ok(JetAcceptRsp {
                        status_code: code,
                        version: 2,
                        association: Uuid::nil(),
                        timeout: 0,
                        instance: "".to_string(),
                    });
                }
                _ => {}
            }
        }

        Err(format!("Invalid accept response: {:?}", response).into())
    }
}
