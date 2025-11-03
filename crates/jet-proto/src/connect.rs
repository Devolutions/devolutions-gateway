use crate::utils::{RequestHelper, ResponseHelper};
use crate::{
    Error, JET_HEADER_ASSOCIATION, JET_HEADER_CONNECTION, JET_HEADER_HOST, JET_HEADER_METHOD, JET_HEADER_VERSION,
    get_uuid_in_path,
};
use http::StatusCode;
use std::io;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JetConnectReq {
    pub version: u32,
    pub host: String,
    pub association: Uuid,
    pub candidate: Uuid,
}

impl JetConnectReq {
    pub fn write_payload(&self, mut stream: impl io::Write) -> Result<(), Error> {
        match self.version {
            1 => {
                stream.write_fmt(format_args!("GET / HTTP/1.1\r\n"))?;
                stream.write_fmt(format_args!("{}: {}\r\n", JET_HEADER_HOST, &self.host))?;
                stream.write_fmt(format_args!("{JET_HEADER_CONNECTION}: Keep-Alive\r\n"))?;
                stream.write_fmt(format_args!("{}: {}\r\n", JET_HEADER_METHOD, "Connect"))?;
                stream.write_fmt(format_args!(
                    "{}: {}\r\n",
                    JET_HEADER_ASSOCIATION,
                    &self.association.to_string()
                ))?;
                stream.write_fmt(format_args!(
                    "{}: {}\r\n",
                    JET_HEADER_VERSION,
                    &self.version.to_string()
                ))?;
                stream.write_fmt(format_args!("\r\n"))?;
            }
            _ => {
                // version = 2
                stream.write_fmt(format_args!(
                    "GET /jet/connect/{}/{} HTTP/1.1\r\n",
                    &self.association.to_string(),
                    &self.candidate.to_string()
                ))?;
                stream.write_fmt(format_args!("{}: {}\r\n", JET_HEADER_HOST, &self.host))?;
                stream.write_fmt(format_args!("{JET_HEADER_CONNECTION}: Keep-Alive\r\n"))?;
                stream.write_fmt(format_args!(
                    "{}: {}\r\n",
                    JET_HEADER_VERSION,
                    &self.version.to_string()
                ))?;
                stream.write_fmt(format_args!("\r\n"))?;
            }
        }

        Ok(())
    }

    pub fn from_request(request: &httparse::Request<'_, '_>) -> Result<Self, Error> {
        if request.is_get_method() {
            // Version has to be specified
            let version_opt = if let Some(version_str) = request.get_header_value("jet-version") {
                version_str.parse::<u32>().ok()
            } else {
                None
            };

            // Host has to be specified
            let host_opt = request.get_header_value("host");

            if let (Some(version), Some(host)) = (version_opt, host_opt)
                && let Some(path) = request.path
            {
                if path.starts_with("/jet/connect") {
                    if let (Some(association_id), Some(candidate_id)) =
                        (get_uuid_in_path(path, 2), get_uuid_in_path(path, 3))
                    {
                        return Ok(JetConnectReq {
                            version,
                            host: host.to_owned(),
                            association: association_id,
                            candidate: candidate_id,
                        });
                    }
                } else if path.eq("/")
                    && let Some(jet_method) = request.get_header_value("jet-method")
                    && jet_method.to_lowercase().eq("connect")
                    && let Some(jet_association) = request.get_header_value("jet-association")
                    && let Ok(association) = Uuid::from_str(jet_association)
                {
                    return Ok(JetConnectReq {
                        version,
                        host: host.to_owned(),
                        association,
                        candidate: Uuid::nil(),
                    });
                }
            }
        }
        Err(format!("Invalid connect request: {request:?}").into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JetConnectRsp {
    pub status_code: StatusCode,
    pub version: u32,
}

impl JetConnectRsp {
    pub fn write_payload(&self, mut stream: impl io::Write) -> Result<(), Error> {
        stream.write_fmt(format_args!(
            "HTTP/1.1 {} {}\r\n",
            &self.status_code,
            self.status_code.as_str()
        ))?;
        stream.write_fmt(format_args!(
            "{}: {}\r\n",
            JET_HEADER_VERSION,
            &self.version.to_string()
        ))?;
        stream.write_fmt(format_args!("\r\n"))?;
        Ok(())
    }

    pub fn from_response(response: &httparse::Response<'_, '_>) -> Result<Self, Error> {
        if let Some(status_code) = response.code.and_then(|code| StatusCode::from_u16(code).ok()) {
            let version_opt = response
                .get_header_value(JET_HEADER_VERSION)
                .and_then(|version| version.parse::<u32>().ok());

            match version_opt {
                Some(1) => {
                    return Ok(JetConnectRsp {
                        status_code,
                        version: 1,
                    });
                }
                Some(2) => {
                    return Ok(JetConnectRsp {
                        status_code,
                        version: 2,
                    });
                }
                _ => {}
            }
        }

        Err(format!("Invalid connect response: {response:?}").into())
    }
}
