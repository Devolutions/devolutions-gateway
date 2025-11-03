use crate::utils::{RequestHelper, ResponseHelper};
use crate::{
    Error, JET_HEADER_ASSOCIATION, JET_HEADER_HOST, JET_HEADER_INSTANCE, JET_HEADER_METHOD, JET_HEADER_TIMEOUT,
    JET_HEADER_VERSION, get_uuid_in_path,
};
use http::StatusCode;
use std::io;
use std::str::FromStr;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JetAcceptReq {
    pub version: u32,
    pub host: String,
    pub association: Uuid,
    pub candidate: Uuid,
}

impl JetAcceptReq {
    pub fn write_payload(&self, mut stream: impl io::Write) -> Result<(), Error> {
        match self.version {
            1 => {
                stream.write_fmt(format_args!("GET / HTTP/1.1\r\n"))?;
                stream.write_fmt(format_args!("Host: {}\r\n", &self.host))?;
                stream.write_fmt(format_args!("Connection: Keep-Alive\r\n"))?;
                stream.write_fmt(format_args!("Jet-Method: {}\r\n", "Accept"))?;
                stream.write_fmt(format_args!("Jet-Version: {}\r\n", &self.version.to_string()))?;
                stream.write_fmt(format_args!("\r\n"))?;
            }
            _ => {
                // version = 2
                stream.write_fmt(format_args!(
                    "GET /jet/accept/{}/{} HTTP/1.1\r\n",
                    &self.association.to_string(),
                    &self.candidate.to_string()
                ))?;
                stream.write_fmt(format_args!("Host: {}\r\n", &self.host))?;
                stream.write_fmt(format_args!("Connection: Keep-Alive\r\n"))?;
                stream.write_fmt(format_args!("Jet-Version: {}\r\n", &self.version.to_string()))?;
                stream.write_fmt(format_args!("\r\n"))?;
            }
        }

        Ok(())
    }

    pub fn from_request(request: &httparse::Request<'_, '_>) -> Result<Self, Error> {
        if request.is_get_method() {
            let version_opt = request
                .get_header_value(JET_HEADER_VERSION)
                .and_then(|version| version.parse::<u32>().ok());
            let host_opt = request.get_header_value(JET_HEADER_HOST);

            if let (Some(version), Some(host)) = (version_opt, host_opt)
                && let Some(path) = request.path
            {
                if path.starts_with("/jet/accept") {
                    if let (Some(association_id), Some(candidate_id)) =
                        (get_uuid_in_path(path, 2), get_uuid_in_path(path, 3))
                    {
                        return Ok(JetAcceptReq {
                            version,
                            host: host.to_owned(),
                            association: association_id,
                            candidate: candidate_id,
                        });
                    }
                } else if path.eq("/")
                    && let Some(jet_method) = request.get_header_value(JET_HEADER_METHOD)
                    && jet_method.to_lowercase().eq("accept")
                {
                    return Ok(JetAcceptReq {
                        version,
                        host: host.to_owned(),
                        association: Uuid::nil(),
                        candidate: Uuid::nil(),
                    });
                }
            }
        }
        Err(format!("Invalid accept request: {request:?}").into())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JetAcceptRsp {
    pub status_code: StatusCode,
    pub version: u32,
    pub association: Uuid,
    pub timeout: u32,
    pub instance: String,
}

impl JetAcceptRsp {
    pub fn write_payload(&self, mut stream: impl io::Write) -> Result<(), Error> {
        match self.version {
            1 => {
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
                stream.write_fmt(format_args!("{}: {}\r\n", JET_HEADER_INSTANCE, &self.instance))?;
                stream.write_fmt(format_args!(
                    "{}: {}\r\n",
                    JET_HEADER_ASSOCIATION,
                    &self.association.to_string()
                ))?;
                stream.write_fmt(format_args!(
                    "{}: {}\r\n",
                    JET_HEADER_TIMEOUT,
                    &self.timeout.to_string()
                ))?;
                stream.write_fmt(format_args!("\r\n"))?;
            }
            _ => {
                // version = 2
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
            }
        }

        Ok(())
    }

    pub fn from_response(response: &httparse::Response<'_, '_>) -> Result<Self, Error> {
        if let Some(status_code) = response.code.and_then(|code| StatusCode::from_u16(code).ok()) {
            let version_opt = response
                .get_header_value(JET_HEADER_VERSION)
                .and_then(|version| version.parse::<u32>().ok());

            match version_opt {
                Some(1) => {
                    let association_opt = response
                        .get_header_value(JET_HEADER_ASSOCIATION)
                        .and_then(|association| Uuid::from_str(association).ok());
                    let timeout_opt = response
                        .get_header_value(JET_HEADER_TIMEOUT)
                        .and_then(|timeout| timeout.parse::<u32>().ok());
                    let instance_opt = response.get_header_value(JET_HEADER_INSTANCE);

                    if let (Some(association), Some(timeout), Some(instance)) =
                        (association_opt, timeout_opt, instance_opt)
                    {
                        return Ok(JetAcceptRsp {
                            status_code,
                            version: 1,
                            association,
                            timeout,
                            instance: instance.into(),
                        });
                    }
                }
                Some(2) => {
                    return Ok(JetAcceptRsp {
                        status_code,
                        version: 2,
                        association: Uuid::nil(),
                        timeout: 0,
                        instance: "".to_owned(),
                    });
                }
                _ => {}
            }
        }

        Err(format!("Invalid accept response: {response:?}").into())
    }
}
