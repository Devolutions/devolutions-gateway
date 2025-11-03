use crate::utils::{RequestHelper, ResponseHelper};
use crate::{Error, JET_HEADER_HOST, JET_HEADER_VERSION, get_uuid_in_path};
use http::StatusCode;
use std::io;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JetTestReq {
    pub version: u32,
    pub host: String,
    pub association: Uuid,
    pub candidate: Uuid,
}

impl JetTestReq {
    pub fn write_payload(&self, mut stream: impl io::Write) -> Result<(), Error> {
        stream.write_fmt(format_args!(
            "GET /jet/test/{}/{} HTTP/1.1\r\n",
            &self.association.to_string(),
            &self.candidate.to_string()
        ))?;
        stream.write_fmt(format_args!("Host: {}\r\n", &self.host))?;
        stream.write_fmt(format_args!("Connection: Close\r\n"))?;
        stream.write_fmt(format_args!("Jet-Version: {}\r\n", &self.version.to_string()))?;
        stream.write_fmt(format_args!("\r\n"))?;
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
                && path.starts_with("/jet/test")
                && let (Some(association_id), Some(candidate_id)) =
                    (get_uuid_in_path(path, 2), get_uuid_in_path(path, 3))
            {
                return Ok(JetTestReq {
                    version,
                    host: host.to_owned(),
                    association: association_id,
                    candidate: candidate_id,
                });
            }
        }
        Err(format!("Invalid test request: {request:?}").into())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JetTestRsp {
    pub status_code: StatusCode,
    pub version: u32,
}

impl JetTestRsp {
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
        let code = response
            .code
            .ok_or_else(|| "invalid test response, status code is missing".to_owned())?;
        let status_code = StatusCode::from_u16(code).map_err(|e| format!("invalid test response status code: {e}"))?;
        match response
            .get_header_value(JET_HEADER_VERSION)
            .and_then(|version| version.parse::<u32>().ok())
        {
            Some(version) if version == 2 => Ok(JetTestRsp { status_code, version }),
            _ => Err(Error::from(format!("Invalid test response: {response:?}"))),
        }
    }
}
