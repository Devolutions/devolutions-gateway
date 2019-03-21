extern crate byteorder;
extern crate log;
extern crate uuid;

use byteorder::{BigEndian, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::Read;
use std::io::{self, Write};
use std::ops::Add;
use std::str::FromStr;
use uuid::Uuid;

pub const JET_MSG_SIGNATURE: u32 = 0x0054_454A;
pub const JET_MSG_HEADER_SIZE: u32 = 8;
pub const JET_VERSION: u8 = 1;

const JET_HEADER_VERSION: &str = "Jet-Version";
const JET_HEADER_METHOD: &str = "Jet-Method";
const JET_HEADER_ASSOCIATION: &str = "Jet-Association";
const JET_HEADER_TIMEOUT: &str = "Jet-Timeout";
const JET_HEADER_INSTANCE: &str = "Jet-Instance";

#[derive(Debug, PartialEq, Clone)]
pub enum JetMethod {
    ACCEPT,
    CONNECT,
}

impl FromStr for JetMethod {
    type Err = io::Error;

    fn from_str(s: &str) -> Result<Self, <Self as FromStr>::Err> {
        match s {
            "Accept" => Ok(JetMethod::ACCEPT),
            "Connect" => Ok(JetMethod::CONNECT),
            _ => Err(error_other(&format!(
                "JetMethod: Wrong value ({}). Only Accept and Connect are accepted",
                s
            ))),
        }
    }
}

impl ToString for JetMethod {
    fn to_string(&self) -> String {
        match self {
            JetMethod::ACCEPT => "Accept".to_string(),
            JetMethod::CONNECT => "Connect".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ResponseStatusCode {
    StatusCode200,
    StatusCode400,
}

#[derive(Debug, Clone)]
pub struct JetPacket {
    flags: u8,
    mask: u8,
    response_status_code: Option<ResponseStatusCode>,
    version: Option<u8>,
    method: Option<JetMethod>,
    association: Option<Uuid>,
    timeout: Option<u32>,
    instance: Option<String>,
}

impl JetPacket {
    pub fn new(flags: u8, mask: u8) -> Self {
        JetPacket {
            flags,
            mask,
            version: None,
            method: None,
            association: None,
            timeout: None,
            response_status_code: None,
            instance: None,
        }
    }

    pub fn new_response(flags: u8, mask: u8, response_status_code: ResponseStatusCode) -> Self {
        JetPacket {
            flags,
            mask,
            response_status_code: Some(response_status_code),
            version: Some(JET_VERSION),
            method: None,
            association: None,
            timeout: None,
            instance: None,
        }
    }

    pub fn flags(&self) -> u8 {
        self.flags
    }

    pub fn mask(&self) -> u8 {
        self.mask
    }

    pub fn is_accept(&self) -> bool {
        self.method == Some(JetMethod::ACCEPT)
    }

    pub fn is_connect(&self) -> bool {
        self.method == Some(JetMethod::CONNECT)
    }

    pub fn association(&self) -> Option<Uuid> {
        self.association
    }

    pub fn set_association(&mut self, association: Option<Uuid>) {
        self.association = association;
    }

    pub fn set_jet_instance(&mut self, instance: Option<String>) {
        self.instance = instance;
    }

    pub fn set_timeout(&mut self, timeout: Option<u32>) {
        self.timeout = timeout;
    }

    pub fn set_method(&mut self, method: Option<JetMethod>) {
        self.method = method;
    }

    pub fn set_version(&mut self, version: Option<u8>) {
        self.version = version;
    }

    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self, io::Error> {
        let signature = reader.read_u32::<LittleEndian>()?;
        if signature != JET_MSG_SIGNATURE {
            return Err(error_other(&format!("Invalid JetPacket - Signature = {}.", signature)));
        }
        let size = reader.read_u16::<BigEndian>()?;
        let flags = reader.read_u8()?;
        let mask = reader.read_u8()?;
        let mut jet_packet = JetPacket::new(flags, mask);

        let mut payload: Vec<u8> = vec![0; (size - 8) as usize];
        reader.read_exact(&mut payload)?;

        apply_mask(mask, &mut payload);

        let payload = String::from_utf8(payload).map_err(|e| {
            error_other(&format!(
                "Invalid JetPacket - Packet can't be converted in String: {}",
                e
            ))
        })?;
        let lines = payload.lines();

        // First line is ignored (GET / HTTP/1.1)
        for line in lines.skip(1) {
            if line.is_empty() {
                break;
            }

            let fields: Vec<&str> = line.split(':').collect();

            if fields.len() != 2 {
                return Err(error_other(&format!(
                    "Invalid JetPacket: Error in header line ({})",
                    line
                )));
            }
            match fields[0] {
                JET_HEADER_VERSION => {
                    jet_packet.version = Some(
                        fields[1]
                            .trim()
                            .parse::<u8>()
                            .map_err(|e| error_other(&format!("Invalid version: {}", e)))?,
                    )
                }
                JET_HEADER_METHOD => {
                    jet_packet.method = Some(JetMethod::from_str(fields[1].trim())?);
                }
                JET_HEADER_ASSOCIATION => {
                    jet_packet.association = Some(
                        Uuid::from_str(fields[1].trim())
                            .map_err(|e| error_other(&format!("Invalid association: {}", e)))?,
                    );
                }
                _ => {
                    // ignore unknown header
                }
            }
        }
        Ok(jet_packet)
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<(), io::Error> {
        // Build payload
        let mut payload = "".to_string();
        match self.response_status_code {
            Some(ResponseStatusCode::StatusCode200) => {
                payload = payload.add(&format!("{} {} {}\r\n", "HTTP/1.1", "200", "OK"));
            }
            Some(ResponseStatusCode::StatusCode400) => {
                payload = payload.add(&format!("{} {} {}\r\n", "HTTP/1.1", "400", "Bad Request"));
            }
            None => {
                payload = payload.add(&format!("{} {} {}\r\n", "HTTP/1.1", "400", "Bad Request"));
            }
        }
        if let Some(ref version) = self.version {
            payload = payload.add(&format!("{}: {}\r\n", JET_HEADER_VERSION, version.to_string()));
        }
        if let Some(ref association) = self.association {
            payload = payload.add(&format!("{}: {}\r\n", JET_HEADER_ASSOCIATION, association.to_string()));
        }
        if let Some(ref method) = self.method {
            payload = payload.add(&format!("{}: {}\r\n", JET_HEADER_METHOD, method.to_string()));
        }
        if let Some(ref timeout) = self.timeout {
            payload = payload.add(&format!("{}: {}\r\n", JET_HEADER_TIMEOUT, timeout.to_string()))
        }
        if let Some(ref instance) = self.instance {
            payload = payload.add(&format!("{}: {}\r\n", JET_HEADER_INSTANCE, instance))
        }
        payload = payload.add("\r\n");

        // Apply mask
        let payload_bytes = unsafe { payload.as_bytes_mut() };
        apply_mask(self.mask, payload_bytes);

        // Write message
        let size = payload_bytes.len() as u16 + JET_MSG_HEADER_SIZE as u16;
        writer.write_u32::<LittleEndian>(JET_MSG_SIGNATURE)?;
        writer.write_u16::<BigEndian>(size)?;
        writer.write_u8(self.flags)?;
        writer.write_u8(self.mask)?;

        writer.write_all(payload_bytes)?;

        Ok(())
    }
}

fn error_other(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::Other, desc)
}

fn apply_mask(mask: u8, payload: &mut [u8]) {
    for byte in payload {
        *byte ^= mask;
    }
}
