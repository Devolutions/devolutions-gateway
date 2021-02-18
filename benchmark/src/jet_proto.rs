use std::io;

use http::StatusCode;
use jet_proto::accept::JetAcceptReq;
use jet_proto::connect::JetConnectReq;
use jet_proto::{JetMessage, JET_VERSION_V1};
use uuid::Uuid;

pub fn connect_as_client(mut stream: impl io::Write + io::Read, host: String, association: Uuid) -> io::Result<()> {
    let message = JetMessage::JetConnectReq(JetConnectReq {
        version: JET_VERSION_V1 as u32,
        host,
        association,
        candidate: Uuid::nil(),
    });
    write_jet_message(&mut &mut stream, message)?;

    let buffer = read_bytes(&mut stream)?;
    if let JetMessage::JetConnectRsp(response) = JetMessage::read_connect_response(&mut buffer.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    {
        assert_eq!(StatusCode::OK, response.status_code);
        assert_eq!(JET_VERSION_V1 as u32, response.version);

        Ok(())
    } else {
        unreachable!()
    }
}

pub fn connect_as_server(mut stream: impl io::Write + io::Read, host: String) -> io::Result<Uuid> {
    let message = JetMessage::JetAcceptReq(JetAcceptReq {
        version: JET_VERSION_V1 as u32,
        host,
        association: Uuid::nil(),
        candidate: Uuid::nil(),
    });
    write_jet_message(&mut stream, message)?;

    let buffer = read_bytes(&mut stream)?;
    if let JetMessage::JetAcceptRsp(response) =
        JetMessage::read_accept_response(&mut buffer.as_slice()).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
    {
        assert_eq!(StatusCode::OK, response.status_code);
        assert_eq!(JET_VERSION_V1 as u32, response.version);
        assert!(!response.association.is_nil());

        Ok(response.association)
    } else {
        unreachable!()
    }
}

fn write_jet_message(mut stream: impl io::Write, message: JetMessage) -> io::Result<()> {
    let mut buffer = Vec::with_capacity(1024);
    message.write_to(&mut buffer)?;
    stream.write_all(&buffer)?;

    stream.flush()
}

fn read_bytes(mut stream: impl io::Read) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0u8; 1024];

    match stream.read(&mut buffer) {
        Ok(0) => Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "Failed to get any byte",
        )),
        Ok(n) => {
            buffer.truncate(n);

            Ok(buffer)
        }
        Err(e) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Failed to read bytes: {}", e),
        )),
    }
}
