use anyhow::{anyhow, Result};
use jet_proto::JET_VERSION_V2;
use tokio::io::{AsyncRead, AsyncWrite};
use uuid::Uuid;

pub async fn write_jet_accept_request(
    writer: &mut (dyn AsyncWrite + Send + Unpin),
    association_id: Uuid,
    candidate_id: Uuid,
) -> Result<()> {
    use jet_proto::accept::JetAcceptReq;
    use jet_proto::JetMessage;
    use tokio::io::AsyncWriteExt;

    let jet_accept_request = JetMessage::JetAcceptReq(JetAcceptReq {
        version: u32::from(JET_VERSION_V2),
        host: "jetsocat".to_owned(),
        association: association_id,
        candidate: candidate_id,
    });

    let mut buffer: Vec<u8> = Vec::new();
    jet_accept_request.write_to(&mut buffer)?;
    writer.write_all(&buffer).await?;

    Ok(())
}

pub async fn read_jet_accept_response(reader: &mut (dyn AsyncRead + Send + Unpin)) -> Result<()> {
    use jet_proto::JetMessage;
    use tokio::io::AsyncReadExt;

    let mut buffer = [0u8; 1024];

    let read_bytes_count = reader.read(&mut buffer).await?;

    if read_bytes_count == 0 {
        return Err(anyhow!("Failed to read JetConnectRsp"));
    }

    let mut message: &[u8] = &buffer[0..read_bytes_count];

    match JetMessage::read_accept_response(&mut message)? {
        JetMessage::JetAcceptRsp(rsp) if rsp.status_code != 200 => Err(anyhow!(
            "received JetAcceptRsp with unexpected status code from Devolutions-Gateway ({})",
            rsp.status_code
        )),
        JetMessage::JetAcceptRsp(_) => Ok(()),
        unexpected => {
            return Err(anyhow!(
                "received {:?} message from Devolutions-Gateway instead of JetAcceptRsp",
                unexpected
            ))
        }
    }
}

pub async fn write_jet_connect_request(
    writer: &mut (dyn AsyncWrite + Send + Unpin),
    association_id: Uuid,
    candidate_id: Uuid,
) -> Result<()> {
    use jet_proto::connect::JetConnectReq;
    use jet_proto::JetMessage;
    use tokio::io::AsyncWriteExt;

    let jet_connect_request = JetMessage::JetConnectReq(JetConnectReq {
        version: u32::from(JET_VERSION_V2),
        host: "jetsocat".to_owned(),
        association: association_id,
        candidate: candidate_id,
    });

    let mut buffer: Vec<u8> = Vec::new();
    jet_connect_request.write_to(&mut buffer)?;
    writer.write_all(&buffer).await?;

    Ok(())
}

pub async fn read_jet_connect_response(reader: &mut (dyn AsyncRead + Send + Unpin)) -> Result<()> {
    use jet_proto::JetMessage;
    use tokio::io::AsyncReadExt;

    let mut buffer = [0u8; 1024];

    let read_bytes_count = reader.read(&mut buffer).await?;

    if read_bytes_count == 0 {
        return Err(anyhow!("Failed to read JetConnectRsp"));
    }

    let mut message: &[u8] = &buffer[0..read_bytes_count];

    match JetMessage::read_connect_response(&mut message)? {
        JetMessage::JetConnectRsp(rsp) if rsp.status_code != 200 => Err(anyhow!(
            "received JetConnectRsp with unexpected status code from Devolutions-Gateway ({})",
            rsp.status_code
        )),
        JetMessage::JetConnectRsp(_) => Ok(()),
        unexpected => {
            return Err(anyhow!(
                "received {:?} message from Devolutions-Gateway instead of JetConnectRsp",
                unexpected
            ))
        }
    }
}
