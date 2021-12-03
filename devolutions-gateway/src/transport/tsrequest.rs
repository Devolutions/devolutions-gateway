use bytes::{Buf, BytesMut};
use sspi::internal::credssp::TsRequest;
use std::io;
use tokio_util::codec::{Decoder, Encoder};

// FIXME: this is not a "transport" but a codec to apply above a transport
// (this is also only used as part of the RDP connection sequence)

#[derive(Default)]
pub struct TsRequestTransport {}

impl Decoder for TsRequestTransport {
    type Item = TsRequest;
    type Error = io::Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let ts_request = match TsRequest::from_buffer(buf.as_ref()) {
            Ok(v) => v,
            Err(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        };

        buf.advance(usize::from(ts_request.buffer_len()));

        Ok(Some(ts_request))
    }
}

impl Encoder<TsRequest> for TsRequestTransport {
    type Error = io::Error;

    fn encode(&mut self, item: TsRequest, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let item_len = usize::from(item.buffer_len());
        let len = buf.len();
        buf.resize(len + item_len, 0);

        item.encode_ts_request(&mut buf[len..])
    }
}
