use std::fmt::Debug;
use std::io::{self, Read, Write};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use picky_asn1::wrapper::{
    Asn1SequenceOf, BitStringAsn1, ExplicitContextTag0, ExplicitContextTag1, ExplicitContextTag2, ExplicitContextTag3,
    ObjectIdentifierAsn1, OctetStringAsn1, Optional,
};
use picky_asn1_der::{Asn1DerError, Asn1RawDer};
use serde::{ser, Deserialize, Serialize};
use thiserror::Error;

use crate::constants::gss_api::{MIC_FILLER, MIC_TOKEN_ID, WRAP_FILLER, WRAP_TOKEN_ID};

const MIC_TOKEN_INITIATOR_DEFAULT_FLAGS: u8 = 0x04;
const MIC_TOKEN_ACCEPTOR_DEFAULT_FLAGS: u8 = 0x05;
const WRAP_TOKEN_DEFAULT_FLAGS: u8 = 0x06;
const WRAP_HEADER_LEN: usize = 16;

#[derive(Debug, Error)]
pub enum GssApiMessageError {
    #[error("Invalid token id. Expected {0:?} but got {1:?}")]
    InvalidId([u8; 2], [u8; 2]),
    #[error("IO error: {0:?}")]
    IoError(#[from] io::Error),
    #[error("Invalid MIC token filler {0:?}")]
    InvalidMicFiller([u8; 5]),
    #[error("Invalid Wrap token filler {0:?}")]
    InvalidWrapFiller(u8),
    #[error("Asn1 error: {0:?}")]
    Asn1Error(#[from] Asn1DerError),
}

/// [3.1 GSS-API](https://datatracker.ietf.org/doc/html/rfc2478#section-3.1)
///
/// ```not_rust
/// MechType::= OBJECT IDENTIFIER
/// ```
pub type MechType = ObjectIdentifierAsn1;

/// [3.2.1.  GSS-API](https://datatracker.ietf.org/doc/html/rfc2478#section-3.2.1)
///
/// ```not_rust
/// MechTypeList ::= SEQUENCE OF MechType
/// ```
pub type MechTypeList = Asn1SequenceOf<MechType>;

/// [3.2.1.  GSS-API](https://datatracker.ietf.org/doc/html/rfc2478#section-3.2.1)
///
/// ```not_rust
/// NegTokenInit ::= SEQUENCE {
///     mechTypes       [0] MechTypeList,
///     reqFlags        [1] ContextFlags  OPTIONAL,
///     mechToken       [2] OCTET STRING  OPTIONAL,
///     mechListMIC     [3] OCTET STRING  OPTIONAL,
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NegTokenInit {
    #[serde(default)]
    pub mech_types: Optional<Option<ExplicitContextTag0<MechTypeList>>>,
    #[serde(default)]
    pub req_flags: Optional<Option<ExplicitContextTag1<BitStringAsn1>>>,
    #[serde(default)]
    pub mech_token: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
    #[serde(default)]
    pub mech_list_mic: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
}

/// [3.2.1.  GSS-API](https://datatracker.ietf.org/doc/html/rfc2478#section-3.2.1)
///
/// ```not_rust
/// NegTokenTarg ::= SEQUENCE {
///     negResult      [0] ENUMERATED                              OPTIONAL,
///     supportedMech  [1] MechType                                OPTIONAL,
///     responseToken  [2] OCTET STRING                            OPTIONAL,
///     mechListMIC    [3] OCTET STRING                            OPTIONAL
/// }
/// ```
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct NegTokenTarg {
    #[serde(default)]
    pub neg_result: Optional<Option<ExplicitContextTag0<Asn1RawDer>>>,
    #[serde(default)]
    pub supported_mech: Optional<Option<ExplicitContextTag1<MechType>>>,
    #[serde(default)]
    pub response_token: Optional<Option<ExplicitContextTag2<OctetStringAsn1>>>,
    #[serde(default)]
    pub mech_list_mic: Optional<Option<ExplicitContextTag3<OctetStringAsn1>>>,
}

pub type NegTokenTarg1 = ExplicitContextTag1<NegTokenTarg>;

#[derive(Debug, PartialEq, Clone)]
pub struct KrbMessage<T: Clone> {
    pub krb5_oid: ObjectIdentifierAsn1,
    pub krb5_token_id: [u8; 2],
    pub krb_msg: T,
}

impl<T: Serialize + Clone> KrbMessage<T> {
    pub fn encode(&self, mut data: impl Write) -> Result<(), GssApiMessageError> {
        let mut oid = Vec::new();

        {
            let mut s = picky_asn1_der::Serializer::new_to_byte_buf(&mut oid);
            self.krb5_oid.serialize(&mut s)?;
        }

        data.write_all(&oid)?;
        data.write_all(&self.krb5_token_id)?;
        data.write_all(&picky_asn1_der::to_vec(&self.krb_msg)?)?;

        Ok(())
    }
}

impl<T: ser::Serialize + Debug + PartialEq + Clone> ser::Serialize for KrbMessage<T> {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use serde::ser::Error;

        let mut buff = Vec::new();
        self.encode(&mut buff)
            .map_err(|e| S::Error::custom(format!("Cannot serialize GssApiMessage inner value: {:?}", e)))?;

        Asn1RawDer(buff).serialize(serializer)
    }
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct GssApiNegInit {
    pub oid: ObjectIdentifierAsn1,
    pub neg_token_init: ExplicitContextTag0<NegTokenInit>,
}

// this ApplicationTag0 is different from the ApplicationTag<T, 0>
// ApplicationTag works as a wrapper over the inner value
// but ApplicationTag0 decodes/encodes inner type fields as its own fields
#[derive(Debug, PartialEq)]
pub struct ApplicationTag0<T>(pub T);

impl<T: ser::Serialize + Debug + PartialEq> ser::Serialize for ApplicationTag0<T> {
    fn serialize<S>(&self, serializer: S) -> Result<<S as ser::Serializer>::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        use serde::ser::Error;

        let mut buff = Vec::new();
        {
            let mut s = picky_asn1_der::Serializer::new_to_byte_buf(&mut buff);
            self.0
                .serialize(&mut s)
                .map_err(|e| S::Error::custom(format!("Cannot serialize GssApiMessage inner value: {:?}", e)))?;
        }

        // application tag 0
        buff[0] = 0x60;

        Asn1RawDer(buff).serialize(serializer)
    }
}

/// [MIC Tokens](https://datatracker.ietf.org/doc/html/rfc4121#section-4.2.6.1)
///
/// Octet no Name       Description
/// --------------------------------------------------------------
/// 0..1     TOK_ID     Identification field. Contains the hex value 04 04 expressed in big-endian order
/// 2        Flags      Attributes field
/// 3..7     Filler     Contains five octets of hex value FF.
/// 8..15    SND_SEQ    Sequence number expressed in big-endian order.
/// 16..last SGN_CKSUM  Checksum
#[derive(Debug, PartialEq, Clone)]
pub struct MicToken {
    pub flags: u8,
    pub seq_num: u64,
    pub payload: Option<Vec<u8>>,
    pub checksum: Vec<u8>,
}

impl MicToken {
    pub fn with_initiator_flags() -> Self {
        Self {
            flags: MIC_TOKEN_INITIATOR_DEFAULT_FLAGS,
            seq_num: 0,
            payload: None,
            checksum: Vec::new(),
        }
    }

    pub fn with_acceptor_flags() -> Self {
        Self {
            flags: MIC_TOKEN_ACCEPTOR_DEFAULT_FLAGS,
            seq_num: 0,
            payload: None,
            checksum: Vec::new(),
        }
    }

    pub fn with_seq_number(self, seq_num: u64) -> Self {
        let MicToken {
            flags,
            payload,
            checksum,
            ..
        } = self;
        Self {
            flags,
            seq_num,
            payload,
            checksum,
        }
    }

    pub fn header(&self) -> [u8; 16] {
        let mut header_data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        header_data[0..2].copy_from_slice(&MIC_TOKEN_ID);
        header_data[2] = self.flags;
        header_data[3..8].copy_from_slice(&MIC_FILLER);
        header_data[8..].copy_from_slice(&self.seq_num.to_be_bytes());

        header_data
    }

    pub fn set_checksum(&mut self, checksum: Vec<u8>) {
        self.checksum = checksum;
    }

    pub fn set_payload(&mut self, payload: Vec<u8>) {
        self.payload = Some(payload);
    }

    pub fn encode(&self, mut data: impl Write) -> Result<(), GssApiMessageError> {
        data.write_all(&MIC_TOKEN_ID)?;
        data.write_u8(self.flags)?;
        data.write_all(&MIC_FILLER)?;
        data.write_u64::<BigEndian>(self.seq_num)?;
        data.write_all(&self.checksum)?;

        Ok(())
    }

    pub fn decode(mut data: impl Read) -> Result<Self, GssApiMessageError> {
        let mut mic_token_id = [0, 0];

        data.read_exact(&mut mic_token_id)?;
        if mic_token_id != MIC_TOKEN_ID {
            return Err(GssApiMessageError::InvalidId(MIC_TOKEN_ID, mic_token_id));
        }

        let flags = data.read_u8()?;

        let mut mic_fillter = [0, 0, 0, 0, 0];

        data.read_exact(&mut mic_fillter)?;
        if mic_fillter != MIC_FILLER {
            return Err(GssApiMessageError::InvalidMicFiller(mic_fillter));
        }

        let seq_num = data.read_u64::<BigEndian>()?;

        let mut checksum = Vec::with_capacity(12);
        data.read_to_end(&mut checksum)?;

        Ok(Self {
            flags,
            seq_num,
            checksum,
            payload: None,
        })
    }
}

/// [Wrap Tokens](https://datatracker.ietf.org/doc/html/rfc4121#section-4.2.6.2)
///
/// Octet no   Name        Description
/// --------------------------------------------------------------
///  0..1     TOK_ID    Identification field. Contain the hex value 05 04 expressed in big-endian
///  2        Flags     Attributes field
///  3        Filler    Contains the hex value FF.
///  4..5     EC        Contains the "extra count" field, in big-endian order
///  6..7     RRC       Contains the "right rotation count" in big-endian order
///  8..15    SND_SEQ   Sequence number field expressed in big-endian order.
///  16..last Data      Encrypted data for Wrap tokens
#[derive(Debug, PartialEq, Clone)]
pub struct WrapToken {
    pub flags: u8,
    pub ec: u16,
    pub rrc: u16,
    pub seq_num: u64,
    pub payload: Option<Vec<u8>>,
    pub checksum: Vec<u8>,
}

impl WrapToken {
    pub fn with_seq_number(seq_num: u64) -> Self {
        Self {
            flags: WRAP_TOKEN_DEFAULT_FLAGS,
            ec: 0,
            rrc: 0,
            seq_num,
            payload: None,
            checksum: Vec::new(),
        }
    }

    pub fn header_len() -> usize {
        WRAP_HEADER_LEN
    }

    pub fn header(&self) -> [u8; 16] {
        let mut header_data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        header_data[0..2].copy_from_slice(&WRAP_TOKEN_ID);
        header_data[2] = self.flags;
        header_data[3] = WRAP_FILLER;
        header_data[4..6].copy_from_slice(&self.ec.to_be_bytes());
        header_data[6..8].copy_from_slice(&self.rrc.to_be_bytes());
        header_data[8..].copy_from_slice(&self.seq_num.to_be_bytes());

        header_data
    }

    pub fn set_rrc(&mut self, rrc: u16) {
        self.rrc = rrc;
    }

    pub fn set_checksum(&mut self, checksum: Vec<u8>) {
        self.checksum = checksum;
    }

    pub fn encode(&self, mut data: impl Write) -> Result<(), GssApiMessageError> {
        data.write_all(&WRAP_TOKEN_ID)?;
        data.write_u8(self.flags)?;
        data.write_u8(WRAP_FILLER)?;
        data.write_u16::<BigEndian>(self.ec)?;
        data.write_u16::<BigEndian>(self.rrc)?;
        data.write_u64::<BigEndian>(self.seq_num)?;
        data.write_all(&self.checksum)?;

        Ok(())
    }

    pub fn decode(mut data: impl Read) -> Result<Self, GssApiMessageError> {
        let mut wrap_token_id = [0, 0];

        data.read_exact(&mut wrap_token_id)?;
        if wrap_token_id != WRAP_TOKEN_ID {
            return Err(GssApiMessageError::InvalidId(WRAP_TOKEN_ID, wrap_token_id));
        }

        let flags = data.read_u8()?;

        let filler = data.read_u8()?;
        if filler != WRAP_FILLER {
            return Err(GssApiMessageError::InvalidWrapFiller(filler));
        }

        let ec = data.read_u16::<BigEndian>()?;
        let rrc = data.read_u16::<BigEndian>()?;
        let seq_num = data.read_u64::<BigEndian>()?;

        let mut checksum = Vec::with_capacity(12);
        data.read_to_end(&mut checksum)?;

        Ok(Self {
            flags,
            ec,
            rrc,
            seq_num,
            checksum,
            payload: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::gss_api::{MicToken, WrapToken};

    #[test]
    fn mic_token() {
        let expected_raw = vec![
            4, 4, 5, 255, 255, 255, 255, 255, 0, 0, 0, 0, 86, 90, 21, 229, 142, 95, 130, 211, 64, 247, 193, 232, 123,
            169, 124, 190,
        ];
        let expected = MicToken {
            flags: 5,
            seq_num: 1448744421,
            payload: None,
            checksum: vec![142, 95, 130, 211, 64, 247, 193, 232, 123, 169, 124, 190],
        };

        let mic_token = MicToken::decode(expected_raw.as_slice()).unwrap();
        let mut mic_token_raw = Vec::new();
        mic_token.encode(&mut mic_token_raw).unwrap();

        assert_eq!(expected, mic_token);
        assert_eq!(expected_raw, mic_token_raw);
    }

    #[test]
    fn wrap_token() {
        let expected_raw = vec![
            5, 4, 6, 255, 0, 0, 0, 28, 0, 0, 0, 0, 90, 181, 116, 98, 255, 212, 120, 29, 19, 35, 95, 91, 192, 216, 160,
            95, 135, 227, 86, 195, 248, 21, 226, 203, 98, 231, 109, 149, 168, 198, 63, 143, 64, 138, 30, 8, 241, 82,
            184, 48, 216, 142, 130, 64, 115, 237, 26, 204, 70, 175, 90, 166, 133, 159, 55, 132, 201, 214, 37, 21, 33,
            64, 239, 83, 135, 18, 103, 64, 219, 219, 16, 166, 251, 120, 195, 31, 57, 126, 188, 123,
        ];
        let expected = WrapToken {
            flags: 6,
            ec: 0,
            rrc: 28,
            seq_num: 1521841250,
            payload: None,
            checksum: vec![
                255, 212, 120, 29, 19, 35, 95, 91, 192, 216, 160, 95, 135, 227, 86, 195, 248, 21, 226, 203, 98, 231,
                109, 149, 168, 198, 63, 143, 64, 138, 30, 8, 241, 82, 184, 48, 216, 142, 130, 64, 115, 237, 26, 204,
                70, 175, 90, 166, 133, 159, 55, 132, 201, 214, 37, 21, 33, 64, 239, 83, 135, 18, 103, 64, 219, 219, 16,
                166, 251, 120, 195, 31, 57, 126, 188, 123,
            ],
        };

        let wrap_token = WrapToken::decode(expected_raw.as_slice()).unwrap();

        let mut wrap_token_raw = Vec::new();
        wrap_token.encode(&mut wrap_token_raw).unwrap();

        assert_eq!(expected, wrap_token);
        assert_eq!(expected_raw, wrap_token_raw);
    }
}
