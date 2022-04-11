pub mod types {
    pub const AS_REQ_MSG_TYPE: u8 = 0x0a;
    pub const AS_REP_MSG_TYPE: u8 = 0x0b;
    pub const TGS_REQ_MSG_TYPE: u8 = 0x0c;
    pub const TGS_REP_MSG_TYPE: u8 = 0x0d;
    pub const AP_REQ_MSG_TYPE: u8 = 0x0e;
    pub const AP_REP_MSG_TYPE: u8 = 0x0f;
    pub const TGT_REQ_MSG_TYPE: u8 = 0x10;
    pub const TGT_REP_MSG_TYPE: u8 = 0x11;

    pub const KRB_ERROR_MSG_TYPE: u8 = 0x1e;

    pub const NT_PRINCIPAL: u8 = 0x01;
    pub const NT_SRV_INST: u8 = 0x02;

    pub const PA_ENC_TIMESTAMP: [u8; 1] = [0x02];
    pub const PA_ENC_TIMESTAMP_KEY_USAGE: i32 = 1;
    pub const PA_PAC_REQUEST_TYPE: [u8; 2] = [0x00, 0x80];
    pub const PA_ETYPE_INFO2_TYPE: [u8; 1] = [0x13];
    pub const PA_TGS_REQ_TYPE: [u8; 1] = [0x01];
    pub const PA_PAC_OPTIONS_TYPE: [u8; 2] = [0x00, 0xa7];

    pub const TICKET_TYPE: u8 = 1;
    pub const AUTHENTICATOR_TYPE_TYPE: u8 = 2;
    pub const ENC_AS_REP_PART_TYPE: u8 = 25;
    pub const ENC_TGS_REP_PART_TYPE: u8 = 26;
    pub const ENC_AP_REP_PART_TYPE: u8 = 27;
}

pub mod oids {
    pub const SPNEGO: &str = "1.3.6.1.5.5.2";
    pub const MS_KRB5: &str = "1.2.840.48018.1.2.2";
    pub const KRB5: &str = "1.2.840.113554.1.2.2";
    pub const KRB5_USER_TO_USER: &str = "1.2.840.113554.1.2.2.3";
    pub const NTLM_SSP: &str = "1.3.6.1.4.1.311.2.2.10";
}

pub mod key_usages {
    pub const ACCEPTOR_SEAL: i32 = 22;
    pub const ACCEPTOR_SIGN: i32 = 23;
    pub const INITIATOR_SEAL: i32 = 24;
    pub const INITIATOR_SIGN: i32 = 25;
}
