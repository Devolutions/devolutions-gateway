pub mod types {
    pub const AS_REQ_MSG_TYPE: u8 = 0x0a;
    pub const AS_REP_MSG_TYPE: u8 = 0x0b;
    pub const TGS_REQ_MSG_TYPE: u8 = 0x0c;
    pub const TGS_REP_MSG_TYPE: u8 = 0x0d;
    pub const AP_REQ_MSG_TYPE: u8 = 0x0e;
    pub const AP_REP_MSG_TYPE: u8 = 0x0f;
    pub const TGT_REQ_MSG_TYPE: u8 = 0x10;
    pub const TGT_REP_MSG_TYPE: u8 = 0x11;

    pub const NT_PRINCIPAL: u8 = 0x01;
    pub const NT_SRV_INST: u8 = 0x02;

    pub const PA_ENC_TIMESTAMP: [u8; 1] = [0x02];
    pub const PA_ENC_TIMESTAMP_KEY_USAGE: i32 = 1;
    pub const PA_PAC_REQUEST_TYPE: [u8; 2] = [0x00, 0x80];
    pub const PA_ETYPE_INFO2_TYPE: [u8; 1] = [0x13];
    pub const PA_TGS_REQ_TYPE: [u8; 1] = [0x01];
    pub const PA_PAC_OPTIONS_TYPE: [u8; 2] = [0x00, 0xa7];
}

pub mod oids {
    pub const SPNEGO: &str = "1.3.6.1.5.5.2";
    pub const MSKRB5: &str = "1.2.840.48018.1.2.2";
    pub const KRB5: &str = "1.2.840.113554.1.2.2";
    pub const NTLM_SSP: &str = "1.3.6.1.4.1.311.2.2.10";
}
