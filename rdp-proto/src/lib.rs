mod nego;

use bitflags::bitflags;

struct Settings {
    pub username: String,
    pub security_protocol: SecurityProtocol,
}

bitflags! {
    struct SecurityProtocol: u32 {
        const RDP = 0x00000000;
        const SSL = 0x00000001;
        const Hybrid = 0x00000002;
        const RDSTLS = 0x00000004;
        const HybridEx = 0x00000008;
    }
}
