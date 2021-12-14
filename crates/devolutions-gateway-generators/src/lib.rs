use devolutions_gateway::token::ApplicationProtocol;
use devolutions_gateway::utils::TargetAddr;
use devolutions_gateway::{ConnectionModeDetails, GatewaySessionInfo};
use proptest::prelude::*;

pub fn uuid_str() -> impl Strategy<Value = String> {
    "[[:digit:]]{8}-([[:digit:]]{4}-){3}[[:digit:]]{12}".no_shrink()
}

pub fn uuid_typed() -> impl Strategy<Value = uuid::Uuid> {
    uuid_str().prop_map(|id| uuid::Uuid::parse_str(&id).unwrap())
}

pub fn application_protocol() -> impl Strategy<Value = ApplicationProtocol> {
    prop_oneof![
        Just(ApplicationProtocol::Wayk),
        Just(ApplicationProtocol::Pwsh),
        Just(ApplicationProtocol::Rdp),
        Just(ApplicationProtocol::Ard),
        Just(ApplicationProtocol::Ssh),
        Just(ApplicationProtocol::Sftp),
        Just(ApplicationProtocol::Unknown),
    ]
    .no_shrink()
}

pub fn target_addr() -> impl Strategy<Value = TargetAddr> {
    "[a-z]{1,10}\\.[a-z]{1,5}:[0-9]{3,4}".prop_map(|addr| TargetAddr::parse(&addr, None).unwrap())
}

pub fn session_info_fwd_only() -> impl Strategy<Value = GatewaySessionInfo> {
    (uuid_typed(), application_protocol(), target_addr()).prop_map(|(id, application_protocol, destination_host)| {
        GatewaySessionInfo::new(
            id,
            application_protocol,
            ConnectionModeDetails::Fwd { destination_host },
        )
    })
}
