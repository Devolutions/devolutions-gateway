use ironrdp::{gcc, CapabilitySet, ClientInfoPdu, ConnectInitial, ConnectResponse, DemandActive};
use sspi::Credentials;

pub trait Filter {
    fn filter(&mut self, config: &FilterConfig);
}

pub struct FilterConfig {
    version: gcc::RdpVersion,
    client_early_capability_flags: gcc::ClientEarlyCapabilityFlags,
    server_early_capability_flags: gcc::ServerEarlyCapabilityFlags,
    encryption_methods: gcc::EncryptionMethod,
    target_credentials: Credentials,
}

impl FilterConfig {
    pub fn new(target_credentials: Credentials) -> Self {
        Self {
            version: gcc::RdpVersion::V5Plus,
            client_early_capability_flags: gcc::ClientEarlyCapabilityFlags::empty(),
            server_early_capability_flags: gcc::ServerEarlyCapabilityFlags::empty(),
            encryption_methods: gcc::EncryptionMethod::empty(),
            target_credentials,
        }
    }
}

impl Filter for ConnectInitial {
    fn filter(&mut self, config: &FilterConfig) {
        let mut gcc_blocks = &mut self.conference_create_request.gcc_blocks;
        gcc_blocks.core.version = config.version;
        if let Some(ref mut early_capability_flags) = gcc_blocks.core.optional_data.early_capability_flags {
            *early_capability_flags = config.client_early_capability_flags;
        }
        gcc_blocks.security.encryption_methods = config.encryption_methods;
        gcc_blocks.cluster = None;
        gcc_blocks.monitor = None;
        gcc_blocks.monitor_extended = None;
        gcc_blocks.message_channel = None;
        gcc_blocks.multi_transport_channel = None;
    }
}

impl Filter for ConnectResponse {
    fn filter(&mut self, config: &FilterConfig) {
        let mut gcc_blocks = &mut self.conference_create_response.gcc_blocks;
        gcc_blocks.core.version = config.version;
        if let Some(ref mut early_capability_flags) = gcc_blocks.core.optional_data.early_capability_flags {
            *early_capability_flags = config.server_early_capability_flags;
        }
        gcc_blocks.multi_transport_channel = None;
        gcc_blocks.message_channel = None;
    }
}

impl Filter for ClientInfoPdu {
    fn filter(&mut self, config: &FilterConfig) {
        self.client_info.credentials = config.target_credentials.clone();
    }
}

impl Filter for DemandActive {
    fn filter(&mut self, _config: &FilterConfig) {
        self.capability_sets.retain(|capability_set| match capability_set {
            CapabilitySet::BitmapCacheHostSupport(_)
            | CapabilitySet::Control(_)
            | CapabilitySet::WindowActivation(_)
            | CapabilitySet::Share(_)
            | CapabilitySet::Font(_)
            | CapabilitySet::LargePointer(_)
            | CapabilitySet::DesktopComposition(_) => false,
            _ => true,
        });
    }
}
