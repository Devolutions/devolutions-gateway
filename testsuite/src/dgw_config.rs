use core::fmt;
use std::path::Path;

use anyhow::Context as _;
use tempfile::TempDir;
use typed_builder::TypedBuilder;

pub struct VerbosityProfile(&'static str);

impl VerbosityProfile {
    pub const DEFAULT: Self = Self("Default");
    pub const DEBUG: Self = Self("Debug");
    pub const TLS: Self = Self("Tls");
    pub const ALL: Self = Self("All");
    pub const QUIET: Self = Self("Quiet");
}

impl fmt::Display for VerbosityProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(TypedBuilder)]
pub struct DgwConfig {
    #[builder(default, setter(into))]
    tcp_port: Option<u16>,
    #[builder(default, setter(into))]
    http_port: Option<u16>,
    #[builder(default = false)]
    disable_token_validation: bool,
    #[builder(default = VerbosityProfile::DEFAULT)]
    verbosity_profile: VerbosityProfile,
}

fn find_unused_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

impl DgwConfig {
    pub fn init(self) -> anyhow::Result<DgwConfigHandle> {
        DgwConfigHandle::init(self)
    }
}

pub struct DgwConfigHandle {
    tempdir: TempDir,
    tcp_port: u16,
    http_port: u16,
}

impl DgwConfigHandle {
    pub fn init(config: DgwConfig) -> anyhow::Result<Self> {
        let DgwConfig {
            tcp_port,
            http_port,
            disable_token_validation,
            verbosity_profile,
        } = config;

        let tempdir = tempfile::tempdir().context("create tempdir")?;
        let config_path = tempdir.path().join("gateway.json");

        let tcp_port = tcp_port.unwrap_or_else(find_unused_port);
        let http_port = http_port.unwrap_or_else(find_unused_port);

        let config = format!(
            "{{
    \"ProvisionerPublicKeyData\": {{
        \"Value\": \"mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HgjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB\"
    }},
    \"Listeners\": [
        {{
            \"InternalUrl\": \"tcp://127.0.0.1:{tcp_port}\",
            \"ExternalUrl\": \"tcp://127.0.0.1:{tcp_port}\"
        }},
        {{
            \"InternalUrl\": \"http://127.0.0.1:{http_port}\",
            \"ExternalUrl\": \"http://127.0.0.1:{http_port}\"
        }}
    ],
    \"VerbosityProfile\": \"{verbosity_profile}\",
    \"__debug__\": {{
        \"disable_token_validation\": {disable_token_validation}
    }}
}}"
        );

        std::fs::write(&config_path, config).with_context(|| format!("write config into {}", config_path.display()))?;

        Ok(Self {
            tempdir,
            tcp_port,
            http_port,
        })
    }

    pub fn config_dir(&self) -> &Path {
        self.tempdir.path()
    }

    pub fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    pub fn http_port(&self) -> u16 {
        self.http_port
    }
}
