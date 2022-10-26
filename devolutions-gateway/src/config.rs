use crate::listener::ListenerUrls;
use crate::token::Subkey;
use crate::utils::TargetAddr;
use anyhow::Context;
use camino::{Utf8Path, Utf8PathBuf};
use cfg_if::cfg_if;
use core::fmt;
use picky::key::{PrivateKey, PublicKey};
use picky::pem::Pem;
use serde::{Deserialize, Serialize};
use std::env;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tap::prelude::*;
use tokio::sync::Notify;
use tokio_rustls::rustls;
use url::Url;
use uuid::Uuid;

const CERTIFICATE_LABEL: &str = "CERTIFICATE";
const PRIVATE_KEY_LABELS: &[&str] = &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];

cfg_if! {
    if #[cfg(target_os = "windows")] {
        const COMPANY_DIR: &str = "Devolutions";
        const PROGRAM_DIR: &str = "Gateway";
        const APPLICATION_DIR: &str = "Devolutions\\Gateway";
    } else if #[cfg(target_os = "macos")] {
        const COMPANY_DIR: &str = "Devolutions";
        const PROGRAM_DIR: &str = "Gateway";
        const APPLICATION_DIR: &str = "Devolutions Gateway";
    } else {
        const COMPANY_DIR: &str = "devolutions";
        const PROGRAM_DIR: &str = "gateway";
        const APPLICATION_DIR: &str = "devolutions-gateway";
    }
}

#[derive(Debug, Clone)]
pub struct TlsPublicKey(pub Vec<u8>);

#[derive(Clone)]
pub struct Tls {
    pub acceptor: tokio_rustls::TlsAcceptor,
    pub certificate: rustls::Certificate,
    pub private_key: rustls::PrivateKey,
    pub public_key: TlsPublicKey,
}

impl fmt::Debug for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig")
            .field("certificate", &self.certificate)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl Tls {
    fn init(certificate: rustls::Certificate, private_key: rustls::PrivateKey) -> anyhow::Result<Self> {
        let public_key = {
            let cert = picky::x509::Cert::from_der(&certificate.0).context("Failed to parse TLS certificate")?;
            TlsPublicKey(cert.public_key().to_der().unwrap())
        };

        let rustls_config = crate::tls_sanity::build_rustls_config(certificate.clone(), private_key.clone())
            .context("Failed build TLS config")?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(rustls_config));

        Ok(Self {
            acceptor,
            certificate,
            private_key,
            public_key,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Conf {
    pub id: Option<Uuid>,
    pub hostname: String,
    pub listeners: Vec<ListenerUrls>,
    pub subscriber: Option<dto::Subscriber>,
    pub capture_path: Option<Utf8PathBuf>,
    pub log_file: Utf8PathBuf,
    pub log_directive: Option<String>,
    pub tls: Option<Tls>,
    pub provisioner_public_key: PublicKey,
    pub sub_provisioner_public_key: Option<Subkey>,
    pub delegation_private_key: Option<PrivateKey>,
    pub plugins: Option<Vec<Utf8PathBuf>>,
    pub recording_path: Option<Utf8PathBuf>,
    pub sogar: dto::SogarConf,
    pub jrl_file: Utf8PathBuf,
    pub debug: dto::DebugConf,
}

impl Conf {
    pub fn from_conf_file(conf_file: &dto::ConfFile) -> anyhow::Result<Self> {
        let hostname = conf_file
            .hostname
            .clone()
            .unwrap_or_else(|| default_hostname().unwrap_or_else(|| "localhost".to_owned()));

        let auto_ipv6 = detect_ipv6_support();

        let mut listeners = Vec::new();

        for (idx, listener) in conf_file.listeners.iter().enumerate() {
            let mut listener_urls = to_listener_urls(listener, &hostname, auto_ipv6)
                .with_context(|| format!("Listener at position {idx}"))?;
            listeners.append(&mut listener_urls);
        }

        let has_http_listener = listeners
            .iter()
            .any(|l| matches!(l.internal_url.scheme(), "http" | "https" | "ws" | "wss"));

        if !has_http_listener {
            anyhow::bail!("At least one HTTP-capable listener is required");
        }

        let tls = conf_file
            .tls_certificate_file
            .as_ref()
            .zip(conf_file.tls_private_key_file.as_ref())
            .map(|(cert_file, key_file)| {
                let tls_certificate = read_rustls_certificate_file(cert_file).context("TLS certificate")?;
                let tls_private_key = read_rustls_priv_key_file(key_file).context("TLS private key")?;
                Tls::init(tls_certificate, tls_private_key).context("Failed to init TLS config")
            })
            .transpose()?;

        let requires_tls = listeners
            .iter()
            .any(|l| matches!(l.internal_url.scheme(), "https" | "wss"));

        if requires_tls && tls.is_none() {
            anyhow::bail!("TLS usage implied but TLS configuration is missing (certificate or/and private key)");
        }

        let data_dir = get_data_dir();

        let log_file = conf_file
            .log_file
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("gateway.log"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let jrl_file = conf_file
            .jrl_file
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("jrl.json"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let provisioner_public_key = read_pub_key(
            conf_file.provisioner_public_key_file.as_deref(),
            conf_file.provisioner_public_key_data.as_ref(),
        )
        .context("Provisioner public key")?
        .context("Provisioner public key is missing (no path nor inlined data provided)")?;

        let sub_provisioner_public_key = conf_file
            .sub_provisioner_public_key
            .as_ref()
            .map(|subkey| {
                let kid = subkey.id.clone();
                let key = read_pub_key_data(&subkey.data).context("Sub provisioner public key")?;
                Ok::<_, anyhow::Error>(Subkey { data: key, kid })
            })
            .transpose()?;

        let delegation_private_key = read_priv_key(
            conf_file.delegation_private_key_file.as_deref(),
            conf_file.delegation_private_key_data.as_ref(),
        )
        .context("Delegation private key")?;

        Ok(Conf {
            id: conf_file.id,
            hostname,
            listeners,
            subscriber: conf_file.subscriber.clone(),
            capture_path: conf_file.capture_path.clone(),
            log_file,
            log_directive: conf_file.log_directive.clone(),
            tls,
            provisioner_public_key,
            sub_provisioner_public_key,
            delegation_private_key,
            plugins: conf_file.plugins.clone(),
            recording_path: conf_file.recording_path.clone(),
            sogar: conf_file.sogar.clone().unwrap_or_default(),
            jrl_file,
            debug: conf_file.debug.clone().unwrap_or_default(),
        })
    }
}

fn detect_ipv6_support() -> bool {
    std::net::TcpListener::bind(("[::]", 0)).is_ok()
}

/// Configuration Handle, source of truth for current configuration state
#[derive(Clone)]
pub struct ConfHandle {
    inner: Arc<ConfHandleInner>,
}

struct ConfHandleInner {
    conf: parking_lot::RwLock<Arc<Conf>>,
    conf_file: parking_lot::RwLock<Arc<dto::ConfFile>>,
    changed: Notify,
}

impl ConfHandle {
    /// Initializes configuration for this instance.
    ///
    /// It's best to call this only once to avoid inconsistencies.
    pub fn init() -> anyhow::Result<Self> {
        let conf_file = load_conf_file_or_generate_new()?;
        let conf = Conf::from_conf_file(&conf_file).context("Invalid configuration file")?;

        Ok(Self {
            inner: Arc::new(ConfHandleInner {
                conf: parking_lot::RwLock::new(Arc::new(conf)),
                conf_file: parking_lot::RwLock::new(Arc::new(conf_file)),
                changed: Notify::new(),
            }),
        })
    }

    /// Returns current configuration state (do not hold it forever as it may become outdated)
    pub fn get_conf(&self) -> Arc<Conf> {
        self.inner.conf.read().clone()
    }

    /// Returns current configuration file state (do not hold it forever as it may become outdated)
    pub fn get_conf_file(&self) -> Arc<dto::ConfFile> {
        self.inner.conf_file.read().clone()
    }

    /// Waits for configuration to be changed
    pub async fn change_notified(&self) {
        self.inner.changed.notified().await;
    }

    /// Atomically saves and replaces current configuration with a new one
    #[instrument(skip(self))]
    pub fn save_new_conf_file(&self, conf_file: dto::ConfFile) -> anyhow::Result<()> {
        let conf = Conf::from_conf_file(&conf_file).context("Invalid configuration file")?;
        save_config(&conf_file).context("Failed to save configuration")?;
        *self.inner.conf.write() = Arc::new(conf);
        *self.inner.conf_file.write() = Arc::new(conf_file);
        self.inner.changed.notify_waiters();
        trace!("success");
        Ok(())
    }
}

fn save_config(conf: &dto::ConfFile) -> anyhow::Result<()> {
    let conf_file_path = get_conf_file_path();
    let json = serde_json::to_string_pretty(conf).context("Failed JSON serialization of configuration")?;
    std::fs::write(&conf_file_path, &json).with_context(|| format!("Failed to write file at {conf_file_path}"))?;
    Ok(())
}

fn get_data_dir() -> Utf8PathBuf {
    if let Ok(config_path_env) = env::var("DGATEWAY_CONFIG_PATH") {
        Utf8PathBuf::from(config_path_env)
    } else {
        let mut config_path = Utf8PathBuf::new();

        if cfg!(target_os = "windows") {
            let program_data_env = env::var("ProgramData").expect("ProgramData env variable");
            config_path.push(program_data_env);
            config_path.push(COMPANY_DIR);
            config_path.push(PROGRAM_DIR);
        } else if cfg!(target_os = "macos") {
            config_path.push("/Library/Application Support");
            config_path.push(APPLICATION_DIR);
        } else {
            config_path.push("/etc");
            config_path.push(APPLICATION_DIR);
        }

        config_path
    }
}

fn get_conf_file_path() -> Utf8PathBuf {
    get_data_dir().join("gateway.json")
}

fn normalize_data_path(path: &Utf8Path, data_dir: &Utf8Path) -> Utf8PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        data_dir.join(path)
    }
}

fn load_conf_file(conf_path: &Utf8Path) -> anyhow::Result<Option<dto::ConfFile>> {
    match File::open(conf_path) {
        Ok(file) => BufReader::new(file)
            .pipe(serde_json::from_reader)
            .map(Some)
            .with_context(|| format!("Invalid config file at {conf_path}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!(e).context(format!("Couldn't open config file at {conf_path}"))),
    }
}

pub fn load_conf_file_or_generate_new() -> anyhow::Result<dto::ConfFile> {
    let conf_file_path = get_conf_file_path();

    let conf_file = match load_conf_file(&conf_file_path).context("Failed to load configuration")? {
        Some(conf_file) => conf_file,
        None => {
            let defaults = dto::ConfFile::generate_new();
            println!("Write default configuration to disk…");
            save_config(&defaults).context("Failed to save configuration")?;
            defaults
        }
    };

    Ok(conf_file)
}

fn default_hostname() -> Option<String> {
    hostname::get().ok()?.into_string().ok()
}

fn read_rustls_certificate_file(path: &Utf8Path) -> anyhow::Result<rustls::Certificate> {
    read_rustls_certificate(Some(path), None).transpose().unwrap()
}

fn read_rustls_certificate(
    path: Option<&Utf8Path>,
    data: Option<&dto::ConfData<dto::CertFormat>>,
) -> anyhow::Result<Option<rustls::Certificate>> {
    match (path, data) {
        (Some(path), _) => {
            let pem: Pem = normalize_data_path(path, &get_data_dir())
                .pipe_ref(std::fs::read_to_string)
                .with_context(|| format!("Couldn't read file at {path}"))?
                .pipe_deref(str::parse)
                .context("Couldn't parse pem document")?;

            if pem.label() != CERTIFICATE_LABEL {
                anyhow::bail!("bad pem label (expected {})", CERTIFICATE_LABEL);
            }

            Ok(Some(rustls::Certificate(pem.into_data().into_owned())))
        }
        (None, Some(data)) => {
            let value = data.decode_value()?;

            match data.format {
                dto::CertFormat::X509 => Ok(Some(rustls::Certificate(value))),
            }
        }
        (None, None) => Ok(None),
    }
}

fn read_pub_key_data(data: &dto::ConfData<dto::PubKeyFormat>) -> anyhow::Result<PublicKey> {
    read_pub_key(None, Some(data)).transpose().unwrap()
}

fn read_pub_key(
    path: Option<&Utf8Path>,
    data: Option<&dto::ConfData<dto::PubKeyFormat>>,
) -> anyhow::Result<Option<PublicKey>> {
    match (path, data) {
        (Some(path), _) => normalize_data_path(path, &get_data_dir())
            .pipe_ref(std::fs::read_to_string)
            .with_context(|| format!("Couldn't read file at {path}"))?
            .pipe_deref(PublicKey::from_pem_str)
            .context("Couldn't parse pem document")
            .map(Some),
        (None, Some(data)) => {
            let value = data.decode_value()?;

            match data.format {
                dto::PubKeyFormat::Spki => PublicKey::from_der(&value).context("Bad SPKI"),
                dto::PubKeyFormat::Rsa => PublicKey::from_rsa_der(&value).context("Bad RSA value"),
            }
            .map(Some)
        }
        (None, None) => Ok(None),
    }
}

fn read_rustls_priv_key_file(path: &Utf8Path) -> anyhow::Result<rustls::PrivateKey> {
    read_rustls_priv_key(Some(path), None).transpose().unwrap()
}

fn read_rustls_priv_key(
    path: Option<&Utf8Path>,
    data: Option<&dto::ConfData<dto::PrivKeyFormat>>,
) -> anyhow::Result<Option<rustls::PrivateKey>> {
    let data = match (path, data) {
        (Some(path), _) => {
            let pem: Pem = normalize_data_path(path, &get_data_dir())
                .pipe_ref(std::fs::read_to_string)
                .with_context(|| format!("Couldn't read file at {path}"))?
                .pipe_deref(str::parse)
                .context("Couldn't parse pem document")?;

            if PRIVATE_KEY_LABELS.iter().all(|&label| pem.label() != label) {
                anyhow::bail!("bad pem label (expected one of {:?})", PRIVATE_KEY_LABELS);
            }

            pem.into_data().into_owned()
        }
        (None, Some(data)) => data.decode_value()?,
        (None, None) => return Ok(None),
    };

    Ok(Some(rustls::PrivateKey(data)))
}

fn read_priv_key(
    path: Option<&Utf8Path>,
    data: Option<&dto::ConfData<dto::PrivKeyFormat>>,
) -> anyhow::Result<Option<PrivateKey>> {
    match (path, data) {
        (Some(path), _) => normalize_data_path(path, &get_data_dir())
            .pipe_ref(std::fs::read_to_string)
            .with_context(|| format!("Couldn't read file at {path}"))?
            .pipe_deref(PrivateKey::from_pem_str)
            .context("Couldn't parse pem document")
            .map(Some),
        (None, Some(data)) => {
            let value = data.decode_value()?;

            match data.format {
                dto::PrivKeyFormat::Pkcs8 => PrivateKey::from_pkcs8(&value).context("Bad PKCS8"),
                dto::PrivKeyFormat::Ec => PrivateKey::from_ec_der(&value).context("Bad EC value"),
                dto::PrivKeyFormat::Rsa => PrivateKey::from_rsa_der(&value).context("Bad RSA value"),
            }
            .map(Some)
        }
        (None, None) => Ok(None),
    }
}

fn to_listener_urls(conf: &dto::ListenerConf, hostname: &str, auto_ipv6: bool) -> anyhow::Result<Vec<ListenerUrls>> {
    fn map_scheme(url: &mut Url) {
        match url.scheme() {
            "http" => url.set_scheme("ws").unwrap(),
            "https" => url.set_scheme("wss").unwrap(),
            _ => (),
        }
    }

    let mut internal_url = Url::parse(&conf.internal_url)
        .context("Invalid internal URL")?
        .tap_mut(map_scheme);

    let mut internal_url_ipv6 = None;

    if internal_url.host_str() == Some("*") {
        internal_url
            .set_host(Some("0.0.0.0"))
            .context("Internal URL IPv4 bind address")?;

        if auto_ipv6 {
            let mut ipv6_version = internal_url.clone();
            ipv6_version
                .set_host(Some("[::]"))
                .context("Internal URL IPv6 bind address")?;
            internal_url_ipv6 = Some(ipv6_version);
            println!("{:?}", internal_url_ipv6);
        }
    }

    let mut external_url = Url::parse(&conf.external_url)
        .context("Invalid external URL")?
        .tap_mut(map_scheme);

    if external_url.host_str() == Some("*") {
        external_url.set_host(Some(hostname)).context("External URL hostname")?;
    }

    let mut out = Vec::new();

    if let Some(internal_url_ipv6) = internal_url_ipv6 {
        out.push(ListenerUrls {
            internal_url: internal_url_ipv6,
            external_url: external_url.clone(),
        })
    }

    out.push(ListenerUrls {
        internal_url,
        external_url,
    });

    Ok(out)
}

pub mod dto {
    use super::*;

    /// Source of truth for Gateway configuration
    ///
    /// This struct represents the JSON file used for configuration as close as possible
    /// and is not trying to be too smart.
    ///
    /// Unstable options are subject to change
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ConfFile {
        /// This Gateway unique ID (e.g.: 123e4567-e89b-12d3-a456-426614174000)
        pub id: Option<Uuid>,
        /// This Gateway hostname (e.g.: my-relay.ngrok.io)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub hostname: Option<String>,

        /// Path to provisioner key to verify tokens without restriction
        pub provisioner_public_key_file: Option<Utf8PathBuf>,
        /// Inlined provisioner key to verify tokens without restriction
        #[serde(skip_serializing_if = "Option::is_none")]
        pub provisioner_public_key_data: Option<ConfData<PubKeyFormat>>,

        /// Sub provisioner key which can only be used when establishing a session
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sub_provisioner_public_key: Option<SubProvisionerKeyConf>,

        /// Delegation key used to decipher sensitive data
        #[serde(skip_serializing_if = "Option::is_none")]
        pub delegation_private_key_file: Option<Utf8PathBuf>,
        /// Inlined delegation key to decipher sensitive data
        #[serde(skip_serializing_if = "Option::is_none")]
        pub delegation_private_key_data: Option<ConfData<PrivKeyFormat>>,

        // TLS config
        /// Certificate to use for TLS
        #[serde(alias = "CertificateFile")]
        pub tls_certificate_file: Option<Utf8PathBuf>,
        /// Private key to use for TLS
        #[serde(alias = "PrivateKeyFile")]
        pub tls_private_key_file: Option<Utf8PathBuf>,

        /// Listeners to launch at startup
        pub listeners: Vec<ListenerConf>,

        /// Subscriber API
        #[serde(skip_serializing_if = "Option::is_none")]
        pub subscriber: Option<Subscriber>,

        /// (Unstable) Folder and prefix for log files
        #[serde(skip_serializing_if = "Option::is_none")]
        pub log_file: Option<Utf8PathBuf>,
        /// (Unstable) Path to the JRL file
        #[serde(skip_serializing_if = "Option::is_none")]
        pub jrl_file: Option<Utf8PathBuf>,
        /// (Unstable) Directive string in the same form as the RUST_LOG environment variable
        #[serde(skip_serializing_if = "Option::is_none")]
        pub log_directive: Option<String>,

        /// (Unstable) Plugin paths to load at startup
        #[serde(skip_serializing_if = "Option::is_none")]
        pub plugins: Option<Vec<Utf8PathBuf>>,
        /// (Unstable) Recording path to be provided to the recording plugin
        #[serde(skip_serializing_if = "Option::is_none")]
        pub recording_path: Option<Utf8PathBuf>,
        /// (Unstable) Folder where pcap recordings should be stored
        /// Providing this option will cause the PCAP interceptor to be attached to each stream.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub capture_path: Option<Utf8PathBuf>,

        /// (Unstable) Sogar (generic OCI registry)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sogar: Option<SogarConf>,

        /// (Unstable) Unsafe debug options for developers
        #[serde(default, rename = "__debug__", skip_serializing_if = "Option::is_none")]
        pub debug: Option<DebugConf>,

        // Other unofficial options.
        // This field is useful so that we can deserialize
        // and then losslessly serialize back all root keys of the config file.
        #[serde(flatten)]
        pub rest: serde_json::Map<String, serde_json::Value>,
    }

    impl ConfFile {
        pub fn generate_new() -> Self {
            Self {
                id: Some(Uuid::new_v4()),
                hostname: None,
                provisioner_public_key_file: Some("provisioner.pub.key".into()),
                provisioner_public_key_data: None,
                sub_provisioner_public_key: None,
                delegation_private_key_file: None,
                delegation_private_key_data: None,
                tls_certificate_file: None,
                tls_private_key_file: None,
                listeners: vec![
                    ListenerConf {
                        internal_url: "tcp://*:8080".try_into().unwrap(),
                        external_url: "tcp://*:8080".try_into().unwrap(),
                    },
                    ListenerConf {
                        internal_url: "ws://*:7171".try_into().unwrap(),
                        external_url: "wss://*:7171".try_into().unwrap(),
                    },
                ],
                subscriber: None,
                log_file: None,
                jrl_file: None,
                log_directive: None,
                plugins: None,
                recording_path: None,
                capture_path: None,
                sogar: None,
                debug: None,
                rest: serde_json::Map::new(),
            }
        }
    }

    /// Unsafe debug options that should only ever be used at development stage
    ///
    /// These options might change or get removed without further notice.
    ///
    /// Note to developers: all options should be safe by default, never add an option
    /// that needs to be overridden manually in order to be safe.
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    pub struct DebugConf {
        /// Dump received tokens using a `debug` statement
        #[serde(default)]
        pub dump_tokens: bool,

        /// Ignore token signature and accept as-is (any signer is accepted), expired tokens and token
        /// reuse is allowed, etc. Only restriction is to provide claims in the right format.
        #[serde(default)]
        pub disable_token_validation: bool,

        /// Ignore KDC address provided by KDC token, and use this one instead
        pub override_kdc: Option<TargetAddr>,
    }

    /// Manual Default trait implementation just to make sure default values are deliberates
    #[allow(clippy::derivable_impls)]
    impl Default for DebugConf {
        fn default() -> Self {
            Self {
                dump_tokens: false,
                disable_token_validation: false,
                override_kdc: None,
            }
        }
    }

    impl DebugConf {
        pub fn is_default(&self) -> bool {
            Self::default().eq(self)
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct SogarConf {
        pub registry_url: String,
        pub username: String,
        pub password: String,
        pub image_name: String,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub user_list: Vec<SogarUser>,
        #[serde(default)]
        pub serve_as_registry: bool,
        pub registry_name: String,
        pub registry_image: String,
        #[serde(default)]
        pub push_files: bool,
        #[serde(default)]
        pub keep_files: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub keep_time: Option<u64>,
    }

    impl Default for SogarConf {
        fn default() -> Self {
            Self {
                registry_url: String::new(),
                username: String::new(),
                password: String::new(),
                image_name: "videos".to_owned(),
                user_list: Vec::new(),
                serve_as_registry: false,
                registry_name: "devolutions_registry".to_owned(),
                registry_image: "videos".to_owned(),
                push_files: false,
                keep_files: false,
                keep_time: None,
            }
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    pub enum SogarPermission {
        Push,
        Pull,
    }

    #[derive(PartialEq, Eq, Debug, Default, Clone, Serialize, Deserialize)]
    pub struct SogarUser {
        pub password: Option<String>,
        pub username: Option<String>,
        pub permission: Option<SogarPermission>,
    }

    #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
    #[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
    pub enum DataEncoding {
        #[default]
        Multibase,
        Base64,
        Base64Pad,
        Base64Url,
        Base64UrlPad,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
    pub enum CertFormat {
        #[default]
        X509,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
    pub enum PrivKeyFormat {
        #[default]
        Pkcs8,
        Ec,
        Rsa,
    }

    #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
    #[derive(PartialEq, Eq, Debug, Clone, Default, Serialize, Deserialize)]
    pub enum PubKeyFormat {
        #[default]
        Spki,
        Rsa,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ConfData<Format> {
        pub value: String,
        #[serde(default)]
        pub format: Format,
        #[serde(default)]
        pub encoding: DataEncoding,
    }

    impl<Format> ConfData<Format> {
        pub fn decode_value(&self) -> anyhow::Result<Vec<u8>> {
            match self.encoding {
                DataEncoding::Multibase => multibase::decode(&self.value).map(|o| o.1),
                DataEncoding::Base64 => multibase::Base::Base64.decode(&self.value),
                DataEncoding::Base64Pad => multibase::Base::Base64Pad.decode(&self.value),
                DataEncoding::Base64Url => multibase::Base::Base64Url.decode(&self.value),
                DataEncoding::Base64UrlPad => multibase::Base::Base64UrlPad.decode(&self.value),
            }
            .context("Invalid encoding for value")
        }
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct SubProvisionerKeyConf {
        pub id: String,
        #[serde(flatten)]
        pub data: ConfData<PubKeyFormat>,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ListenerConf {
        /// URL to use on local network
        pub internal_url: String,
        /// URL to use from external networks
        pub external_url: String,
    }

    /// Subscriber configuration
    #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct Subscriber {
        /// HTTP URL where notification messages are to be sent
        #[cfg_attr(feature = "openapi", schema(value_type = String))]
        pub url: Url,
        /// Bearer token to use when making HTTP requests
        pub token: String,
    }
}
