use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use std::{env, fmt};

use anyhow::Context;
use camino::{Utf8Path, Utf8PathBuf};
use cfg_if::cfg_if;
use picky::key::{PrivateKey, PublicKey};
use picky::pem::Pem;
use tap::prelude::*;
use tokio::sync::Notify;
use tokio_rustls::rustls::pki_types;
use url::Url;
use uuid::Uuid;

use crate::SYSTEM_LOGGER;
use crate::credential::Password;
use crate::listener::ListenerUrls;
use crate::target_addr::TargetAddr;
use crate::token::Subkey;

const CERTIFICATE_LABELS: &[&str] = &["CERTIFICATE", "X509 CERTIFICATE", "TRUSTED CERTIFICATE"];
const PRIVATE_KEY_LABELS: &[&str] = &["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"];
const WEB_APP_TOKEN_DEFAULT_LIFETIME_SECS: u64 = 28800; // 8 hours
const WEB_APP_DEFAULT_LOGIN_LIMIT_RATE: u8 = 10;
const ENV_VAR_DGATEWAY_WEBAPP_PATH: &str = "DGATEWAY_WEBAPP_PATH";
const ENV_VAR_DGATEWAY_LIB_XMF_PATH: &str = "DGATEWAY_LIB_XMF_PATH";

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
}

impl fmt::Debug for Tls {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TlsConfig").finish_non_exhaustive()
    }
}

impl Tls {
    fn init(cert_source: crate::tls::CertificateSource, strict_checks: bool) -> anyhow::Result<Self> {
        let tls_server_config = crate::tls::build_server_config(cert_source, strict_checks)?;

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_server_config));

        Ok(Self { acceptor })
    }
}

#[derive(Debug, Clone)]
pub struct Conf {
    pub id: Option<Uuid>,
    pub hostname: String,
    pub listeners: Vec<ListenerUrls>,
    pub subscriber: Option<dto::Subscriber>,
    pub log_file: Utf8PathBuf,
    pub job_queue_database: Utf8PathBuf,
    pub traffic_audit_database: Utf8PathBuf,
    pub tls: Option<Tls>,
    pub provisioner_public_key: PublicKey,
    pub provisioner_private_key: Option<PrivateKey>,
    pub sub_provisioner_public_key: Option<Subkey>,
    pub delegation_private_key: Option<PrivateKey>,
    pub plugins: Option<Vec<Utf8PathBuf>>,
    pub recording_path: Utf8PathBuf,
    pub sogar: dto::SogarConf,
    pub jrl_file: Utf8PathBuf,
    pub ngrok: Option<dto::NgrokConf>,
    pub verbosity_profile: dto::VerbosityProfile,
    pub web_app: WebAppConf,
    pub debug: dto::DebugConf,
}

#[derive(PartialEq, Debug, Clone)]
pub struct WebAppConf {
    pub enabled: bool,
    pub authentication: WebAppAuth,
    pub app_token_maximum_lifetime: std::time::Duration,
    pub login_limit_rate: u8,
    pub static_root_path: std::path::PathBuf,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum WebAppAuth {
    Custom(HashMap<String, WebAppUser>),
    None,
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct WebAppUser {
    pub name: String,
    /// Hash of the password, in the PHC string format
    pub password_hash: Password,
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

        let has_ngrok_http_listener = if let Some(ngrok_conf) = &conf_file.ngrok {
            ngrok_conf
                .tunnels
                .values()
                .any(|t| matches!(t, dto::NgrokTunnelConf::Http(_)))
        } else {
            false
        };

        anyhow::ensure!(
            has_http_listener | has_ngrok_http_listener,
            "at least one HTTP-capable listener is required",
        );

        let requires_tls = listeners
            .iter()
            .any(|l| matches!(l.internal_url.scheme(), "https" | "wss"));

        let strict_checks = conf_file.tls_verify_strict.unwrap_or(false);

        let tls = match conf_file.tls_certificate_source.unwrap_or_default() {
            dto::CertSource::External => match conf_file.tls_certificate_file.as_ref() {
                None if requires_tls => anyhow::bail!("TLS usage implied, but TLS certificate file is missing"),
                None => None,
                Some(certificate_path) => {
                    let (certificates, private_key) = match certificate_path.extension() {
                        Some("pfx" | "p12") => {
                            read_pfx_file(certificate_path, conf_file.tls_private_key_password.as_ref())
                                .context("read PFX/PKCS12 file")?
                        }
                        None | Some(_) => {
                            let certificates =
                                read_rustls_certificate_file(certificate_path).context("read TLS certificate")?;

                            let private_key = conf_file
                                .tls_private_key_file
                                .as_ref()
                                .context("TLS private key file is missing")?
                                .pipe_deref(read_rustls_priv_key_file)
                                .context("read TLS private key")?;

                            (certificates, private_key)
                        }
                    };

                    let cert_source = crate::tls::CertificateSource::External {
                        certificates,
                        private_key,
                    };

                    let tls =
                        Tls::init(cert_source, strict_checks).context("failed to initialize TLS configuration")?;

                    let _ = SYSTEM_LOGGER.emit(sysevent_codes::tls_configured("filesystem"));

                    Some(tls)
                }
            },
            dto::CertSource::System => match conf_file.tls_certificate_subject_name.clone() {
                None if requires_tls => anyhow::bail!("TLS usage implied, but TLS certificate subject name is missing"),
                None => None,
                Some(cert_subject_name) => {
                    let store_location = conf_file.tls_certificate_store_location.unwrap_or_default();

                    let store_name = conf_file
                        .tls_certificate_store_name
                        .clone()
                        .unwrap_or_else(|| String::from("My"));

                    let cert_source = crate::tls::CertificateSource::SystemStore {
                        machine_hostname: hostname.clone(),
                        cert_subject_name,
                        store_location,
                        store_name,
                    };

                    let tls =
                        Tls::init(cert_source, strict_checks).context("failed to initialize TLS configuration")?;

                    let _ = SYSTEM_LOGGER.emit(sysevent_codes::tls_configured("system"));

                    Some(tls)
                }
            },
        };

        // Sanity check
        if requires_tls && tls.is_none() {
            anyhow::bail!("TLS usage implied but TLS configuration is missing (certificate or/and private key)");
        }

        let data_dir = get_data_dir();

        let log_file = conf_file
            .log_file
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("gateway"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let job_queue_database = conf_file
            .job_queue_database
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("job_queue.db"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let traffic_audit_database = conf_file
            .traffic_audit_database
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("traffic_audit.db"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let jrl_file = conf_file
            .jrl_file
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("jrl.json"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let recording_path = conf_file
            .recording_path
            .clone()
            .unwrap_or_else(|| Utf8PathBuf::from("recordings"))
            .pipe_ref(|path| normalize_data_path(path, &data_dir));

        let provisioner_public_key = read_pub_key(
            conf_file.provisioner_public_key_file.as_deref(),
            conf_file.provisioner_public_key_data.as_ref(),
        )
        .context("provisioner public key")?
        .context("provisioner public key is missing (no path nor inlined data provided)")?;

        let provisioner_private_key = read_priv_key(
            conf_file.provisioner_private_key_file.as_deref(),
            conf_file.provisioner_private_key_data.as_ref(),
        )
        .context("provisioner public key")?;

        let sub_provisioner_public_key = conf_file
            .sub_provisioner_public_key
            .as_ref()
            .map(|subkey| {
                let kid = subkey.id.clone();
                let key = read_pub_key_data(&subkey.data).context("sub provisioner public key")?;
                Ok::<_, anyhow::Error>(Subkey { data: key, kid })
            })
            .transpose()?;

        let delegation_private_key = read_priv_key(
            conf_file.delegation_private_key_file.as_deref(),
            conf_file.delegation_private_key_data.as_ref(),
        )
        .context("delegation private key")?;

        if let Some(web_app_conf) = &conf_file.web_app
            && web_app_conf.enabled
        {
            anyhow::ensure!(
                provisioner_private_key.is_some(),
                "provisioner private key must be specified when the standalone web application is enabled",
            );
        }

        Ok(Conf {
            id: conf_file.id,
            hostname,
            listeners,
            subscriber: conf_file.subscriber.clone(),
            log_file,
            job_queue_database,
            traffic_audit_database,
            tls,
            provisioner_public_key,
            provisioner_private_key,
            sub_provisioner_public_key,
            delegation_private_key,
            plugins: conf_file.plugins.clone(),
            recording_path,
            sogar: conf_file.sogar.clone().unwrap_or_default(),
            jrl_file,
            ngrok: conf_file.ngrok.clone(),
            verbosity_profile: conf_file.verbosity_profile.unwrap_or_default(),
            web_app: conf_file
                .web_app
                .as_ref()
                .map(WebAppConf::from_dto)
                .unwrap_or_else(WebAppConf::from_env)
                .context("webapp config")?,
            debug: conf_file.debug.clone().unwrap_or_default(),
        })
    }

    pub fn get_lib_xmf_path(&self) -> Option<Utf8PathBuf> {
        if let Ok(path) = env::var(ENV_VAR_DGATEWAY_LIB_XMF_PATH) {
            return Some(Utf8PathBuf::from(path));
        }

        if let Some(path) = self.debug.lib_xmf_path.as_deref() {
            return Some(path.to_owned());
        }

        if cfg!(target_os = "windows") {
            let path = env::current_exe().ok()?.parent()?.join("xmf.dll");
            Utf8PathBuf::from_path_buf(path).ok()
        } else if cfg!(target_os = "linux") {
            Some(Utf8PathBuf::from("/usr/lib/devolutions-gateway/libxmf.so"))
        } else {
            None
        }
    }
}

impl WebAppConf {
    fn from_dto(value: &dto::WebAppConf) -> anyhow::Result<Self> {
        let authentication = match value.authentication {
            dto::WebAppAuth::Custom => {
                let users_file = value
                    .users_file
                    .clone()
                    .unwrap_or_else(|| Utf8PathBuf::from("users.txt"))
                    .pipe_ref(|path| normalize_data_path(path, &get_data_dir()));

                let users_contents = std::fs::read_to_string(&users_file)
                    .with_context(|| format!("failed to read file at {users_file}"))?;

                let mut users = HashMap::new();

                for line in users_contents.lines() {
                    // Skip blank lines and commented lines.
                    if line.trim().is_empty() || line.starts_with('#') {
                        continue;
                    }

                    let (user, hash) = line.split_once(':').context("missing separator in users file")?;

                    users.insert(
                        user.to_owned(),
                        WebAppUser {
                            name: user.to_owned(),
                            password_hash: hash.to_owned().into(),
                        },
                    );
                }

                WebAppAuth::Custom(users)
            }
            dto::WebAppAuth::None => WebAppAuth::None,
        };

        let app_token_maximum_lifetime = std::time::Duration::from_secs(
            value
                .app_token_maximum_lifetime
                .unwrap_or(WEB_APP_TOKEN_DEFAULT_LIFETIME_SECS),
        );

        let static_root_path = if let Ok(path) = env::var(ENV_VAR_DGATEWAY_WEBAPP_PATH) {
            std::path::PathBuf::from(path)
        } else if let Some(path) = &value.static_root_path {
            path.as_std_path().to_owned()
        } else {
            Self::default_system_static_root_path()?
        };

        let conf = Self {
            enabled: value.enabled,
            authentication,
            app_token_maximum_lifetime,
            login_limit_rate: value.login_limit_rate.unwrap_or(WEB_APP_DEFAULT_LOGIN_LIMIT_RATE),
            static_root_path,
        };

        Ok(conf)
    }

    fn from_env() -> anyhow::Result<Self> {
        let static_root_path = if let Ok(path) = env::var(ENV_VAR_DGATEWAY_WEBAPP_PATH) {
            std::path::PathBuf::from(path)
        } else {
            Self::default_system_static_root_path()?
        };

        Ok(Self {
            enabled: false,
            authentication: WebAppAuth::None,
            app_token_maximum_lifetime: std::time::Duration::from_secs(WEB_APP_TOKEN_DEFAULT_LIFETIME_SECS),
            login_limit_rate: WEB_APP_DEFAULT_LOGIN_LIMIT_RATE,
            static_root_path,
        })
    }

    fn default_system_static_root_path() -> anyhow::Result<std::path::PathBuf> {
        if cfg!(target_os = "windows") {
            let mut exe_path = env::current_exe().context("failed to find service executable location")?;
            exe_path.pop();
            exe_path.push("webapp");
            Ok(exe_path)
        } else if cfg!(target_os = "linux") {
            let mut root_path = std::path::PathBuf::from("/usr/share");
            root_path.push(APPLICATION_DIR);
            root_path.push("webapp");
            Ok(root_path)
        } else {
            anyhow::bail!("standalone web application path must be specified manually on this platform");
        }
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
        let conf = Conf::from_conf_file(&conf_file).context("invalid configuration file")?;

        Ok(Self {
            inner: Arc::new(ConfHandleInner {
                conf: parking_lot::RwLock::new(Arc::new(conf)),
                conf_file: parking_lot::RwLock::new(Arc::new(conf_file)),
                changed: Notify::new(),
            }),
        })
    }

    #[doc(hidden)]
    pub fn mock(json_config: &str) -> anyhow::Result<Self> {
        let conf_file = serde_json::from_str::<dto::ConfFile>(json_config).context("invalid JSON config")?;
        let conf = Conf::from_conf_file(&conf_file).context("invalid configuration file")?;

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
        let conf = Conf::from_conf_file(&conf_file).context("invalid configuration file")?;
        save_config(&conf_file).context("failed to save configuration")?;
        *self.inner.conf.write() = Arc::new(conf);
        *self.inner.conf_file.write() = Arc::new(conf_file);
        self.inner.changed.notify_waiters();
        trace!("success");
        Ok(())
    }
}

fn save_config(conf: &dto::ConfFile) -> anyhow::Result<()> {
    let conf_file_path = get_conf_file_path();
    let json = serde_json::to_string_pretty(conf).context("failed JSON serialization of configuration")?;
    std::fs::write(&conf_file_path, json).with_context(|| format!("failed to write file at {conf_file_path}"))?;
    Ok(())
}

pub fn get_data_dir() -> Utf8PathBuf {
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
            .with_context(|| format!("invalid config file at {conf_path}")),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(anyhow::anyhow!(e).context(format!("couldn't open config file at {conf_path}"))),
    }
}

#[allow(clippy::print_stdout)] // Logger is likely not yet initialized at this point, so it’s fine to write to stdout.
pub fn load_conf_file_or_generate_new() -> anyhow::Result<dto::ConfFile> {
    let conf_file_path = get_conf_file_path();

    let conf_file = match load_conf_file(&conf_file_path).context("failed to load configuration")? {
        Some(conf_file) => conf_file,
        None => {
            let defaults = dto::ConfFile::generate_new();
            println!("Write default configuration to {conf_file_path}…");
            save_config(&defaults).context("failed to save configuration")?;
            defaults
        }
    };

    Ok(conf_file)
}

fn default_hostname() -> Option<String> {
    hostname::get().ok()?.into_string().ok()
}

fn read_pfx_file(
    path: &Utf8Path,
    password: Option<&Password>,
) -> anyhow::Result<(
    Vec<pki_types::CertificateDer<'static>>,
    pki_types::PrivateKeyDer<'static>,
)> {
    use picky::pkcs12::{
        Pfx, Pkcs12AttributeKind, Pkcs12CryptoContext, Pkcs12ParsingParams, SafeBagKind, SafeContentsKind,
    };
    use picky::x509::certificate::CertType;
    use std::cmp::Ordering;

    let crypto_context = password
        .map(|pwd| Pkcs12CryptoContext::new_with_password(pwd.expose_secret()))
        .unwrap_or_else(Pkcs12CryptoContext::new_without_password);
    let parsing_params = Pkcs12ParsingParams::default();

    let pfx_contents = normalize_data_path(path, &get_data_dir())
        .pipe_ref(std::fs::read)
        .with_context(|| format!("failed to read file at {path}"))?;

    let pfx = Pfx::from_der(&pfx_contents, &crypto_context, &parsing_params).context("failed to decode PFX")?;

    // Build an iterator over all the safe bags of the PFX
    let safe_bags_it = pfx
        .safe_contents()
        .iter()
        .flat_map(|safe_contents| match safe_contents.kind() {
            SafeContentsKind::SafeBags(safe_bags) => safe_bags.iter(),
            SafeContentsKind::EncryptedSafeBags { safe_bags, .. } => safe_bags.iter(),
            SafeContentsKind::Unknown => std::slice::Iter::default(),
        })
        .flat_map(|safe_bag| {
            if let SafeBagKind::Nested(safe_bags) = safe_bag.kind() {
                safe_bags.iter()
            } else {
                std::slice::from_ref(safe_bag).iter()
            }
        });

    let mut certificates = Vec::new();
    let mut private_keys = Vec::new();

    // Iterate on all safe bags, and collect all certificates and private keys along their local key id (which is optional)
    for safe_bag in safe_bags_it {
        let local_key_id = safe_bag.attributes().iter().find_map(|attr| {
            if let Pkcs12AttributeKind::LocalKeyId(key_id) = attr.kind() {
                Some(key_id.as_slice())
            } else {
                None
            }
        });

        match safe_bag.kind() {
            SafeBagKind::PrivateKey(key) | SafeBagKind::EncryptedPrivateKey { key, .. } => {
                private_keys.push((key, local_key_id))
            }
            SafeBagKind::Certificate(cert) => certificates.push((cert, local_key_id)),
            _ => {}
        }
    }

    // Sort certificates such that: Leaf < Unknown < Intermediate < Root (stable sort usage is deliberate)
    certificates.sort_by(|(lhs, _), (rhs, _)| match (lhs.ty(), rhs.ty()) {
        // Equality
        (CertType::Leaf, CertType::Leaf) => Ordering::Equal,
        (CertType::Unknown, CertType::Unknown) => Ordering::Equal,
        (CertType::Intermediate, CertType::Intermediate) => Ordering::Equal,
        (CertType::Root, CertType::Root) => Ordering::Equal,

        // Leaf
        (CertType::Leaf, _) => Ordering::Less,
        (_, CertType::Leaf) => Ordering::Greater,

        // Unknown
        (CertType::Unknown, _) => Ordering::Less,
        (_, CertType::Unknown) => Ordering::Greater,

        // Intermediate
        (CertType::Intermediate, CertType::Root) => Ordering::Less,
        (CertType::Root, CertType::Intermediate) => Ordering::Greater,
    });

    // Find the first certificate that is "closer" to being a leaf
    let (_, leaf_local_key_id) = certificates.first().context("leaf certificate not found")?;

    // If there is a local key id, find the key with this same local key id, otherwise take the first key
    let private_key = if let Some(leaf_local_key_id) = *leaf_local_key_id {
        private_keys
            .into_iter()
            .find_map(|(pk, local_key_id)| match local_key_id {
                Some(local_key_id) if local_key_id == leaf_local_key_id => Some(pk),
                _ => None,
            })
    } else {
        private_keys.into_iter().map(|(pk, _)| pk).next()
    };

    let private_key = private_key.context("leaf private key not found")?.clone();
    let private_key = private_key
        .to_pkcs8()
        .map(|der| pki_types::PrivateKeyDer::Pkcs8(der.into()))
        .context("invalid private key")?;

    let certificates = certificates
        .into_iter()
        .map(|(cert, _)| cert.to_der().map(pki_types::CertificateDer::from))
        .collect::<Result<_, _>>()
        .context("invalid certificate")?;

    Ok((certificates, private_key))
}

fn read_rustls_certificate_file(path: &Utf8Path) -> anyhow::Result<Vec<pki_types::CertificateDer<'static>>> {
    read_rustls_certificate(Some(path), None)
        .transpose()
        .expect("a path is provided, so it’s never None")
}

fn read_rustls_certificate(
    path: Option<&Utf8Path>,
    data: Option<&dto::ConfData<dto::CertFormat>>,
) -> anyhow::Result<Option<Vec<pki_types::CertificateDer<'static>>>> {
    use picky::pem::{PemError, read_pem};

    match (path, data) {
        (Some(path), _) => {
            let mut x509_chain_file = normalize_data_path(path, &get_data_dir())
                .pipe_ref(File::open)
                .with_context(|| format!("couldn't open file at {path}"))?
                .pipe(BufReader::new);

            let mut x509_chain = Vec::new();

            loop {
                match read_pem(&mut x509_chain_file) {
                    Ok(pem) => {
                        if CERTIFICATE_LABELS.iter().all(|&label| pem.label() != label) {
                            anyhow::bail!(
                                "bad pem label (got {}, expected one of {CERTIFICATE_LABELS:?}) at position {}",
                                pem.label(),
                                x509_chain.len(),
                            );
                        }

                        x509_chain.push(pki_types::CertificateDer::from(pem.into_data().into_owned()));
                    }
                    Err(e @ PemError::HeaderNotFound) => {
                        if x509_chain.is_empty() {
                            return anyhow::Error::new(e)
                                .context("couldn't parse first pem document")
                                .pipe(Err);
                        }

                        break;
                    }
                    Err(e) => {
                        return anyhow::Error::new(e)
                            .context(format!("couldn't parse pem document at position {}", x509_chain.len()))
                            .pipe(Err);
                    }
                }
            }

            Ok(Some(x509_chain))
        }
        (None, Some(data)) => {
            let value = data.decode_value()?;

            match data.format {
                dto::CertFormat::X509 => Ok(Some(vec![pki_types::CertificateDer::from(value)])),
            }
        }
        (None, None) => Ok(None),
    }
}

fn read_pub_key_data(data: &dto::ConfData<dto::PubKeyFormat>) -> anyhow::Result<PublicKey> {
    read_pub_key(None, Some(data))
        .transpose()
        .expect("data is provided, so it’s never None")
}

fn read_pub_key(
    path: Option<&Utf8Path>,
    data: Option<&dto::ConfData<dto::PubKeyFormat>>,
) -> anyhow::Result<Option<PublicKey>> {
    match (path, data) {
        (Some(path), _) => normalize_data_path(path, &get_data_dir())
            .pipe_ref(std::fs::read_to_string)
            .with_context(|| format!("couldn't read file at {path}"))?
            .pipe_deref(PublicKey::from_pem_str)
            .context("couldn't parse pem document")
            .map(Some),
        (None, Some(data)) => {
            let value = data.decode_value()?;

            match data.format {
                dto::PubKeyFormat::Spki => PublicKey::from_der(&value).context("bad SPKI"),
                dto::PubKeyFormat::Pkcs1 => PublicKey::from_pkcs1(&value).context("bad RSA value"),
            }
            .map(Some)
        }
        (None, None) => Ok(None),
    }
}

fn read_rustls_priv_key_file(path: &Utf8Path) -> anyhow::Result<pki_types::PrivateKeyDer<'static>> {
    read_rustls_priv_key(Some(path), None)
        .transpose()
        .expect("path is provided, so it’s never None")
}

fn read_rustls_priv_key(
    path: Option<&Utf8Path>,
    data: Option<&dto::ConfData<dto::PrivKeyFormat>>,
) -> anyhow::Result<Option<pki_types::PrivateKeyDer<'static>>> {
    let private_key = match (path, data) {
        (Some(path), _) => {
            let pem: Pem<'_> = normalize_data_path(path, &get_data_dir())
                .pipe_ref(std::fs::read_to_string)
                .with_context(|| format!("couldn't read file at {path}"))?
                .pipe_deref(str::parse)
                .context("couldn't parse pem document")?;

            match pem.label() {
                "PRIVATE KEY" => pki_types::PrivateKeyDer::Pkcs8(pem.into_data().into_owned().into()),
                "RSA PRIVATE KEY" => pki_types::PrivateKeyDer::Pkcs1(pem.into_data().into_owned().into()),
                "EC PRIVATE KEY" => pki_types::PrivateKeyDer::Sec1(pem.into_data().into_owned().into()),
                _ => {
                    anyhow::bail!(
                        "bad pem label (got {}, expected one of {PRIVATE_KEY_LABELS:?})",
                        pem.label(),
                    );
                }
            }
        }
        (None, Some(data)) => {
            let value = data.decode_value()?;

            match data.format {
                dto::PrivKeyFormat::Pkcs8 => pki_types::PrivateKeyDer::Pkcs8(value.into()),
                dto::PrivKeyFormat::Pkcs1 => pki_types::PrivateKeyDer::Pkcs1(value.into()),
                dto::PrivKeyFormat::Ec => pki_types::PrivateKeyDer::Sec1(value.into()),
            }
        }
        (None, None) => return Ok(None),
    };

    Ok(Some(private_key))
}

fn read_priv_key(
    path: Option<&Utf8Path>,
    data: Option<&dto::ConfData<dto::PrivKeyFormat>>,
) -> anyhow::Result<Option<PrivateKey>> {
    match (path, data) {
        (Some(path), _) => normalize_data_path(path, &get_data_dir())
            .pipe_ref(std::fs::read_to_string)
            .with_context(|| format!("couldn't read file at {path}"))?
            .pipe_deref(PrivateKey::from_pem_str)
            .context("couldn't parse pem document")
            .map(Some),
        (None, Some(data)) => {
            let value = data.decode_value()?;

            match data.format {
                dto::PrivKeyFormat::Pkcs8 => PrivateKey::from_pkcs8(&value).context("bad PKCS8"),
                dto::PrivKeyFormat::Pkcs1 => PrivateKey::from_pkcs1(&value).context("bad RSA value"),
                dto::PrivKeyFormat::Ec => PrivateKey::from_ec_der(&value).context("bad EC value"),
            }
            .map(Some)
        }
        (None, None) => Ok(None),
    }
}

fn to_listener_urls(conf: &dto::ListenerConf, hostname: &str, auto_ipv6: bool) -> anyhow::Result<Vec<ListenerUrls>> {
    fn map_scheme(url: &mut Url) {
        match url.scheme() {
            "ws" => url.set_scheme("http").expect("http is a valid scheme"),
            "wss" => url.set_scheme("https").expect("https is a valid scheme"),
            _ => (),
        }
    }

    let mut internal_url = Url::parse(&conf.internal_url)
        .context("invalid internal URL")?
        .tap_mut(map_scheme);

    let mut internal_url_ipv6 = None;

    if internal_url.host_str() == Some("*") {
        internal_url
            .set_host(Some("0.0.0.0"))
            .context("internal URL IPv4 bind address")?;

        if auto_ipv6 {
            let mut ipv6_version = internal_url.clone();
            ipv6_version
                .set_host(Some("[::]"))
                .context("internal URL IPv6 bind address")?;
            internal_url_ipv6 = Some(ipv6_version);
        }
    }

    let mut external_url = Url::parse(&conf.external_url)
        .context("invalid external URL")?
        .tap_mut(map_scheme);

    if external_url.host_str() == Some("*") {
        external_url.set_host(Some(hostname)).context("external URL hostname")?;
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
    use std::collections::HashMap;

    use super::*;

    /// Source of truth for Gateway configuration
    ///
    /// This struct represents the JSON file used for configuration as close as possible
    /// and is not trying to be too smart.
    ///
    /// Unstable options are subject to change
    #[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct ConfFile {
        /// This Gateway unique ID (e.g.: 123e4567-e89b-12d3-a456-426614174000)
        pub id: Option<Uuid>,
        /// This Gateway hostname (e.g.: my-relay.ngrok.io)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub hostname: Option<String>,

        /// Path to provisioner public key to verify tokens without restriction
        pub provisioner_public_key_file: Option<Utf8PathBuf>,
        /// Inlined provisioner public key to verify tokens without restriction
        #[serde(skip_serializing_if = "Option::is_none")]
        pub provisioner_public_key_data: Option<ConfData<PubKeyFormat>>,
        /// Path to the provisioner private key, to generate session tokens in standalone mode (via web application)
        pub provisioner_private_key_file: Option<Utf8PathBuf>,
        /// Inlined provisioner private key, to generate session tokens in standalone mode (via web application)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub provisioner_private_key_data: Option<ConfData<PrivKeyFormat>>,

        /// Sub provisioner public key which can only be used when establishing a session
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sub_provisioner_public_key: Option<SubProvisionerKeyConf>,

        /// Delegation private key used to decipher sensitive data
        #[serde(skip_serializing_if = "Option::is_none")]
        pub delegation_private_key_file: Option<Utf8PathBuf>,
        /// Inlined delegation private key to decipher sensitive data
        #[serde(skip_serializing_if = "Option::is_none")]
        pub delegation_private_key_data: Option<ConfData<PrivKeyFormat>>,

        /// Source for the TLS certificate
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tls_certificate_source: Option<CertSource>,
        /// Certificate to use for TLS
        #[serde(alias = "CertificateFile", skip_serializing_if = "Option::is_none")]
        pub tls_certificate_file: Option<Utf8PathBuf>,
        /// Private key to use for TLS
        #[serde(alias = "PrivateKeyFile", skip_serializing_if = "Option::is_none")]
        pub tls_private_key_file: Option<Utf8PathBuf>,
        /// Password to use for decrypting the TLS private key
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tls_private_key_password: Option<Password>,
        /// Subject name of the certificate to use for TLS
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tls_certificate_subject_name: Option<String>,
        /// Name of the Windows Certificate Store to use
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tls_certificate_store_name: Option<String>,
        /// Location of the Windows Certificate Store to use
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tls_certificate_store_location: Option<CertStoreLocation>,
        /// Enables strict TLS certificate verification.
        ///
        /// When enabled (`true`), the client performs additional checks on the server certificate,
        /// including:
        /// - Ensuring the presence of the **Subject Alternative Name (SAN)** extension.
        /// - Verifying that the **Extended Key Usage (EKU)** extension includes `serverAuth`.
        ///
        /// Certificates that do not meet these requirements are increasingly rejected by modern clients
        /// (e.g., Chrome, macOS). Therefore, we strongly recommend using certificates that comply with
        /// these standards.
        ///
        /// If unset, the default is `true`.
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tls_verify_strict: Option<bool>,

        /// Listeners to launch at startup
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub listeners: Vec<ListenerConf>,

        /// Subscriber API
        #[serde(skip_serializing_if = "Option::is_none")]
        pub subscriber: Option<Subscriber>,

        /// Path to the recordings folder
        #[serde(skip_serializing_if = "Option::is_none")]
        pub recording_path: Option<Utf8PathBuf>,

        /// Ngrok config (closely maps https://ngrok.com/docs/ngrok-agent/config/)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ngrok: Option<NgrokConf>,

        /// Verbosity profile
        #[serde(skip_serializing_if = "Option::is_none")]
        pub verbosity_profile: Option<VerbosityProfile>,

        /// Web application configuration for standalone mode
        #[serde(skip_serializing_if = "Option::is_none")]
        pub web_app: Option<WebAppConf>,

        /// (Unstable) Folder and prefix for log files
        #[serde(skip_serializing_if = "Option::is_none")]
        pub log_file: Option<Utf8PathBuf>,

        /// (Unstable) Path to the JRL file
        #[serde(skip_serializing_if = "Option::is_none")]
        pub jrl_file: Option<Utf8PathBuf>,

        /// (Unstable) Plugin paths to load at startup
        #[serde(skip_serializing_if = "Option::is_none")]
        pub plugins: Option<Vec<Utf8PathBuf>>,

        /// (Unstable) Sogar (generic OCI registry)
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sogar: Option<SogarConf>,

        /// (Unstable) Path to the SQLite database file for the job queue
        #[serde(skip_serializing_if = "Option::is_none")]
        pub job_queue_database: Option<Utf8PathBuf>,

        /// (Unstable) Path to the SQLite database file for the traffic audit repository
        #[serde(skip_serializing_if = "Option::is_none")]
        pub traffic_audit_database: Option<Utf8PathBuf>,

        /// (Unstable) Unsafe debug options for developers
        #[serde(rename = "__debug__", skip_serializing_if = "Option::is_none")]
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
                provisioner_public_key_file: Some("provisioner.pem".into()),
                provisioner_public_key_data: None,
                provisioner_private_key_file: None,
                provisioner_private_key_data: None,
                sub_provisioner_public_key: None,
                delegation_private_key_file: None,
                delegation_private_key_data: None,
                tls_certificate_source: None,
                tls_certificate_file: None,
                tls_private_key_file: None,
                tls_private_key_password: None,
                tls_certificate_subject_name: None,
                tls_certificate_store_name: None,
                tls_certificate_store_location: None,
                tls_verify_strict: Some(true),
                listeners: vec![
                    ListenerConf {
                        internal_url: "tcp://*:8181".to_owned(),
                        external_url: "tcp://*:8181".to_owned(),
                    },
                    ListenerConf {
                        internal_url: "http://*:7171".to_owned(),
                        external_url: "https://*:7171".to_owned(),
                    },
                ],
                subscriber: None,
                ngrok: None,
                verbosity_profile: None,
                log_file: None,
                jrl_file: None,
                plugins: None,
                recording_path: None,
                web_app: None,
                sogar: None,
                job_queue_database: None,
                traffic_audit_database: None,
                debug: None,
                rest: serde_json::Map::new(),
            }
        }
    }

    /// Verbosity profile (pre-defined tracing directives)
    #[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize, Default)]
    pub enum VerbosityProfile {
        /// The default profile, mostly info records
        #[default]
        Default,
        /// Recommended profile for developers
        Debug,
        /// Verbose logging for TLS troubleshooting
        Tls,
        /// Show all traces
        All,
        /// Only show warnings and errors
        Quiet,
    }

    impl VerbosityProfile {
        pub fn to_log_filter(self) -> &'static str {
            match self {
                VerbosityProfile::Default => "info",
                VerbosityProfile::Debug => {
                    "info,devolutions_gateway=debug,devolutions_gateway::api=trace,jmux_proxy=debug,tower_http=trace,job_queue=trace,job_queue_libsql=trace,traffic_audit=trace,traffic_audit_libsql=trace,devolutions_gateway::rdp_proxy=trace"
                }
                VerbosityProfile::Tls => {
                    "info,devolutions_gateway=debug,devolutions_gateway::tls=trace,rustls=trace,tokio_rustls=debug"
                }
                VerbosityProfile::All => "trace",
                VerbosityProfile::Quiet => "warn",
            }
        }
    }

    /// Domain user credentials.
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    pub struct DomainUser {
        pub username: String,
        pub domain: String,
        pub password: String,
    }

    /// Kerberos server config
    ///
    /// This config is used to configure the Kerberos server during RDP proxying.
    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    pub struct KerberosServer {
        /// The maximum allowed time difference between client and proxy clocks
        ///
        /// The value must be in seconds.
        pub max_time_skew: u64,
        /// Ticket decryption key
        ///
        /// This key is used to decrypt the TGS ticket sent by the client. If you do not plan
        /// to use Kerberos U2U authentication, then the `ticket_decryption_key' is required.
        pub ticket_decryption_key: Option<Vec<u8>>,
        /// The domain user credentials for the Kerberos U2U authentication
        ///
        /// This field is needed only for Kerberos User-to-User authentication. If you do not plan
        /// to use Kerberos U2U, do not specify it.
        pub service_user: Option<DomainUser>,
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
        ///
        /// reuse is allowed, etc. Only restriction is to provide claims in the right format.
        #[serde(default)]
        pub disable_token_validation: bool,

        /// Ignore KDC address provided by KDC token, and use this one instead
        pub override_kdc: Option<TargetAddr>,

        /// Directives string in the same form as the RUST_LOG environment variable
        pub log_directives: Option<String>,

        /// Folder where pcap recordings should be stored
        ///
        /// Providing this option will cause the PCAP interceptor to be attached to each stream.
        pub capture_path: Option<Utf8PathBuf>,

        /// Path to the XMF shared library (Cadeau) for runtime loading
        pub lib_xmf_path: Option<Utf8PathBuf>,

        /// WebSocket keep-alive interval in seconds
        ///
        /// The interval in seconds before a Ping message is sent to the other end.
        ///
        /// Default value is 45.
        #[serde(default = "ws_keep_alive_interval_default_value")]
        pub ws_keep_alive_interval: u64,

        /// Kerberos application server configuration
        ///
        /// It is used only during RDP proxying.
        pub kerberos_server: Option<KerberosServer>,

        /// Enable unstable features which may break at any point
        #[serde(default)]
        pub enable_unstable: bool,
    }

    /// Manual Default trait implementation just to make sure default values are deliberates
    #[allow(clippy::derivable_impls)]
    impl Default for DebugConf {
        fn default() -> Self {
            Self {
                dump_tokens: false,
                disable_token_validation: false,
                override_kdc: None,
                log_directives: None,
                capture_path: None,
                lib_xmf_path: None,
                enable_unstable: false,
                kerberos_server: None,
                ws_keep_alive_interval: ws_keep_alive_interval_default_value(),
            }
        }
    }

    impl DebugConf {
        pub fn is_default(&self) -> bool {
            Self::default().eq(self)
        }
    }

    const fn ws_keep_alive_interval_default_value() -> u64 {
        45
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

    #[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
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
    #[derive(PartialEq, Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
    pub enum DataEncoding {
        #[default]
        Multibase,
        Base64,
        Base64Pad,
        Base64Url,
        Base64UrlPad,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
    pub enum CertFormat {
        #[default]
        X509,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
    pub enum PrivKeyFormat {
        #[default]
        Pkcs8,
        #[serde(alias = "Rsa")]
        Pkcs1,
        Ec,
    }

    #[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
    #[derive(PartialEq, Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
    pub enum PubKeyFormat {
        #[default]
        Spki,
        #[serde(alias = "Rsa")]
        Pkcs1,
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
            .context("invalid encoding for value")
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

    #[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct NgrokConf {
        // NOTE: here, we deviate deliberately from ngrok where the name is `authtoken`
        pub auth_token: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub heartbeat_interval: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub heartbeat_tolerance: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub metadata: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub server_addr: Option<String>,
        #[serde(default, skip_serializing_if = "HashMap::is_empty")]
        pub tunnels: HashMap<String, NgrokTunnelConf>,
    }

    #[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "kebab-case")]
    #[serde(tag = "Proto")]
    pub enum NgrokTunnelConf {
        Tcp(NgrokTcpTunnelConf),
        Http(NgrokHttpTunnelConf),
    }

    #[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct NgrokTcpTunnelConf {
        pub remote_addr: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub metadata: Option<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub allow_cidrs: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub deny_cidrs: Vec<String>,
    }

    #[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct NgrokHttpTunnelConf {
        pub domain: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub metadata: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub circuit_breaker: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression: Option<bool>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub allow_cidrs: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub deny_cidrs: Vec<String>,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
    pub enum CertSource {
        /// Provided by filesystem
        #[default]
        External,
        /// Provided by Operating System (Windows Certificate Store, etc)
        System,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Copy, Default, Serialize, Deserialize)]
    pub enum CertStoreLocation {
        #[default]
        CurrentUser,
        CurrentService,
        LocalMachine,
    }

    #[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    pub struct WebAppConf {
        pub enabled: bool,
        pub authentication: WebAppAuth,
        /// Maximum lifetime granted for application tokens, in seconds
        pub app_token_maximum_lifetime: Option<u64>,
        /// The maximum number of login requests for a given username over a minute
        pub login_limit_rate: Option<u8>,
        /// Path to the users file with <user>:<hash> lines
        #[serde(skip_serializing_if = "Option::is_none")]
        pub users_file: Option<Utf8PathBuf>,
        /// Path to the static files for the standalone web application
        pub static_root_path: Option<Utf8PathBuf>,
    }

    #[derive(PartialEq, Eq, Debug, Clone, Copy, Serialize, Deserialize)]
    pub enum WebAppAuth {
        Custom,
        None,
    }
}
