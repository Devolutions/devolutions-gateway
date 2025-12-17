use anyhow::Context as _;

use crate::doctor::macros::diagnostic;
use crate::doctor::{Args, Diagnostic, DiagnosticCtx, cert_to_pem, help};

pub(crate) fn run(args: &Args, callback: &mut dyn FnMut(Diagnostic) -> bool) {
    #[cfg(not(windows))]
    {
        openssl::run(args, callback);
    }

    match args.subject_name.as_deref() {
        Some(subject_name) if args.allow_network => {
            diagnostic!(callback, native_tls_connect(subject_name, args.server_port));
        }
        _ => {}
    }
}

fn native_tls_connect(ctx: &mut DiagnosticCtx, subject_name: &str, port: Option<u16>) -> anyhow::Result<()> {
    use std::net::TcpStream;

    use native_tls::TlsConnector;

    info!("Connect to {subject_name}");

    let connector = TlsConnector::new().context("failed to build TLS connector")?;

    let socket = TcpStream::connect((subject_name, port.unwrap_or(443)))
        .inspect_err(|_| help::failed_to_connect_to_server(ctx, subject_name))
        .context("failed to connect to server...")?;

    info!("Perform TLS handshake");

    let tls_stream = connector
        .connect(subject_name, socket)
        .inspect_err(|e| {
            let native_tls::HandshakeError::Failure(e) = e else {
                unreachable!()
            };
            parse_tls_connect_error_string(ctx, e, subject_name)
        })
        .context("TLS connection failed")?;

    warn!("We can't retrieve the certification chain using the API exposed by native-tls and schannel crates");

    let peer_certificate = tls_stream
        .peer_certificate()
        .context("failed to retrieve peer certificate")?
        .context("no peer certificate attached to the TLS stream")?;
    let peer_certificate = peer_certificate.to_der().context("peer certificate der conversion")?;

    info!("Peer certificate:");
    let cert_pem = cert_to_pem(&peer_certificate).context("failed to write the peer certificate as PEM")?;
    info!("{cert_pem}");

    Ok(())
}

/// Parses Windows (schannel) error messages and convert them into a helpful diagnostic error
#[cfg(target_os = "windows")]
fn parse_tls_connect_error_string(ctx: &mut DiagnosticCtx, error: &native_tls::Error, hostname: &str) {
    let mut dyn_error: Option<&dyn std::error::Error> = Some(error);

    loop {
        let Some(source_error) = dyn_error.take() else {
            break;
        };

        if let Some(io_error) = source_error.downcast_ref::<std::io::Error>() {
            if let Some(code) = io_error.raw_os_error() {
                if os_error_look_up(ctx, hostname, code) {
                    break;
                }
            }
        }

        let formatted_error = source_error.to_string();

        if str_look_up(ctx, hostname, &formatted_error) {
            break;
        }

        dyn_error = source_error.source();
    }

    fn os_error_look_up(ctx: &mut DiagnosticCtx, hostname: &str, code: i32) -> bool {
        match code {
            -2146762481 => {
                help::cert_invalid_hostname(ctx, hostname);
                true
            }
            -2146762487 => {
                help::cert_unknown_issuer(ctx);
                true
            }
            -2146762495 => {
                help::cert_is_expired(ctx);
                true
            }
            _ => false,
        }
    }

    fn str_look_up(ctx: &mut DiagnosticCtx, hostname: &str, s: &str) -> bool {
        if s.contains("CN name does not match the passed value") {
            help::cert_invalid_hostname(ctx, hostname);
            true
        } else if s.contains("terminated in a root certificate which is not trusted by the trust provider") {
            help::cert_unknown_issuer(ctx);
            true
        } else if s.contains("not within its validity period when verifying against the current system clock") {
            help::cert_is_expired(ctx);
            true
        } else {
            false
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn parse_tls_connect_error_string(_ctx: &mut DiagnosticCtx, _error: &native_tls::Error, _hostname: &str) {}

#[cfg(not(any(target_os = "windows", target_vendor = "apple")))]
mod openssl {
    use std::borrow::Cow;
    use std::path::Path;

    use anyhow::Context as _;
    use openssl::x509::X509;

    use crate::doctor::macros::diagnostic;
    use crate::doctor::{Args, Diagnostic, DiagnosticCtx, InspectCert, help};

    pub(super) fn run(args: &Args, callback: &mut dyn FnMut(Diagnostic) -> bool) {
        let mut server_certificates = Vec::new();

        if let Some(chain_path) = &args.chain_path {
            diagnostic!(callback, openssl_read_chain(&chain_path, &mut server_certificates));
        } else if let Some(subject_name) = args.subject_name.as_deref()
            && args.allow_network
        {
            diagnostic!(
                callback,
                openssl_fetch_chain(subject_name, args.server_port, &mut server_certificates)
            );
        }

        if !server_certificates.is_empty() {
            if let Some(subject_name) = args.subject_name.as_deref() {
                diagnostic!(
                    callback,
                    openssl_check_end_entity_cert(subject_name, &server_certificates)
                );
            }

            diagnostic!(callback, openssl_check_chain(&server_certificates));
        }
    }

    fn openssl_fetch_chain(
        ctx: &mut DiagnosticCtx,
        subject_name: &str,
        port: Option<u16>,
        server_certificates: &mut Vec<X509>,
    ) -> anyhow::Result<()> {
        use std::net::TcpStream;

        use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};

        info!("Connect to {subject_name}");

        let mut builder = SslConnector::builder(SslMethod::tls_client()).context("failed to create SSL builder")?;
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();

        let socket = TcpStream::connect((subject_name, port.unwrap_or(443)))
            .inspect_err(|_| help::failed_to_connect_to_server(ctx, subject_name))
            .context("failed to connect to server...")?;

        info!("Fetch server certificates");

        let stream = connector
            .connect(subject_name, socket)
            .context("TLS connection failed")?;

        let ssl = stream.ssl();

        // On the client side, the chain includes the leaf certificate, but on the server side it does not. Fun!
        for certificate in ssl
            .peer_cert_chain()
            .context("peer certification chain missing from SSL context")?
        {
            server_certificates.push(certificate.to_owned());
        }

        crate::doctor::log_chain(server_certificates.iter());
        help::x509_io_link(ctx, server_certificates.iter());

        Ok(())
    }

    fn openssl_read_chain(
        ctx: &mut DiagnosticCtx,
        chain_path: &Path,
        server_certificates: &mut Vec<X509>,
    ) -> anyhow::Result<()> {
        info!("Read file at {}", chain_path.display());

        let mut file = std::fs::File::open(chain_path)
            .map(std::io::BufReader::new)
            .context("read file from disk")?;

        for (idx, certificate) in rustls_pemfile::certs(&mut file).enumerate() {
            let certificate = certificate.with_context(|| format!("failed to read certificate number {idx}"))?;
            let certificate = X509::from_der(&certificate).context("X509::from_der")?;
            server_certificates.push(certificate);
        }

        crate::doctor::log_chain(server_certificates.iter());
        help::x509_io_link(ctx, server_certificates.iter());

        Ok(())
    }

    fn openssl_check_end_entity_cert(
        ctx: &mut DiagnosticCtx,
        subject_name_to_verify: &str,
        server_certificates: &[X509],
    ) -> anyhow::Result<()> {
        let certificate = server_certificates
            .first()
            .context("end entity certificate is missing")?;

        info!("Inspect the end entity certificate");

        let mut certificate_names = Vec::new();

        let certificate_subject_name = certificate.subject_name();

        for entry in certificate_subject_name.entries() {
            if entry.object().nid() == openssl::nid::Nid::COMMONNAME
                && let Ok(data) = entry.data().as_utf8()
            {
                certificate_names.push(data.to_owned());
            }
        }

        if let Some(alt_names) = certificate.subject_alt_names() {
            for name in alt_names {
                if let Some(dnsname) = name.dnsname() {
                    certificate_names.push(dnsname.to_owned());
                }

                if let Some(directory_name) = name.directory_name() {
                    for entry in directory_name.entries() {
                        if entry.object().nid() == openssl::nid::Nid::COMMONNAME
                            && let Ok(data) = entry.data().as_utf8()
                        {
                            certificate_names.push(data.to_owned());
                        }
                    }
                }
            }
        }

        for value in &certificate_names {
            info!("Found name: {value}");
        }

        info!("Verify validity for subject name {subject_name_to_verify}");

        let success = certificate_names
            .into_iter()
            .any(|certificate_name| crate::doctor::wildcard_host_match(&certificate_name, subject_name_to_verify));

        if !success {
            help::cert_invalid_hostname(ctx, subject_name_to_verify);
            anyhow::bail!(
                "the subject name '{subject_name_to_verify}' does not match any domain identified by the certificate"
            );
        }

        Ok(())
    }

    fn openssl_check_chain(ctx: &mut DiagnosticCtx, server_certificates: &[X509]) -> anyhow::Result<()> {
        use openssl::ssl::{SslConnector, SslMethod};
        use openssl::stack::Stack;
        use openssl::x509::{X509StoreContext, X509VerifyResult};

        info!("Create SSL context");

        let connector = SslConnector::builder(SslMethod::tls_client())
            .context("failed to create SSL builder")?
            .build();

        let connection_configuration = connector.configure().context("failed to configure")?;

        // Use an arbitrary "foo" domain name because X509_verify_cert doesn’t verify it anyway.
        let ssl = connection_configuration.into_ssl("foo").context("into_ssl")?;

        let ssl_context = ssl.ssl_context();
        let store = ssl_context.cert_store();

        info!("Verify chain");

        let mut store_context = X509StoreContext::new().context("failed to create X509 store context")?;

        let mut certs = server_certificates.iter();

        let leaf_certificate = certs.next().context("leaf certificate is missing")?;

        let mut chain = Stack::new().context("create chain stack")?;

        for intermediate_certificate in certs {
            chain
                .push(intermediate_certificate.clone())
                .context("failed to push extra intermediate certificate")?;
        }

        let result = store_context
            .init(store, leaf_certificate, &chain, |ctx| {
                ctx.verify_cert()?;
                Ok(ctx.error())
            })
            .context("verification failed")?;

        if result != X509VerifyResult::OK {
            match result.as_raw() {
                10 => help::cert_is_expired(ctx),
                18 => help_cert_is_self_signed(ctx),
                19 => help::cert_unknown_issuer(ctx),
                _ => (),
            }

            anyhow::bail!("chain verification failed: {}", result.error_string());
        }

        Ok(())
    }

    pub(crate) fn help_cert_is_self_signed(ctx: &mut DiagnosticCtx) {
        ctx.attach_help("The certificate is self-signed.
It is generally considered a bad practice to use self-signed certificates, because it goes against the purpose of public key infrastructures (PKIs).
To resolve this issue, you can:
- Trust the self-signed certificate on your system, if you know what you are doing.
- Obtain and use a certificate signed by a legitimate certification authority.");
    }

    impl InspectCert for X509 {
        fn der(&self) -> anyhow::Result<Cow<'_, [u8]>> {
            let der = self.to_der()?;
            Ok(Cow::Owned(der))
        }

        fn friendly_name(&self) -> Option<Cow<'_, str>> {
            let mut friendly_name = String::new();

            self.subject_name().entries().enumerate().for_each(|(idx, entry)| {
                if idx > 0 {
                    friendly_name.push(' ');
                }

                if let Ok(name) = entry.data().as_utf8() {
                    friendly_name.push_str(&name);
                }
            });

            Some(Cow::Owned(friendly_name))
        }
    }
}
