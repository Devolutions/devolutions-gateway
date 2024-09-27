use std::fmt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Context as _;
use onlyargs_derive::OnlyArgs;

shadow_rs::shadow!(build);

macro_rules! diagnostic {
    ( $name:ident ( $( $arg:expr ),* ) ) => {{
        let diagnostic_name = stringify!($name);

        let mut out = String::new();
        let result = $name ( &mut out, $( $arg ),* );

        print!("\n=> {diagnostic_name}… ");

        if result.is_ok() {
            println!("OK ✅");
        } else {
            println!("FAILED ❌");
        }

        if !out.is_empty() {
            for line in out.lines() {
                println!(">> {line}");
            }
        }

        match result {
            Ok(()) => true,
            Err(e) => {
                println!("Error: {e:?}");
                false
            }
        }
    }}
}

macro_rules! output {
    ( $dst:expr, $($arg:tt)* ) => {
        writeln!( $dst, $($arg)* ).context("write output")
    };
}

/// Sanity checks for Devolutions Gateway and Jetsocat.
#[derive(OnlyArgs)]
struct Args {
    #[short('c')]
    check_cert: Option<PathBuf>,
    #[short('n')]
    subject_name: Option<String>,
    #[short('p')]
    server_port: Option<u16>,
}

fn main() -> ExitCode {
    let args: Args = onlyargs::parse().expect("CLI arguments");

    println!("{} {}", build::PROJECT_NAME, build::PKG_VERSION);
    println!("> Tag: {}", build::TAG);
    println!("> Commit hash: {}", build::SHORT_COMMIT);
    println!("> Commit date: {}", build::COMMIT_DATE);
    println!("> Build date: {}", build::BUILD_TIME);

    let mut success = true;
    let mut root_store = rustls::RootCertStore::empty();
    let mut server_certificates = Vec::new();

    success &= diagnostic!(openssl_probe());
    success &= diagnostic!(load_native_certs(&mut root_store));

    if let Some(subject_name) = args.subject_name.as_deref() {
        success &= diagnostic!(fetch_chain(
            subject_name,
            args.server_port,
            root_store.clone(),
            &mut server_certificates
        ));
    }

    if let Some(chain_file_path) = &args.check_cert {
        success &= diagnostic!(read_chain(&chain_file_path, &mut server_certificates));
    }

    if !server_certificates.is_empty() {
        success &= diagnostic!(check_end_entity_cert(
            &server_certificates,
            args.subject_name.as_deref()
        ));
        success &= diagnostic!(check_chain(&root_store, &server_certificates));
    }

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn openssl_probe(mut out: impl fmt::Write) -> anyhow::Result<()> {
    let result = openssl_probe::probe();

    output!(out, "cert_file = {:?}", result.cert_file)?;
    output!(out, "cert_dir = {:?}", result.cert_dir)?;

    Ok(())
}

fn load_native_certs(mut out: impl fmt::Write, root_store: &mut rustls::RootCertStore) -> anyhow::Result<()> {
    for cert in rustls_native_certs::load_native_certs().context("failed to load native certificates")? {
        let cert_der = cert.to_vec();
        if let Err(e) = root_store.add(cert) {
            output!(out, "Invalid root certificate: {e}")?;

            let pem = pem::Pem::new("CERTIFICATE", cert_der);
            output!(out, "{pem}")?;
        }
    }

    Ok(())
}

fn fetch_chain(
    mut out: impl fmt::Write,
    subject_name: &str,
    port: Option<u16>,
    root_store: rustls::RootCertStore,
    server_certificates: &mut Vec<rustls::pki_types::CertificateDer<'static>>,
) -> anyhow::Result<()> {
    use std::io::Write as _;
    use std::net::TcpStream;

    output!(out, "Connect to {subject_name}")?;

    let mut socket =
        TcpStream::connect((subject_name, port.unwrap_or(443))).context("failed to connect to server...")?;

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let config = std::sync::Arc::new(config);
    let subject_name = rustls::pki_types::ServerName::try_from(subject_name.to_owned()).context("invalid DNS name")?;
    let mut client = rustls::ClientConnection::new(config, subject_name).context("failed to create TLS client")?;

    output!(out, "Fetch server certificates")?;

    loop {
        if client.wants_read() {
            client.read_tls(&mut socket).context("read_tls failed")?;
            client.process_new_packets().context("process_new_packets failed")?;
        }

        if client.wants_write() {
            client.write_tls(&mut socket).context("write_tls failed")?;
        }

        socket.flush().context("flush failed")?;

        if let Some(peer_certificates) = client.peer_certificates() {
            for certificate in peer_certificates {
                let pem = pem::Pem::new("CERTIFICATE", certificate.to_vec());
                output!(out, "{pem}")?;

                server_certificates.push(certificate.clone().into_owned());
            }

            break;
        }
    }

    Ok(())
}

fn read_chain(
    mut out: impl fmt::Write,
    chain_file_path: &Path,
    server_certificates: &mut Vec<rustls::pki_types::CertificateDer<'static>>,
) -> anyhow::Result<()> {
    output!(out, "Read file at {}", chain_file_path.display())?;

    let file_contents = std::fs::read(chain_file_path).context("read file from disk")?;

    let parsed = match pem::parse_many(&file_contents) {
        Ok(pems) => {
            output!(out, "Detected PEM format")?;

            pems.into_iter()
                .enumerate()
                .map(|(idx, pem)| {
                    let pem_tag = pem.tag();

                    if pem_tag != "CERTIFICATE" {
                        output!(out, "WARNING: unexpected PEM tag for certificate {idx}: {pem_tag}")?;
                    }

                    anyhow::Ok(pem.into_contents())
                })
                .collect::<anyhow::Result<_>>()?
        }
        Err(pem::PemError::MalformedFraming | pem::PemError::NotUtf8(_)) => {
            output!(out, "Read as raw DER")?;
            vec![file_contents]
        }
        Err(e) => return Err(anyhow::Error::new(e).context("read file as PEM")),
    };

    for certificate in parsed.into_iter() {
        let pem = pem::Pem::new("CERTIFICATE", certificate.clone());
        output!(out, "{pem}")?;

        server_certificates.push(rustls::pki_types::CertificateDer::from(certificate));
    }

    Ok(())
}

fn check_end_entity_cert(
    mut out: impl fmt::Write,
    server_certificates: &[rustls::pki_types::CertificateDer<'static>],
    subject_name: Option<&str>,
) -> anyhow::Result<()> {
    let end_entity_cert = server_certificates.first().cloned().context("empty chain")?;

    output!(out, "Decode end entity certificate")?;

    let end_entity_cert =
        rustls::server::ParsedCertificate::try_from(&end_entity_cert).context("parse end entity certificate")?;

    if let Some(subject_name) = subject_name {
        output!(out, "Verify validity for DNS name")?;

        let subject_name = rustls::pki_types::ServerName::try_from(subject_name).context("invalid DNS name")?;
        rustls::client::verify_server_name(&end_entity_cert, &subject_name).context("verify DNS name")?;
    }

    Ok(())
}

fn check_chain(
    mut out: impl fmt::Write,
    root_store: &rustls::RootCertStore,
    server_certificates: &[rustls::pki_types::CertificateDer<'static>],
) -> anyhow::Result<()> {
    use rustls::client::verify_server_cert_signed_by_trust_anchor;

    let mut certs = server_certificates.iter().cloned();

    let end_entity_cert = certs.next().context("empty chain")?;

    output!(out, "Decode end entity certificate")?;

    let end_entity_cert =
        rustls::server::ParsedCertificate::try_from(&end_entity_cert).context("parse end entity certificate")?;

    output!(out, "Verify server certificate signed by trust anchor")?;

    let intermediates: Vec<_> = certs.collect();
    let now = rustls::pki_types::UnixTime::now();
    let ring_crypto_provider = rustls::crypto::ring::default_provider();

    verify_server_cert_signed_by_trust_anchor(
        &end_entity_cert,
        &root_store,
        &intermediates,
        now,
        ring_crypto_provider.signature_verification_algorithms.all,
    )
    .context("failed to verify certification chain")?;

    Ok(())
}
