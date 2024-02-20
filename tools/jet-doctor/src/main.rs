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
        writeln!( $dst, $($arg)* ).context("write output")?
    };
}

/// Sanity checks for Devolutions Gateway and Jetsocat.
#[derive(OnlyArgs)]
struct Args {
    check_cert: Option<PathBuf>,
    subject_name: Option<String>,
}

fn main() -> ExitCode {
    let args: Args = onlyargs::parse().expect("CLI arguments");

    println!("{} {}", build::PROJECT_NAME, build::PKG_VERSION);
    println!("> Tag: {}", build::TAG);
    println!("> Commit hash: {}", build::SHORT_COMMIT);
    println!("> Commit date: {}", build::COMMIT_DATE);
    println!("> Build date: {}", build::BUILD_TIME);

    let mut success = true;

    success &= diagnostic!(ssl_probe());
    success &= diagnostic!(check_root_store());

    if let Some(cert_path) = &args.check_cert {
        success &= diagnostic!(check_cert(&cert_path, args.subject_name.as_deref()));
    }

    if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn ssl_probe(mut out: impl fmt::Write) -> anyhow::Result<()> {
    let result = openssl_probe::probe();

    output!(out, "cert_file = {:?}", result.cert_file);
    output!(out, "cert_dir = {:?}", result.cert_dir);

    Ok(())
}

fn check_root_store(mut out: impl fmt::Write) -> anyhow::Result<()> {
    let mut root_store = rustls::RootCertStore::empty();

    for cert in rustls_native_certs::load_native_certs().context("failed to load native certificates")? {
        let cert = rustls::Certificate(cert.0);

        if let Err(e) = root_store.add(&cert) {
            output!(out, "Invalid root certificate: {e}");

            let pem = pem::Pem::new("CERTIFICATE", cert.0);
            output!(out, "{pem}");
        }
    }

    Ok(())
}

fn check_cert(mut out: impl fmt::Write, cert_path: &Path, subject_name: Option<&str>) -> anyhow::Result<()> {
    output!(out, "Read file at {}", cert_path.display());

    let cert_val = std::fs::read(cert_path).context("read file from disk")?;

    let cert_der = match pem::parse(&cert_val) {
        Ok(cert_pem) => {
            output!(out, "Detected PEM format");

            let pem_tag = cert_pem.tag();

            if pem_tag != "CERTIFICATE" {
                output!(out, "WARNING: unexpected PEM tag: {pem_tag}");
            }

            cert_pem.into_contents()
        }
        Err(pem::PemError::MalformedFraming | pem::PemError::NotUtf8(_)) => {
            output!(out, "Read as raw DER");
            cert_val
        }
        Err(e) => {
            return Err(anyhow::Error::new(e).context("read file as PEM"));
        }
    };

    output!(out, "Decode end entity certificate");

    let end_entity_cert =
        webpki::EndEntityCert::try_from(cert_der.as_slice()).context("decode end entity certificate")?;

    if let Some(subject_name) = subject_name {
        output!(out, "Verify validity for DNS name");

        let subject_name = webpki::SubjectNameRef::try_from_ascii_str(subject_name)
            .ok()
            .context("invalid subject name")?;

        end_entity_cert
            .verify_is_valid_for_subject_name(subject_name)
            .context("verify DNS name")?;
    }

    Ok(())
}
