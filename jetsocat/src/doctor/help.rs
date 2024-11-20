use core::fmt;

use crate::doctor::DiagnosticCtx;

pub(crate) fn failed_to_connect_to_server(ctx: &mut DiagnosticCtx, hostname: &str) {
    ctx.attach_help(format!(
        "Connection could not be established with the server for the hostname '{hostname}'.
Please verify that:
- '{hostname}' is the correct hostname.
- The server is up and running.
- You correctly configured DNS records for '{hostname}'."
    ));
}

pub(crate) fn cert_invalid_hostname(ctx: &mut DiagnosticCtx, hostname: &str) {
    ctx.attach_help(format!(
        "The certificate is not valid for the subject name '{hostname}' (domain/DNS name).
To resolve this issue, you can:
- Update your DNS records to use a domain that is matched by the certificate, and use this name instead.
- Generate and install a new certificate that includes '{hostname}'.
Please note that asterisks '*' found in domain name fragments of wildcard certificates only match one level of subdomains.
For example: 'a.b.c' is matched by '*.b.c', but is not matched by '*.c' (the wildcard does not cover multiple levels)."
    ));

    ctx.attach_link(
        "Public key certificate",
        "https://en.wikipedia.org/wiki/Public_key_certificate",
        "more information on certificate structure, types such as Wildcard certificates, certificate authorities, and so on",
    );
}

pub(crate) fn cert_unknown_issuer(ctx: &mut DiagnosticCtx) {
    ctx.attach_help( "The issuer is not trusted by the trust provider (issuer is unknown).
Please ensure the following:
- The server is providing intermediate certificates along with the leaf certificate.
- If you are using a custom root CA managed by you or your organization, verify that the root certificate is installed and trusted on your system.
- For self-signed certificates, either trust the certificate on your system or obtain one signed by a recognized certificate authority.
If none of the above applies, you could be facing a Man-in-the-Middle (MITM) attack.".to_owned());

    ctx.attach_link(
        "Man-in-the-middle attack",
        "https://en.wikipedia.org/wiki/Man-in-the-middle_attack",
        "more information on MITM attacks",
    );
}

pub(crate) fn cert_is_expired(ctx: &mut DiagnosticCtx) {
    ctx.attach_help(
        "The certificate has expired.
To resolve this, you should:
- Renew the certificate through your certification authority.
- Install the new certificate on your server.
If you believe the certificate should still be valid, verify that your system clock is set to the correct time."
            .to_owned(),
    );
}

pub(crate) fn cert_is_not_yet_valid(ctx: &mut DiagnosticCtx) {
    ctx.attach_help(
        "The certificate is not yet valid.
Make sure your clock is set to the correct time."
            .to_owned(),
    )
}

pub(crate) fn cert_invalid_purpose(ctx: &mut DiagnosticCtx) {
    ctx.attach_help(
        "The certificate is not valid for server authentication.
You need to generate a separate certificate valid for server authentication."
            .to_owned(),
    )
}

pub(crate) fn x509_io_link<C>(ctx: &mut DiagnosticCtx, certs: C)
where
    C: Iterator,
    C::Item: AsRef<[u8]>,
{
    let mut href = String::new();
    write_x509_io_link(&mut href, certs).expect("writing to a String will typially not cause any error (unless OOM)");

    ctx.attach_link(
        "x509.io Certificates Viewer",
        href,
        "view the extracted certification chain using x509.io certificates viewer in the browser",
    );

    fn write_x509_io_link<C>(mut out: impl fmt::Write, certs: C) -> fmt::Result
    where
        C: Iterator,
        C::Item: AsRef<[u8]>,
    {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;

        write!(out, "https://x509.io/?cert=")?;

        let mut is_first = true;

        for cert_der in certs {
            if is_first {
                is_first = false;
            } else {
                write!(out, ",")?;
            }

            let cert_base64 = URL_SAFE_NO_PAD.encode(cert_der.as_ref());

            write!(out, "{cert_base64}")?;
        }

        Ok(())
    }
}
