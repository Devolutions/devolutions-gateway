//! What a role reports to the test, one JSON object per line on standard output.

use serde::Serialize;

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "kebab-case")]
pub(crate) enum Event<'a> {
    Listening { port: u16 },
    Accepted,
    Cookie { cookie: &'a str },
    CredsspFinished { account: &'a str },
    KdcRequest { request: ObservedKdcReq },
    KdcExchangeServed,
    ConnectionRequestSent,
    TlsConnected,
    KdcProxyRequest { request: ObservedKdcReq },
    KdcProxyReply { reply: ObservedKdcReply },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub(crate) enum ObservedKdcReq {
    As { cname: String, realm: String },
    Tgs { sname: Vec<String>, realm: String },
    Other,
}

#[derive(Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ObservedKdcReply {
    AsRep,
    TgsRep,
    KrbError,
    Other,
}

#[expect(clippy::print_stdout, reason = "standard output is how the test reads events")]
pub(crate) fn emit(event: &Event<'_>) {
    let line = serde_json::to_string(event).expect("events always serialize");
    println!("{line}");
}

#[expect(
    clippy::print_stderr,
    reason = "the test shows standard error when an assertion fails"
)]
pub(crate) fn report_error(context: &str, error: &anyhow::Error) {
    eprintln!("{context}: {error:#}");
}
