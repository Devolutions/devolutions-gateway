use jmux_generators::destination_url_parts;
use jmux_proto::*;
use proptest::prelude::*;

#[test]
fn parse() {
    proptest!(|(
        (scheme, host, port) in destination_url_parts()
    )| {
        let s = format!("{scheme}://{host}:{port}");
        let parsed = DestinationUrl::parse_str(&s).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let as_str = parsed.as_str();
        let reparsed = DestinationUrl::parse_str(as_str).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(parsed, reparsed);
    })
}

#[test]
fn format() {
    proptest!(|(
        (scheme, host, port) in destination_url_parts()
    )| {
        let url = DestinationUrl::new(&scheme, &host, port);
        let expected = format!("{scheme}://{host}:{port}");
        let actual = url.to_string();
        prop_assert_eq!(expected, actual);
    })
}
