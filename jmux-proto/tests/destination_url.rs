mod common;

use jmux_proto::*;
use proptest::prelude::*;

#[test]
fn parse() {
    proptest!(|(
        scheme in ".{1,5}",
        host in ".{1,10}",
        port in any::<u16>(),
    )| {
        let s = format!("{}://{}:{}", scheme, host, port);
        let parsed = DestinationUrl::parse_str(&s).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let as_str = parsed.as_str();
        let reparsed = DestinationUrl::parse_str(&as_str).map_err(|e| TestCaseError::fail(e.to_string()))?;
        prop_assert_eq!(parsed, reparsed);
    })
}
