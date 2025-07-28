#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use expect_test::Expect;
use expect_test::expect;

fn check(sample: &str, expected: Expect) {
    #[allow(deprecated)]
    let claims = devolutions_gateway::token::unsafe_debug::dangerous_validate_token(sample, None).unwrap();

    let devolutions_gateway::token::AccessTokenClaims::Jmux(claims) = claims else {
        panic!("unexpected token cty")
    };

    let actual = devolutions_gateway::jmux::claims_to_jmux_config(&claims);

    expected.assert_debug_eq(&actual);
}

#[test]
fn specific_ports() {
    check(
        "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpNVVgifQ.eyJkc3RfYWRkbCI6WyJodHRwczovL2xvY2FsaG9zdDo0NDMiLCJodHRwOi8vd3d3LmxvY2FsaG9zdDo4ODAwIiwiaHR0cHM6Ly93d3cubG9jYWxob3N0OjQ0MyJdLCJkc3RfaHN0IjoiaHR0cDovL2xvY2FsaG9zdDo4ODAwIiwiZXhwIjoxNzUzNjU4NDgxLCJpYXQiOjE3NTM2NTgxODEsImpldF9haWQiOiIyYzNjOGI4ZC0wZThlLTQwMGItYWVmMy1mM2U4ZjFhN2EzOTQiLCJqZXRfYXAiOiJodHRwIiwiamV0X2d3X2lkIjoiZGU0ZDMyODUtMjUzOS00NjhkLThlMmEtMTc1OWVjMDQyYTM3IiwianRpIjoiYTk3NWI4OGMtOGU5My00N2JkLThkNDQtY2QwZGI2YzViNGNmIiwibmJmIjoxNzUzNjU4MTgxfQ.g9yKXuH-A_oRlPaS6xcKddnzQZZ4XTnSFd_pzN-pPzbLAuxOpNyzkhOfSUEkday0Uh3Z2TQ2KxAnkG7zjvO6dKecv4xUamiU8gItuzhgHTzQQBqNsiu-t4rHvG1Ad83cXDzcuGMXiYHAxq4zqPrUN2atzkzXlF6eoG3mNQw8kNGrTCWWyAZgU1_Sjwuyd-MRATNdZt0cy3Awj6dMPCdGR3_oBTnLhPyqIAzfh_56bpUVlayy8u3HBFZo5Wj8uX8dbgN0izna-idvR85rWKqyBLpZUgeEctrk4UnM6Cz9kwCIxtQI5jTmi-U7UIGfggcbmyRWkoWvxr2tnBIPxSZDkA",
        expect![[r#"
            JmuxConfig {
                filtering: Any(
                    [
                        All(
                            [
                                WildcardHost(
                                    "localhost",
                                ),
                                Port(
                                    8800,
                                ),
                            ],
                        ),
                        All(
                            [
                                WildcardHost(
                                    "localhost",
                                ),
                                Port(
                                    443,
                                ),
                            ],
                        ),
                        All(
                            [
                                WildcardHost(
                                    "www.localhost",
                                ),
                                Port(
                                    8800,
                                ),
                            ],
                        ),
                        All(
                            [
                                WildcardHost(
                                    "www.localhost",
                                ),
                                Port(
                                    443,
                                ),
                            ],
                        ),
                    ],
                ),
            }
        "#]],
    );
}

#[test]
fn allow_any_port() {
    check(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpNVVgifQ.eyJkc3RfYWRkbCI6WyJodHRwOi8vd3d3LmRldm9sdXRpb25zLm5ldDowIl0sImRzdF9oc3QiOiJodHRwOi8vZGV2b2x1dGlvbnMubmV0OjAiLCJleHAiOjE3NTM2NTg0ODEsImlhdCI6MTc1MzY1ODE4MSwiamV0X2FpZCI6IjJjM2M4YjhkLTBlOGUtNDAwYi1hZWYzLWYzZThmMWE3YTM5NCIsImpldF9hcCI6Imh0dHAiLCJqZXRfZ3dfaWQiOiJkZTRkMzI4NS0yNTM5LTQ2OGQtOGUyYS0xNzU5ZWMwNDJhMzciLCJqdGkiOiJhOTc1Yjg4Yy04ZTkzLTQ3YmQtOGQ0NC1jZDBkYjZjNWI0Y2YiLCJuYmYiOjE3NTM2NTgxODF9.SihT5LKgKDKOAVsrpTQ01jC8KkrUuNbU19-rGn8YgV4",
        expect![[r#"
            JmuxConfig {
                filtering: Any(
                    [
                        WildcardHost(
                            "devolutions.net",
                        ),
                        WildcardHost(
                            "www.devolutions.net",
                        ),
                    ],
                ),
            }
        "#]],
    );
}

#[test]
fn allow_any_host() {
    check(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpNVVgifQ.eyJkc3RfaHN0IjoiaHR0cDovLyo6ODAiLCJleHAiOjE3NTM2NTg0ODEsImlhdCI6MTc1MzY1ODE4MSwiamV0X2FpZCI6IjJjM2M4YjhkLTBlOGUtNDAwYi1hZWYzLWYzZThmMWE3YTM5NCIsImpldF9hcCI6Imh0dHAiLCJqZXRfZ3dfaWQiOiJkZTRkMzI4NS0yNTM5LTQ2OGQtOGUyYS0xNzU5ZWMwNDJhMzciLCJqdGkiOiJhOTc1Yjg4Yy04ZTkzLTQ3YmQtOGQ0NC1jZDBkYjZjNWI0Y2YiLCJuYmYiOjE3NTM2NTgxODF9.JqSSKp2w2-dgUn_S3uizvWhS2RUnOvrcZm7YebTjPuc",
        expect![[r#"
            JmuxConfig {
                filtering: Any(
                    [
                        Port(
                            80,
                        ),
                    ],
                ),
            }
        "#]],
    );
}

#[test]
fn allow_any_host_and_any_port() {
    check(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IkpNVVgifQ.eyJkc3RfaHN0IjoiaHR0cDovLyo6MCIsImV4cCI6MTc1MzY1ODQ4MSwiaWF0IjoxNzUzNjU4MTgxLCJqZXRfYWlkIjoiMmMzYzhiOGQtMGU4ZS00MDBiLWFlZjMtZjNlOGYxYTdhMzk0IiwiamV0X2FwIjoiaHR0cCIsImpldF9nd19pZCI6ImRlNGQzMjg1LTI1MzktNDY4ZC04ZTJhLTE3NTllYzA0MmEzNyIsImp0aSI6ImE5NzViODhjLThlOTMtNDdiZC04ZDQ0LWNkMGRiNmM1YjRjZiIsIm5iZiI6MTc1MzY1ODE4MX0.tDgAH8uoQSUOJHYnpDoK0Ox2nbPV6alwPjIbMYAullE",
        expect![[r#"
            JmuxConfig {
                filtering: Any(
                    [
                        Allow,
                    ],
                ),
            }
        "#]],
    );
}
