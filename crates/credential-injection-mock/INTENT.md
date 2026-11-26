This binary is the mock RDP client, RDP server and KDC that the credential-injection tests in `testsuite` run against Gateway.
It is a separate program so that `testsuite` does not depend on the RDP and Kerberos crates.
It holds the client side too, because ironrdp-agent's direct TCP connection sends no preconnection blob, and the Gateway TCP listener requires one.

## Shared libraries

The mock uses the same CredSSP library (sspi) and the same `kdc` crate as Gateway, so a bug shared by both sides passes the tests.
This is accepted: the tests check Gateway's credential injection, not whether these libraries follow the protocol.
