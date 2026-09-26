# Agent RFC 9421 signing

This crate implements, on the agent side, the RFC 9421 profile defined in [contract.intent.md](../../docs/agent-identity/contract.intent.md).

## Implementation decisions

- Built on the `httpsig` crate: device keys implement its `SigningKey` trait.
- This crate contains no RFC 9421 implementation of its own (signature base construction, structured-field serialization).
- It only signs.
  Verifying signatures is the authority's job; the agent never parses signature headers.
- It provides a tower layer that:
  - signs outgoing requests: REST operations and the gRPC stream opening;
  - prefixes gRPC paths with the base URL's path when there is one (e.g. an IIS virtual directory).
- Signing lives in a tower layer because a tonic `Interceptor` does not see the request path.
