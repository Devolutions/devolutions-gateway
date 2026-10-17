This crate implements, on the agent side, the RFC 9421 profile of [CONTRACT.md](../../docs/agent-identity/CONTRACT.md).

## Implementation decisions

- Built on the `httpsig` crate: device keys implement its `SigningKey` trait.
- This crate contains no RFC 9421 implementation of its own (signature base construction, structured-field serialization).
- It only signs.
  Verifying signatures is the authority's job; the agent never parses signature headers.
- Every signature, REST or gRPC, is built by `httpsig` through `RequestSigner`.
- A tower layer applies it to the gRPC stream opening and prefixes gRPC paths with the base URL's path when there is one (e.g. an IIS virtual directory), because a tonic `Interceptor` does not see the request path.
  REST requests call `RequestSigner` directly, because the agent's HTTP client has no tower stack.
