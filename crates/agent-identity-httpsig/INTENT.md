This crate implements, on the agent side, the RFC 9421 profile of [CONTRACT.md](../../docs/agent-identity/CONTRACT.md).

## Implementation decisions

- Built on the `httpsig` crate: a local adapter exposes a device key through its `SigningKey` trait, so that `device-key` stays independent of the request-authentication mechanism.
- This crate owns the Agent Identity profile's inputs (covered components, parameters, tag, nonce) and the `Content-Digest` field; `httpsig` builds the signature base and serializes the `Signature-Input` and `Signature` fields, so the crate contains no RFC 9421 serializer of its own.
- It contains no verifier: verifying signatures is the authority's job, and the agent never parses signature headers.
- Every request signature, for a REST request or a gRPC stream opening, is built by `httpsig` through `RequestSigner`; the channel proof is not a request signature.
- A tower layer applies it to the gRPC stream opening and prefixes gRPC paths with the base URL's path when there is one (e.g. an IIS virtual directory), because a tonic `Interceptor` does not see the request path.
  REST requests call `RequestSigner` directly, because the agent's HTTP client has no tower stack.
