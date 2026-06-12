# Devolutions.UniGetUI.Broker.Client

Hand-written C# client and DTOs for the Devolutions Agent UniGetUI package broker.

This is a deliberate middle-ground: rather than generating the client from the
OpenAPI document, the DTOs and the named-pipe HTTP client are written by hand
(idiomatic, with strongly-typed enums), and **validated against the exact same JSON
Schemas and sample documents the Rust crate uses** — no copied fixtures, no drift.

## Layout

- `Devolutions.UniGetUI.Broker.Client/` — the library:
  - DTOs for the request, response, status, and policy documents (PascalCase wire format).
  - Enums (`Operation`, `Decision`, `OperationStatus`, …) that serialize to the exact
    wire values, so policy/status comparisons are type-checked rather than stringly-typed.
  - `BrokerClient` — HTTP/1.1 over a Windows named pipe (evaluate / execute / poll status).
- `Devolutions.UniGetUI.Broker.Client.Tests/` — xunit parity tests that load
  `../../schema/*.json` and `../../assets/samples/**` directly and assert:
  - every sample round-trips through the DTOs under strict unmapped-member handling
    (so a missing DTO field fails the test — the mirror of Rust's `deny_unknown_fields`);
  - re-serialized output validates against the JSON Schema (via `NJsonSchema`);
  - intentionally-invalid fixtures are rejected.

## Build & test

```powershell
dotnet test crates/unigetui-broker/dotnet/Devolutions.UniGetUI.Broker.Client.slnx
```

The OpenAPI document (`../openapi/unigetui-broker-api.yaml`) is kept as an API reference
but is not used to generate this client.
