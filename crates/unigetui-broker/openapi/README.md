# UniGetUI Package Broker OpenAPI

`unigetui-broker-api.yaml` is the OpenAPI 3.1 description of the broker's HTTP API
(served over a Windows named pipe). It is generated from the Rust types via
`aide` + `schemars` and also carries the `PolicyDocument` schema as a component.

Regenerate it with the crate-local binary (writes this file directly):

```powershell
cargo run -p unigetui-broker --bin generate-broker-openapi
```

Alternatively, use the workspace OpenAPI tool:

```powershell
../../../tools/generate-openapi/generate.ps1
```

(or `cargo run -p generate-openapi -- unigetui-broker`).

The document is kept as an API reference / schema artifact. The C# client is
hand-written in `../dotnet/` and validated against the same JSON Schemas
(`../schema/`) and sample documents (`../assets/samples/`) used by the Rust tests,
rather than generated from this spec.
