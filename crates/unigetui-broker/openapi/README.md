# UniGetUI Package Broker OpenAPI libraries

The broker's HTTP API (served over a Windows named pipe) is described by
`unigetui-broker-api.yaml`, generated from the Rust types via `aide` + `schemars`.
The same document carries the `PolicyDocument` schema so the generated C# client
also gets strongly-typed policy models.

To regenerate the spec and clients, run `.\openapi\generate_all.ps1`.

For more info, refer to the Gateway [OpenAPI guide](../../../devolutions-gateway/openapi/README.md)
