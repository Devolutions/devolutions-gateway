using System.Text.Json;

using Xunit;

namespace Devolutions.UniGetUI.Broker.Client.Tests;

/// <summary>
/// Sync guard for the meta-endpoint DTOs (health, capabilities, error). These endpoints are
/// served from generated values rather than sample files, so instead of round-tripping a
/// fixture we construct a representative DTO, serialize it with the wire options, and assert
/// the output validates against the matching OpenAPI component schema. If the Rust models add
/// a required field, the regenerated schema gains a `required` entry and the C# DTO (which no
/// longer emits the full shape) fails validation here — flagging the drift.
/// </summary>
public class MetaModelTests
{
    [Fact]
    public async Task HealthResponse_serializes_to_schema_valid_output()
    {
        var dto = new HealthResponse
        {
            Status = HealthStatus.Ready,
            ProtocolVersion = "1.0",
            ElevatedSimulation = false,
            PolicyId = "corp-policy",
            Endpoints =
            [
                "GET /v1/health",
                "GET /v1/capabilities",
                "POST /v1/package-operations/evaluate",
                "POST /v1/package-operations/execute",
                "POST /v1/package-operations/status",
            ],
        };

        await AssertSerializesValid(dto, "HealthResponse");
    }

    [Fact]
    public async Task CapabilitiesResponse_serializes_to_schema_valid_output()
    {
        var dto = new CapabilitiesResponse
        {
            ProtocolVersion = "1.0",
            Transports = [Transport.HttpNamedPipe],
            RequestMediaTypes = ["application/vnd.unigetui.package-request+json; version=1.0", "application/json"],
            ResponseMediaTypes = ["application/vnd.unigetui.package-broker-response+json; version=1.0"],
            SupportedManagers = [ManagerName.Winget, ManagerName.PowerShell, ManagerName.PowerShell7],
            SupportedOperations = [Operation.Install, Operation.Update, Operation.Uninstall],
            MaxRequestBodyBytes = 262144,
            PipeName = "UniGetUI.PackageBroker.v1",
        };

        await AssertSerializesValid(dto, "CapabilitiesResponse");
    }

    [Fact]
    public async Task ErrorResponse_serializes_to_schema_valid_output()
    {
        var full = new ErrorResponse
        {
            Error = "broker paused",
            Reason = "policy file is unavailable or corrupted; waiting for a valid policy",
            AuditId = "audit-1234",
        };
        await AssertSerializesValid(full, "ErrorResponse");

        // Optional fields omitted when null (mirrors the Rust skip_serializing_if).
        var minimal = new ErrorResponse { Error = "request body is required" };
        await AssertSerializesValid(minimal, "ErrorResponse");
    }

    private static async Task AssertSerializesValid<T>(T dto, string componentName)
    {
        var schema = await TestData.SchemaAsync(componentName);
        var json = JsonSerializer.Serialize(dto, BrokerJson.Options);

        // Output must satisfy the schema (catches missing required fields / type drift).
        var errors = schema.Validate(json);
        Assert.True(
            errors.Count == 0,
            $"Serialized {typeof(T).Name} failed {componentName} schema validation:\n" +
            string.Join("\n", errors.Select(e => $"  {e.Kind} at {e.Path}")));

        // Round-trip back through the DTO with strict mapping (catches schema fields the DTO drops).
        var reparsed = JsonSerializer.Deserialize<T>(json, TestData.Strict);
        Assert.NotNull(reparsed);
    }
}
