using System.Text.Json;

using NJsonSchema;

using Xunit;

namespace Devolutions.UniGetUI.Broker.Client.Tests;

/// <summary>
/// Parity tests: the hand-written C# DTOs must consume the exact sample documents the
/// Rust crate uses, and re-serialize to output that still validates against the same
/// schemas. Request/response DTOs validate against the OpenAPI component schemas; policy
/// DTOs validate against the standalone policy JSON Schema. Uses <see cref="TestData.Strict"/>
/// so a sample field missing from a DTO fails the test (DTO completeness), mirroring the
/// Rust `deny_unknown_fields` contract.
/// </summary>
public class DtoRoundTripTests
{
    [Theory]
    [MemberData(nameof(TestData.RequestSamples), MemberType = typeof(TestData))]
    public async Task PackageRequest_round_trips_and_validates(string path)
        => await AssertRoundTrip<PackageRequest>(path, await TestData.SchemaAsync("PackageRequest"));

    [Theory]
    [MemberData(nameof(TestData.ResponseSamples), MemberType = typeof(TestData))]
    public async Task BrokerResponse_round_trips_and_validates(string path)
        => await AssertRoundTrip<BrokerResponse>(path, await TestData.SchemaAsync("BrokerResponse"));

    [Theory]
    [MemberData(nameof(TestData.StatusRequestSamples), MemberType = typeof(TestData))]
    public async Task StatusRequest_round_trips_and_validates(string path)
        => await AssertRoundTrip<StatusRequest>(path, await TestData.SchemaAsync("StatusRequest"));

    [Theory]
    [MemberData(nameof(TestData.StatusResponseSamples), MemberType = typeof(TestData))]
    public async Task StatusResponse_round_trips_and_validates(string path)
        => await AssertRoundTrip<StatusResponse>(path, await TestData.SchemaAsync("StatusResponse"));

    [Theory]
    [MemberData(nameof(TestData.PolicySamples), MemberType = typeof(TestData))]
    public async Task PolicyDocument_round_trips_and_validates(string path)
        => await AssertRoundTrip<PolicyDocument>(path, await JsonSchema.FromFileAsync(TestData.PolicySchema));

    private static async Task AssertRoundTrip<T>(string samplePath, JsonSchema schema)
    {
        var original = await File.ReadAllTextAsync(samplePath);

        // 1. Deserialize the canonical sample into the DTO (strict: every field must map).
        var dto = JsonSerializer.Deserialize<T>(original, TestData.Strict);
        Assert.NotNull(dto);

        // 2. Re-serialize and validate the output against the same schema.
        var reserialized = JsonSerializer.Serialize(dto, BrokerJson.Options);
        var errors = schema.Validate(reserialized);

        Assert.True(
            errors.Count == 0,
            $"Re-serialized {typeof(T).Name} from {Path.GetFileName(samplePath)} failed schema validation:\n" +
            string.Join("\n", errors.Select(e => $"  {e.Kind} at {e.Path}")));
    }
}
