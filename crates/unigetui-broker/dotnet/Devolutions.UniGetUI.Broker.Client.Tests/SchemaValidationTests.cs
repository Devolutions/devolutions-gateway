using NJsonSchema;

using Xunit;

namespace Devolutions.UniGetUI.Broker.Client.Tests;

/// <summary>
/// Cross-checks that the bundled sample documents validate against the shared JSON
/// Schemas, and that intentionally-invalid fixtures are rejected. This confirms the C#
/// tooling reads the very same schema + data files the Rust tests use.
/// </summary>
public class SchemaValidationTests
{
    [Theory]
    [MemberData(nameof(TestData.RequestSamples), MemberType = typeof(TestData))]
    public async Task Request_samples_are_schema_valid(string path)
        => await AssertValid(path, TestData.RequestSchema);

    [Theory]
    [MemberData(nameof(TestData.ResponseSamples), MemberType = typeof(TestData))]
    public async Task Response_samples_are_schema_valid(string path)
        => await AssertValid(path, TestData.ResponseSchema);

    [Theory]
    [MemberData(nameof(TestData.StatusResponseSamples), MemberType = typeof(TestData))]
    public async Task Status_response_samples_are_schema_valid(string path)
        => await AssertValid(path, TestData.StatusResponseSchema);

    [Theory]
    [MemberData(nameof(TestData.PolicySamples), MemberType = typeof(TestData))]
    public async Task Policy_samples_are_schema_valid(string path)
        => await AssertValid(path, TestData.PolicySchema);

    [Fact]
    public async Task Invalid_request_is_rejected_by_schema()
    {
        var path = Path.Combine(TestData.SamplesDir, "invalid", "requests", "missing-package-id.request.json");
        Assert.True(File.Exists(path), $"missing invalid fixture: {path}");

        var schema = await JsonSchema.FromFileAsync(TestData.RequestSchema);
        var errors = schema.Validate(await File.ReadAllTextAsync(path));

        Assert.True(errors.Count > 0, "expected the empty package id to fail schema validation");
    }

    private static async Task AssertValid(string samplePath, string schemaPath)
    {
        var schema = await JsonSchema.FromFileAsync(schemaPath);
        var errors = schema.Validate(await File.ReadAllTextAsync(samplePath));

        Assert.True(
            errors.Count == 0,
            $"{Path.GetFileName(samplePath)} failed schema validation:\n" +
            string.Join("\n", errors.Select(e => $"  {e.Kind} at {e.Path}")));
    }
}
