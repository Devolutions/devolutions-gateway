using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.UniGetUI.Broker.Client.Tests;

/// <summary>
/// Resolves the shared schema and sample files that the Rust crate uses, so the C#
/// client is validated against the exact same fixtures (no copies, no drift).
/// </summary>
public static class TestData
{
    /// <summary>Absolute path to the crate root (`crates/unigetui-broker`).</summary>
    public static string CrateRoot { get; } = ResolveCrateRoot();

    public static string SchemaDir => Path.Combine(CrateRoot, "schema");
    public static string SamplesDir => Path.Combine(CrateRoot, "assets", "samples");

    public static string RequestSchema => Path.Combine(SchemaDir, "unigetui.package-request.schema.json");
    public static string ResponseSchema => Path.Combine(SchemaDir, "unigetui.package-broker-response.schema.json");
    public static string PolicySchema => Path.Combine(SchemaDir, "unigetui.package-policy.schema.json");
    public static string StatusRequestSchema => Path.Combine(SchemaDir, "unigetui.package-operation-status-request.schema.json");
    public static string StatusResponseSchema => Path.Combine(SchemaDir, "unigetui.package-operation-status-response.schema.json");

    /// <summary>
    /// Strict options: deserialization fails if a sample contains a field the DTO does
    /// not declare, ensuring the C# models cover the full wire shape.
    /// </summary>
    public static readonly JsonSerializerOptions Strict = new(BrokerJson.Options)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    /// <summary>JSON files under `assets/samples/requests` that are package requests (not status).</summary>
    public static IEnumerable<object[]> RequestSamples() =>
        JsonFiles(Path.Combine(SamplesDir, "requests"))
            .Where(f => !Path.GetFileName(f).StartsWith("status-", StringComparison.Ordinal))
            .Select(f => new object[] { f });

    public static IEnumerable<object[]> StatusRequestSamples() =>
        JsonFiles(Path.Combine(SamplesDir, "requests"))
            .Where(f => Path.GetFileName(f).StartsWith("status-", StringComparison.Ordinal))
            .Select(f => new object[] { f });

    public static IEnumerable<object[]> ResponseSamples() =>
        JsonFiles(Path.Combine(SamplesDir, "responses"))
            .Where(f => !Path.GetFileName(f).StartsWith("status-", StringComparison.Ordinal))
            .Select(f => new object[] { f });

    public static IEnumerable<object[]> StatusResponseSamples() =>
        JsonFiles(Path.Combine(SamplesDir, "responses"))
            .Where(f => Path.GetFileName(f).StartsWith("status-", StringComparison.Ordinal))
            .Select(f => new object[] { f });

    /// <summary>JSON policy samples (top-level `assets/samples/*.policy.json`).</summary>
    public static IEnumerable<object[]> PolicySamples() =>
        Directory.GetFiles(SamplesDir, "*.policy.json")
            .Select(f => new object[] { f });

    private static IEnumerable<string> JsonFiles(string dir) =>
        Directory.Exists(dir) ? Directory.GetFiles(dir, "*.json") : [];

    private static string ResolveCrateRoot([CallerFilePath] string thisFile = "")
    {
        // thisFile = <crate>/dotnet/Devolutions.UniGetUI.Broker.Client.Tests/TestData.cs
        var testsDir = Path.GetDirectoryName(thisFile)!;
        return Path.GetFullPath(Path.Combine(testsDir, "..", ".."));
    }
}
