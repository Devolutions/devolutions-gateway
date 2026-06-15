using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

using NJsonSchema;

using NSwag;

using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Devolutions.UniGetUI.Broker.Client.Tests;

/// <summary>
/// Resolves the shared schema artifacts and sample files that the Rust crate uses, so the
/// C# client is validated against the exact same fixtures (no copies, no drift). The
/// request/response wire schemas are sourced from the OpenAPI spec
/// (`openapi/unigetui-broker-api.yaml`); the policy schema keeps its standalone JSON Schema
/// file (`schema/unigetui.package-policy.schema.json`), the canonical artifact for
/// admin-authored policy files.
/// </summary>
public static class TestData
{
    /// <summary>Absolute path to the crate root (`crates/unigetui-broker`).</summary>
    public static string CrateRoot { get; } = ResolveCrateRoot();

    public static string SamplesDir => Path.Combine(CrateRoot, "assets", "samples");

    /// <summary>The OpenAPI specification: the source of truth for the request/response wire schemas.</summary>
    public static string OpenApiSpec => Path.Combine(CrateRoot, "openapi", "unigetui-broker-api.yaml");

    /// <summary>The standalone JSON Schema for admin-authored policy documents.</summary>
    public static string PolicySchema => Path.Combine(CrateRoot, "schema", "unigetui.package-policy.schema.json");

    private static readonly SemaphoreSlim s_docLock = new(1, 1);
    private static OpenApiDocument? s_doc;

    /// <summary>
    /// Resolves a component schema by name from the OpenAPI spec, with all internal
    /// `$ref`s already resolved so it can be used directly for validation.
    /// </summary>
    public static async Task<JsonSchema> SchemaAsync(string componentName)
    {
        var doc = await LoadOpenApiAsync();
        if (!doc.Components.Schemas.TryGetValue(componentName, out var schema))
        {
            throw new InvalidOperationException(
                $"component schema '{componentName}' not found in {Path.GetFileName(OpenApiSpec)}");
        }

        return schema;
    }

    private static async Task<OpenApiDocument> LoadOpenApiAsync()
    {
        await s_docLock.WaitAsync();
        try
        {
            return s_doc ??= await ParseOpenApiAsync();
        }
        finally
        {
            s_docLock.Release();
        }
    }

    /// <summary>
    /// Parses the OpenAPI spec into an <see cref="OpenApiDocument"/>. The spec is produced
    /// by `aide` with intentionally minimal path items (no `responses`), which the strict
    /// OpenAPI reader rejects. We only need the component schemas, so the `paths` section is
    /// replaced with an empty object before parsing while the rest (including OpenAPI 3.x
    /// `nullable` semantics and `$ref` resolution) is handled by the reader.
    /// </summary>
    private static async Task<OpenApiDocument> ParseOpenApiAsync()
    {
        var yamlText = await File.ReadAllTextAsync(OpenApiSpec);

        var stream = new YamlStream();
        stream.Load(new StringReader(yamlText));
        var root = (JsonObject)YamlToJson(stream.Documents[0].RootNode)!;
        root["paths"] = new JsonObject();

        return await OpenApiDocument.FromJsonAsync(root.ToJsonString());
    }

    private static JsonNode? YamlToJson(YamlNode node)
    {
        switch (node)
        {
            case YamlMappingNode map:
                var obj = new JsonObject();
                foreach (var (key, value) in map.Children)
                {
                    obj[((YamlScalarNode)key).Value!] = YamlToJson(value);
                }

                return obj;

            case YamlSequenceNode seq:
                var arr = new JsonArray();
                foreach (var item in seq.Children)
                {
                    arr.Add(YamlToJson(item));
                }

                return arr;

            case YamlScalarNode scalar:
                return ScalarToJson(scalar);

            default:
                return null;
        }
    }

    private static JsonNode? ScalarToJson(YamlScalarNode scalar)
    {
        var value = scalar.Value;
        if (value is null)
        {
            return null;
        }

        // Quoted scalars are always strings, never interpreted as numbers/booleans.
        if (scalar.Style is ScalarStyle.SingleQuoted or ScalarStyle.DoubleQuoted)
        {
            return JsonValue.Create(value);
        }

        return value switch
        {
            "" or "null" or "~" => null,
            "true" or "True" => JsonValue.Create(true),
            "false" or "False" => JsonValue.Create(false),
            _ when long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var l) => JsonValue.Create(l),
            _ when double.TryParse(value, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) => JsonValue.Create(d),
            _ => JsonValue.Create(value),
        };
    }

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
