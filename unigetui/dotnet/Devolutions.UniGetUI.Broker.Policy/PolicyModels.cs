using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

using YamlDotNet.Core;
using YamlDotNet.RepresentationModel;

namespace Devolutions.UniGetUI.Broker.Policy;

public static class SchemaUris
{
    public const string Policy = "https://aka.ms/unigetui/package-policy.schema.1.0.json";
}

/// <summary>A policy document governing which package operations are allowed or denied.</summary>
public sealed class PolicyDocument
{
    [JsonPropertyName("$schema")]
    public string Schema { get; set; } = SchemaUris.Policy;

    [JsonPropertyName("PolicyVersion")]
    public string PolicyVersion { get; set; } = "1.0.0";

    [JsonPropertyName("PolicyType")]
    public string PolicyType { get; set; } = "PackageBrokerPolicy";

    [JsonPropertyName("Metadata")]
    public PolicyMetadata Metadata { get; set; } = new();

    [JsonPropertyName("Enforcement")]
    public PolicyEnforcement Enforcement { get; set; } = new();

    [JsonPropertyName("Rules")]
    public List<PolicyRule> Rules { get; set; } = [];

    public static PolicyDocument Create(string id, string publisher, Decision defaultDecision = Decision.Deny)
    {
        return new PolicyDocument
        {
            Metadata = new PolicyMetadata
            {
                Id = id,
                Publisher = publisher,
                Revision = 1,
                PublishedAt = DateTimeOffset.UtcNow,
            },
            Enforcement = new PolicyEnforcement
            {
                DefaultDecision = defaultDecision,
                RulePrecedence = RulePrecedence.PriorityThenDeny,
            },
        };
    }

    public static PolicyDocument ParseJson(string json)
    {
        return JsonSerializer.Deserialize<PolicyDocument>(json, PolicyJson.StrictOptions)
            ?? throw new JsonException("policy document was null");
    }

    public static PolicyDocument ParseYaml(string yaml)
    {
        var stream = new YamlStream();
        stream.Load(new StringReader(yaml));
        if (stream.Documents.Count == 0)
        {
            throw new JsonException("policy YAML document was empty");
        }

        var json = YamlToJson(stream.Documents[0].RootNode)?.ToJsonString()
            ?? throw new JsonException("policy YAML document was empty");
        return ParseJson(json);
    }

    public string ToJson() => JsonSerializer.Serialize(this, PolicyJson.Options);

    private static JsonNode? YamlToJson(YamlNode node)
    {
        switch (node)
        {
            case YamlMappingNode map:
                var obj = new JsonObject();
                foreach (var (key, value) in map.Children)
                {
                    if (key is not YamlScalarNode scalarKey || scalarKey.Value is null)
                    {
                        throw new JsonException("policy YAML mapping keys must be scalar strings");
                    }

                    obj[scalarKey.Value] = YamlToJson(value);
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
}

public sealed class PolicyMetadata
{
    [JsonPropertyName("Id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("Publisher")]
    public string Publisher { get; set; } = "";

    [JsonPropertyName("Revision")]
    public uint Revision { get; set; }

    [JsonPropertyName("PublishedAt")]
    public DateTimeOffset PublishedAt { get; set; }

    [JsonPropertyName("ValidFrom")]
    public DateTimeOffset? ValidFrom { get; set; }

    [JsonPropertyName("ValidUntil")]
    public DateTimeOffset? ValidUntil { get; set; }

    [JsonPropertyName("Description")]
    public string? Description { get; set; }

    [JsonPropertyName("SupportUrl")]
    public string? SupportUrl { get; set; }
}

public sealed class PolicyEnforcement
{
    [JsonPropertyName("DefaultDecision")]
    public Decision DefaultDecision { get; set; }

    [JsonPropertyName("RulePrecedence")]
    public RulePrecedence RulePrecedence { get; set; }

    [JsonPropertyName("AuditMode")]
    public bool? AuditMode { get; set; }
}

public sealed class PolicyRule
{
    [JsonPropertyName("Id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("Enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("Priority")]
    public uint Priority { get; set; }

    [JsonPropertyName("Decision")]
    public Decision Decision { get; set; }

    [JsonPropertyName("Reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("Match")]
    public PolicyMatch Match { get; set; } = new();

    [JsonPropertyName("Constraints")]
    public PolicyConstraints? Constraints { get; set; }
}

public sealed class PolicyMatch
{
    [JsonPropertyName("Operations")]
    public List<Operation> Operations { get; set; } = [];

    [JsonPropertyName("Managers")]
    public List<ManagerName> Managers { get; set; } = [];

    [JsonPropertyName("Sources")]
    public List<string> Sources { get; set; } = [];

    [JsonPropertyName("PackageIdentifiers")]
    public List<string> PackageIdentifiers { get; set; } = [];

    [JsonPropertyName("PackageNames")]
    public List<string> PackageNames { get; set; } = [];

    [JsonPropertyName("Versions")]
    public List<string> Versions { get; set; } = [];

    [JsonPropertyName("VersionRange")]
    public VersionRange? VersionRange { get; set; }

    [JsonPropertyName("Scopes")]
    public List<Scope> Scopes { get; set; } = [];

    [JsonPropertyName("Architectures")]
    public List<Architecture> Architectures { get; set; } = [];

    [JsonPropertyName("Elevation")]
    public List<Elevation> Elevation { get; set; } = [];

    [JsonPropertyName("Interactive")]
    public List<bool> Interactive { get; set; } = [];

    [JsonPropertyName("SkipHashCheck")]
    public List<bool> SkipHashCheck { get; set; } = [];

    [JsonPropertyName("PreRelease")]
    public List<bool> PreRelease { get; set; } = [];

    [JsonPropertyName("HasCustomParameters")]
    public List<bool> HasCustomParameters { get; set; } = [];

    [JsonPropertyName("HasCustomInstallLocation")]
    public List<bool> HasCustomInstallLocation { get; set; } = [];

    [JsonPropertyName("HasPrePostCommands")]
    public List<bool> HasPrePostCommands { get; set; } = [];

    [JsonPropertyName("HasKillBeforeOperation")]
    public List<bool> HasKillBeforeOperation { get; set; } = [];

    [JsonPropertyName("HasUninstallPrevious")]
    public List<bool> HasUninstallPrevious { get; set; } = [];
}

public sealed class VersionRange
{
    [JsonPropertyName("MinVersion")]
    public string? MinVersion { get; set; }

    [JsonPropertyName("MaxVersion")]
    public string? MaxVersion { get; set; }

    [JsonPropertyName("IncludePrerelease")]
    public bool IncludePrerelease { get; set; }
}

public sealed class PolicyConstraints
{
    [JsonPropertyName("AllowInteractive")]
    public bool AllowInteractive { get; set; } = true;

    [JsonPropertyName("AllowSkipHashCheck")]
    public bool AllowSkipHashCheck { get; set; } = true;

    [JsonPropertyName("AllowPreRelease")]
    public bool AllowPreRelease { get; set; } = true;

    [JsonPropertyName("AllowCustomInstallLocation")]
    public bool AllowCustomInstallLocation { get; set; } = true;

    [JsonPropertyName("AllowedInstallLocationPatterns")]
    public List<string> AllowedInstallLocationPatterns { get; set; } = [];

    [JsonPropertyName("AllowCustomParameters")]
    public bool AllowCustomParameters { get; set; } = true;

    [JsonPropertyName("AllowedCustomParameters")]
    public List<string> AllowedCustomParameters { get; set; } = [];

    [JsonPropertyName("AllowedCustomParameterPatterns")]
    public List<string> AllowedCustomParameterPatterns { get; set; } = [];

    [JsonPropertyName("DeniedCustomParameters")]
    public List<string> DeniedCustomParameters { get; set; } = [];

    [JsonPropertyName("AllowPrePostCommands")]
    public bool AllowPrePostCommands { get; set; } = true;

    [JsonPropertyName("AllowKillBeforeOperation")]
    public bool AllowKillBeforeOperation { get; set; } = true;

    [JsonPropertyName("AllowUninstallPrevious")]
    public bool AllowUninstallPrevious { get; set; } = true;

    [JsonPropertyName("AllowUpgrade")]
    public bool AllowUpgrade { get; set; } = true;
}
