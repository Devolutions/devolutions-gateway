using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.UniGetUI.Broker.Client;

/// <summary>Canonical schema URIs used in the <c>$schema</c> field of each document.</summary>
public static class SchemaUris
{
    public const string Request = "https://aka.ms/unigetui/package-request.schema.1.0.json";
    public const string Response = "https://aka.ms/unigetui/package-broker-response.schema.1.0.json";
    public const string Policy = "https://aka.ms/unigetui/package-policy.schema.1.0.json";
    public const string StatusRequest = "https://aka.ms/unigetui/package-operation-status-request.schema.1.0.json";
    public const string StatusResponse = "https://aka.ms/unigetui/package-operation-status-response.schema.1.0.json";
}

/// <summary>Shared <see cref="JsonSerializerOptions"/> for broker documents.</summary>
public static class BrokerJson
{
    /// <summary>
    /// Serialization options matching the broker wire format: PascalCase property names
    /// (via explicit <c>[JsonPropertyName]</c> attributes), PascalCase enum values, and
    /// null optionals omitted (mirroring the Rust <c>skip_serializing_if = "Option::is_none"</c>).
    /// </summary>
    public static readonly JsonSerializerOptions Options = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
    };

    public static readonly JsonSerializerOptions PrettyOptions = new(Options)
    {
        WriteIndented = true,
    };
}
