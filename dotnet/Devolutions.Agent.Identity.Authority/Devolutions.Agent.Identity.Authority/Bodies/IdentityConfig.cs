using System.Buffers;
using System.Text;
using System.Text.Json;

using Devolutions.Agent.Channel.V1;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The config that the authority holds for an identity, which the agent receives in the <c>enroll</c> and
/// <c>check-in</c> responses and in <c>ConfigUpdate</c> messages.
/// </summary>
/// <remarks>
/// Only <see cref="Create"/> creates instances,
/// so an instance always serializes to a config that CONTRACT.agent-identity.md §5.2 accepts.
/// The agent replaces its stored config only with a higher <see cref="Revision"/>,
/// so the host creates the config with a higher revision whenever the identity's config changes.
/// </remarks>
public sealed class IdentityConfig
{
    private const string VersionMember = "version";
    private const string RevisionMember = "revision";
    private const string AgentChannelUrlMember = "agent_channel_url";

    // The schema of the config; the agent treats a config of another version as a transient failure.
    private const int SchemaVersion = 1;

    // CONTRACT.agent-identity.md §7.1: neither side of the agent channel sends an envelope larger than 64 KiB.
    private const int MaxEnvelopeBytes = 64 * 1024;

    private readonly byte[] _utf8Json;

    private IdentityConfig(ulong revision, string? agentChannelUrl, byte[] utf8Json)
    {
        Revision = revision;
        AgentChannelUrl = agentChannelUrl;
        _utf8Json = utf8Json;
    }

    /// <summary>
    /// The revision of the config, which strictly increases for an identity whenever its config changes.
    /// </summary>
    public ulong Revision { get; }

    /// <summary>
    /// The base URL of the agent channel, without trailing slashes, or null when the authority does not offer the
    /// channel to the identity.
    /// </summary>
    public string? AgentChannelUrl { get; }

    /// <summary>
    /// The UTF-8 JSON object that <see cref="ToUtf8Json"/> copies.
    /// </summary>
    internal ReadOnlySpan<byte> Utf8Json => _utf8Json;

    /// <summary>
    /// Creates a config with schema version 1.
    /// </summary>
    /// <remarks>
    /// The agent channel URL is written in normalized absolute form without trailing slashes,
    /// since the agent appends the path of the channel service to it.
    /// Each product-specific field has a snake_case name:
    /// lowercase ASCII words of letters and digits joined by single underscores, the first starting with a letter.
    /// No two fields have the same name, and none is named <c>version</c>, <c>revision</c> or
    /// <c>agent_channel_url</c>.
    /// Each value is any JSON value but <c>null</c>,
    /// since an absent field is omitted rather than written as <c>null</c>.
    /// The members of every object inside a value follow the same rules:
    /// each has a snake_case name, which no other member of its object has, and a value other than <c>null</c>.
    /// An array element is no member, so it may be <c>null</c>.
    /// CONTRACT.agent-identity.md §7.1 limits each agent channel message to 65,536 bytes of protobuf,
    /// so the config must fit one <c>ConfigUpdate</c> message.
    /// That message is measured as <see cref="ChannelMessages.ConfigUpdate"/> builds it, with a 36-character <c>id</c>,
    /// so the outcome never depends on the UUID generated for it.
    /// </remarks>
    /// <param name="revision">The revision of the config.</param>
    /// <param name="agentChannelUrl">
    /// The absolute <c>https</c> base URL of the agent channel, in ASCII, such as <c>https://host/dvls</c>,
    /// without user information or any other <c>@</c>, query or fragment;
    /// null when the authority does not offer the channel to the identity, so that the agent opens none.
    /// </param>
    /// <param name="productFields">The product-specific fields, if any.</param>
    /// <exception cref="ArgumentException">
    /// <paramref name="agentChannelUrl"/> is not ASCII, is not an absolute <c>https</c> URL,
    /// or has user information or any other <c>@</c>, a query or a fragment;
    /// or a product-specific field has no name, a name that is not snake_case or that the contract gives a member,
    /// no value, the value <c>null</c>, or a value that UTF-8 JSON cannot carry, such as a lone surrogate;
    /// or a member inside a value has a name that is not snake_case or that its object repeats, or the value
    /// <c>null</c>;
    /// or the <c>ConfigUpdate</c> message that carries the config would exceed 65,536 bytes
    /// (CONTRACT.agent-identity.md §7.1), an error reported for <paramref name="productFields"/>.
    /// </exception>
    public static IdentityConfig Create(
        ulong revision,
        string? agentChannelUrl = null,
        IEnumerable<KeyValuePair<string, JsonElement>>? productFields = null)
    {
        string? normalizedUrl = agentChannelUrl is null
            ? null
            : BaseUrl.Normalize(agentChannelUrl, "The agent channel URL", nameof(agentChannelUrl));

        byte[] utf8Json = Write(revision, normalizedUrl, productFields ?? []);
        int envelopeBytes = ConfigUpdateBytes(utf8Json);

        if (envelopeBytes > MaxEnvelopeBytes)
        {
            throw new ArgumentException(
                $"The ConfigUpdate message of the config would take {envelopeBytes} bytes, "
                    + $"more than the {MaxEnvelopeBytes} bytes that the agent channel carries.",
                nameof(productFields));
        }

        return new IdentityConfig(revision, normalizedUrl, utf8Json);
    }

    /// <summary>
    /// Writes the config as a UTF-8 JSON object with the members <c>version</c>, <c>revision</c>,
    /// <c>agent_channel_url</c> when the authority offers the agent channel, and the product-specific fields.
    /// </summary>
    public byte[] ToUtf8Json()
    {
        return [.. _utf8Json];
    }

    // Writes the config once, when it is created,
    // so that a value that UTF-8 JSON cannot carry fails then rather than in a response.
    private static byte[] Write(
        ulong revision,
        string? agentChannelUrl,
        IEnumerable<KeyValuePair<string, JsonElement>> productFields)
    {
        ArrayBufferWriter<byte> buffer = new();

        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            writer.WriteNumber(VersionMember, SchemaVersion);
            writer.WriteNumber(RevisionMember, revision);

            if (agentChannelUrl is not null)
            {
                writer.WriteString(AgentChannelUrlMember, agentChannelUrl);
            }

            WriteProductFields(writer, productFields);
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }

    // Measures the ConfigUpdate that ChannelMessages builds for the config.
    // Its id is a fresh lowercase hyphenated UUID, so a placeholder of the same 36 characters stands in for it,
    // and the outcome never depends on the UUID generated.
    private static int ConfigUpdateBytes(byte[] utf8Json)
    {
        ServerMessage envelope = new()
        {
            Id = Guid.Empty.ToString("D"),
            ConfigUpdate = new ConfigUpdate { ConfigJson = Encoding.UTF8.GetString(utf8Json) },
        };

        return envelope.CalculateSize();
    }

    private static void WriteProductFields(
        Utf8JsonWriter writer,
        IEnumerable<KeyValuePair<string, JsonElement>> productFields)
    {
        HashSet<string> names = new(StringComparer.Ordinal);
        int position = 0;

        foreach ((string name, JsonElement value) in productFields)
        {
            position++;

            if (name is null)
            {
                throw new ArgumentException($"Product field {position} has no name.", nameof(productFields));
            }

            // The name is quoted only once it is valid, so that a message never repeats arbitrary text.
            if (!IsSnakeCase(name))
            {
                throw new ArgumentException(
                    $"The name of product field {position} is not snake_case.",
                    nameof(productFields));
            }

            if (name is VersionMember or RevisionMember or AgentChannelUrlMember)
            {
                throw new ArgumentException(
                    $"The product field '{name}' would repeat a member of the config.",
                    nameof(productFields));
            }

            if (!names.Add(name))
            {
                throw new ArgumentException($"The product fields repeat the name '{name}'.", nameof(productFields));
            }

            if (value.ValueKind is JsonValueKind.Undefined or JsonValueKind.Null)
            {
                throw new ArgumentException(
                    $"The product field '{name}' has no value; an absent field is omitted, never null.",
                    nameof(productFields));
            }

            try
            {
                // CONTRACT.agent-identity.md §1 governs every member of an agent-facing body,
                // so it governs those inside the value.
                if (CheckMembers(value) is { } problem)
                {
                    throw new ArgumentException(
                        $"The value of the product field '{name}' {problem}.",
                        nameof(productFields));
                }

                writer.WritePropertyName(name);
                value.WriteTo(writer);
            }
            catch (InvalidOperationException exception)
            {
                throw new ArgumentException(
                    $"The value of the product field '{name}' cannot be written as UTF-8 JSON.",
                    nameof(productFields),
                    exception);
            }
        }
    }

    // Returns how a member inside the value breaks the conventions of CONTRACT.agent-identity.md §1, or null.
    // The walk keeps its own stack, so that a deeply nested value cannot exhaust the thread's stack.
    // Reading a name decodes its escapes, and throws InvalidOperationException for a lone surrogate.
    private static string? CheckMembers(JsonElement value)
    {
        Stack<JsonElement> pending = new();
        pending.Push(value);

        while (pending.TryPop(out JsonElement element))
        {
            if (element.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement item in element.EnumerateArray())
                {
                    pending.Push(item);
                }
            }
            else if (element.ValueKind == JsonValueKind.Object)
            {
                HashSet<string> names = new(StringComparer.Ordinal);

                foreach (JsonProperty member in element.EnumerateObject())
                {
                    string memberName = member.Name;

                    // The name is quoted only once it is valid, so that a message never repeats arbitrary text.
                    if (!IsSnakeCase(memberName))
                    {
                        return "has a member whose name is not snake_case";
                    }

                    // RFC 8259 §4: receivers disagree on the value of a repeated name.
                    if (!names.Add(memberName))
                    {
                        return $"repeats the member name '{memberName}' in one object";
                    }

                    if (member.Value.ValueKind == JsonValueKind.Null)
                    {
                        return $"gives the member '{memberName}' the value null; an absent field is omitted";
                    }

                    pending.Push(member.Value);
                }
            }
        }

        return null;
    }

    // Checks the name character by character:
    // a .NET regular expression ending in $ would also accept a final line feed.
    private static bool IsSnakeCase(string name)
    {
        if (name.Length == 0 || name[0] is not (>= 'a' and <= 'z') || name[^1] == '_')
        {
            return false;
        }

        for (int i = 1; i < name.Length; i++)
        {
            char c = name[i];

            if (!(c is (>= 'a' and <= 'z') or (>= '0' and <= '9') || (c == '_' && name[i - 1] != '_')))
            {
                return false;
            }
        }

        return true;
    }
}
