using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The authority's choice of key storage for an identity's keys,
/// which the identity's config carries as <c>key_storage</c> (CONTRACT.agent-identity.md §5.7).
/// </summary>
/// <remarks>
/// Only <see cref="Create"/> and <see cref="TryParse"/> create instances,
/// so an instance always holds 1 to 8 distinct names of <see cref="KeyStorageNames.All"/>,
/// since an authority sends only the names that the contract lists.
/// The host stores a policy as the JSON of <see cref="ToUtf8Json"/> and reloads it with <see cref="TryParse"/>,
/// and passes it to <see cref="IdentityConfig.Create"/> to put it in a config.
/// </remarks>
public sealed class KeyStoragePolicy
{
    private const string BackendsMember = "backends";
    private const string RequiredMember = "required";

    private const int MaxBackends = 8;

    private KeyStoragePolicy(string[] backends, bool required)
    {
        Backends = Array.AsReadOnly(backends);
        Required = required;
    }

    /// <summary>
    /// The names of the key storages in which the agent may create the identity's keys,
    /// in the authority's order of preference: the agent creates each new key in the first one available.
    /// </summary>
    public IReadOnlyList<string> Backends { get; }

    /// <summary>
    /// Whether the agent must not create a key outside <see cref="Backends"/>:
    /// when none of them is available, true makes the agent keep its current key,
    /// and false lets it create the key in a key storage of its own choosing.
    /// </summary>
    public bool Required { get; }

    /// <summary>
    /// Creates a policy.
    /// </summary>
    /// <param name="backends">
    /// 1 to 8 distinct names of <see cref="KeyStorageNames.All"/>, in the authority's order of preference.
    /// </param>
    /// <param name="required">Whether the agent must not create a key outside <paramref name="backends"/>.</param>
    /// <exception cref="ArgumentNullException"><paramref name="backends"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="backends"/> is empty, holds more than 8 names, repeats a name,
    /// or holds a null or a name that <see cref="KeyStorageNames.All"/> does not.
    /// </exception>
    public static KeyStoragePolicy Create(IEnumerable<string> backends, bool required)
    {
        ArgumentNullException.ThrowIfNull(backends);

        string[] names = [.. backends];

        if (CheckBackends(names) is { } problem)
        {
            throw new ArgumentException(problem, nameof(backends));
        }

        return new KeyStoragePolicy(names, required);
    }

    /// <summary>
    /// Reads a policy from the JSON that <see cref="ToUtf8Json"/> writes, such as a policy that the host stored.
    /// </summary>
    /// <remarks>
    /// The JSON is one object with exactly the members <c>backends</c>, an array of names that
    /// <see cref="Create"/> accepts, and <c>required</c>, <c>true</c> or <c>false</c>.
    /// JSON that repeats a member name, holds another member, or holds a string that is not Unicode text is refused,
    /// as CONTRACT.agent-identity.md §1 refuses such a request body, so that no other parser reads another policy.
    /// False means that the JSON holds no policy this library can read, such as one naming a key storage it does not
    /// know, not that the identity has no policy.
    /// </remarks>
    /// <param name="utf8Json">The UTF-8 JSON of the policy.</param>
    /// <param name="policy">The policy, when the JSON holds a valid one.</param>
    /// <returns>Whether the JSON holds a valid policy.</returns>
    public static bool TryParse(ReadOnlySpan<byte> utf8Json, [NotNullWhen(true)] out KeyStoragePolicy? policy)
    {
        policy = null;

        if (RequestBodyReader.CheckJson(utf8Json) is not null)
        {
            return false;
        }

        // The check read the same bytes under the same default options, so parsing them succeeds.
        using JsonDocument document = JsonDocument.Parse(utf8Json.ToArray());
        JsonElement root = document.RootElement;

        if (root.ValueKind != JsonValueKind.Object)
        {
            return false;
        }

        List<string>? backends = null;
        bool? required = null;

        foreach (JsonProperty member in root.EnumerateObject())
        {
            switch (member.Name)
            {
                case BackendsMember when member.Value.ValueKind == JsonValueKind.Array:
                    backends = [];

                    foreach (JsonElement name in member.Value.EnumerateArray())
                    {
                        if (name.ValueKind != JsonValueKind.String)
                        {
                            return false;
                        }

                        backends.Add(name.GetString()!);
                    }

                    break;

                case RequiredMember when member.Value.ValueKind is JsonValueKind.True or JsonValueKind.False:
                    required = member.Value.GetBoolean();
                    break;

                default:
                    return false;
            }
        }

        if (backends is null || required is null || CheckBackends(backends) is not null)
        {
            return false;
        }

        policy = new KeyStoragePolicy([.. backends], required.Value);

        return true;
    }

    /// <summary>
    /// Writes the policy as a UTF-8 JSON object with the members <c>backends</c> and <c>required</c>.
    /// </summary>
    public byte[] ToUtf8Json()
    {
        ArrayBufferWriter<byte> buffer = new();

        using (Utf8JsonWriter writer = new(buffer))
        {
            WriteTo(writer);
        }

        return buffer.WrittenSpan.ToArray();
    }

    internal void WriteTo(Utf8JsonWriter writer)
    {
        writer.WriteStartObject();
        writer.WriteStartArray(BackendsMember);

        foreach (string name in Backends)
        {
            writer.WriteStringValue(name);
        }

        writer.WriteEndArray();
        writer.WriteBoolean(RequiredMember, Required);
        writer.WriteEndObject();
    }

    // Returns why the names break the rules of CONTRACT.agent-identity.md §5.7 for an authority, or null.
    private static string? CheckBackends(IReadOnlyList<string?> names)
    {
        if (names.Count == 0)
        {
            return "The key storage policy names no key storage.";
        }

        if (names.Count > MaxBackends)
        {
            return $"The key storage policy names more than {MaxBackends} key storages.";
        }

        HashSet<string> seen = new(StringComparer.Ordinal);

        for (int i = 0; i < names.Count; i++)
        {
            string? name = names[i];

            // The name is quoted only once it is known, so that a message never repeats arbitrary text.
            if (name is null || !KeyStorageNames.All.Contains(name, StringComparer.Ordinal))
            {
                return $"Key storage {i + 1} of the policy is not one of "
                    + string.Join(", ", KeyStorageNames.All) + ".";
            }

            if (!seen.Add(name))
            {
                return $"The key storage policy repeats '{name}'.";
            }
        }

        return null;
    }
}
