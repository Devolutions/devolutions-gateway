using System.Text.Json;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// Reads JSON that the library wrote with the BCL alone, so that a library bug cannot make a body agree with itself.
/// </summary>
internal static class TestJson
{
    public const string LowercaseUuidPattern = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";

    /// <summary>
    /// The members of a JSON text that holds one object, by name; a repeated member name fails.
    /// </summary>
    public static Dictionary<string, JsonElement> Members(byte[] utf8Json)
    {
        using JsonDocument document = JsonDocument.Parse(utf8Json);

        return Members(document.RootElement.Clone());
    }

    /// <summary>
    /// The members of an object, by name; a repeated member name fails.
    /// </summary>
    public static Dictionary<string, JsonElement> Members(JsonElement element)
    {
        Assert.Equal(JsonValueKind.Object, element.ValueKind);

        return element
            .EnumerateObject()
            .ToDictionary(member => member.Name, member => member.Value, StringComparer.Ordinal);
    }

    /// <summary>
    /// The names of the members of an object, in ordinal order, for comparison with the members a contract lists.
    /// </summary>
    public static IEnumerable<string> Names(Dictionary<string, JsonElement> members)
    {
        return members.Keys.Order(StringComparer.Ordinal);
    }

    /// <summary>
    /// The elements of an array.
    /// </summary>
    public static JsonElement[] Elements(JsonElement element)
    {
        Assert.Equal(JsonValueKind.Array, element.ValueKind);

        return [.. element.EnumerateArray()];
    }

    /// <summary>
    /// Decodes a string in canonical <c>base64</c> (RFC 4648 §4):
    /// the encoding that the BCL writes for the decoded bytes, with padding and without white space.
    /// </summary>
    public static byte[] CanonicalBase64(JsonElement element)
    {
        Assert.Equal(JsonValueKind.String, element.ValueKind);
        string text = element.GetString()!;
        byte[] bytes = Convert.FromBase64String(text);
        Assert.Equal(Convert.ToBase64String(bytes), text);

        return bytes;
    }

    public static JsonElement Parse(string text)
    {
        using JsonDocument document = JsonDocument.Parse(text);

        return document.RootElement.Clone();
    }
}
