using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class AccessScopeJsonConverter : JsonConverter<AccessScope>
{
    public override AccessScope Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) => new AccessScope(reader.GetString()!);

    public override void Write(
        Utf8JsonWriter writer,
        AccessScope scope,
        JsonSerializerOptions options) => writer.WriteStringValue(scope.ToString());
}