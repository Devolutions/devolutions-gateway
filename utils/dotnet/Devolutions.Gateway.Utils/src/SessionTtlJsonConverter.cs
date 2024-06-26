using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class SessionTtlJsonConverter : JsonConverter<SessionTtl>
{
    public override SessionTtl Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) => new SessionTtl(reader.GetUInt64());

    public override void Write(
        Utf8JsonWriter writer,
        SessionTtl ttl,
        JsonSerializerOptions options) => writer.WriteNumberValue(ttl.Minutes);
}