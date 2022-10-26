using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class ApplicationProtocolJsonConverter : JsonConverter<ApplicationProtocol>
{
    public override ApplicationProtocol Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) => new ApplicationProtocol(reader.GetString()!);

    public override void Write(
        Utf8JsonWriter writer,
        ApplicationProtocol applicationProtocol,
        JsonSerializerOptions options) => writer.WriteStringValue(applicationProtocol.ToString());
}