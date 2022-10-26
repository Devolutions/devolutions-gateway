using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class TargetAddrJsonConverter : JsonConverter<TargetAddr>
{
    public override TargetAddr Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) => TargetAddr.Parse(reader.GetString()!);

    public override void Write(
        Utf8JsonWriter writer,
        TargetAddr addr,
        JsonSerializerOptions options) => writer.WriteStringValue(addr.ToString());
}