using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class ReusePolicyJsonConverter : JsonConverter<ReusePolicy>
{
    public override ReusePolicy Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) => new ReusePolicy(reader.GetUInt32());

    public override void Write(
        Utf8JsonWriter writer,
        ReusePolicy policy,
        JsonSerializerOptions options) => writer.WriteNumberValue(policy.Value);
}