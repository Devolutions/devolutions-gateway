using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class RecordingPolicyJsonConverter : JsonConverter<RecordingPolicy>
{
    public override RecordingPolicy Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) => new RecordingPolicy(reader.GetString()!);

    public override void Write(
        Utf8JsonWriter writer,
        RecordingPolicy policy,
        JsonSerializerOptions options) => writer.WriteStringValue(policy.ToString());
}