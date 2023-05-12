using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class RecordingOperationJsonConverter : JsonConverter<RecordingOperation>
{
    public override RecordingOperation Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) => new RecordingOperation(reader.GetString()!);

    public override void Write(
        Utf8JsonWriter writer,
        RecordingOperation recordingOperation,
        JsonSerializerOptions options) => writer.WriteStringValue(recordingOperation.ToString());
}