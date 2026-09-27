using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

public class TaskKindJsonConverter : JsonConverter<TaskKind>
{
    public override TaskKind Read(
        ref Utf8JsonReader reader,
        Type typeToConvert,
        JsonSerializerOptions options) => new TaskKind(reader.GetString()!);

    public override void Write(
        Utf8JsonWriter writer,
        TaskKind taskKind,
        JsonSerializerOptions options) => writer.WriteStringValue(taskKind.ToString());
}
