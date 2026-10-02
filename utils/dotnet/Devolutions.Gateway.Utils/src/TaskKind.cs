using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

[JsonConverter(typeof(TaskKindJsonConverter))]
public struct TaskKind
{
    public string Value { get; internal set; }

    internal TaskKind(string value)
    {
        Value = value;
    }

    public static TaskKind AiLog = new TaskKind("ai-log");

    public override string? ToString()
    {
        return this.Value;
    }
}
