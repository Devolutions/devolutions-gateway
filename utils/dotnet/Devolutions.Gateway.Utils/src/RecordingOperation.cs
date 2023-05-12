using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

[JsonConverter(typeof(RecordingOperationJsonConverter))]
public struct RecordingOperation
{
    public string Value { get; internal set; }

    internal RecordingOperation(string value)
    {
        Value = value;
    }

    public static RecordingOperation Push = new RecordingOperation("push");
    public static RecordingOperation Pull = new RecordingOperation("pull");

    public override string? ToString()
    {
        return this.Value;
    }
}