using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

[JsonConverter(typeof(RecordingPolicyJsonConverter))]
public struct RecordingPolicy
{
    public string Value { get; internal set; }

    internal RecordingPolicy(string value)
    {
        Value = value;
    }

    public static RecordingPolicy None = new RecordingPolicy("none");
    public static RecordingPolicy Stream = new RecordingPolicy("stream");
    public static RecordingPolicy Proxy = new RecordingPolicy("proxy");

    public override string? ToString()
    {
        return this.Value;
    }
}