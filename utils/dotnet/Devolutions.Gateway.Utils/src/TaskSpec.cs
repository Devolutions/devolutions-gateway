using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

/// <summary>
/// A task kind with the payload of that kind.
/// </summary>
public class TaskSpec
{
    [JsonPropertyName("kind")]
    public TaskKind Kind => this.Payload.Kind;

    [JsonPropertyName("payload")]
    public TaskPayload Payload { get; }

    internal TaskSpec(TaskPayload payload)
    {
        this.Payload = payload;
    }
}
