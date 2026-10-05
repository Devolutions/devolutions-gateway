using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

/// <summary>
/// Payload of a task kind.
/// </summary>
/// <remarks>
/// Each kind is a derived type registered below, so it serializes with its own properties and no type discriminator.
/// </remarks>
[JsonDerivedType(typeof(RecordingAiAnalysisPayload))]
public abstract class TaskPayload
{
    [JsonIgnore]
    public abstract TaskKind Kind { get; }
}
