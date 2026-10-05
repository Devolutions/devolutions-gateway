using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

/// <summary>
/// Payload of an <c>recording.ai-analysis</c> task.
/// </summary>
/// <remarks>
/// The token is signed but not encrypted, so the API key is not part of it: send it in the body of the task start request.
/// </remarks>
public class RecordingAiAnalysisPayload : TaskPayload
{
    [JsonIgnore]
    public override TaskKind Kind => TaskKind.RecordingAiAnalysis;

    /// <summary>
    /// Session to describe.
    /// </summary>
    [JsonPropertyName("session_id")]
    public Guid SessionId { get; }

    [JsonPropertyName("provider")]
    public AiProvider Provider { get; }

    /// <summary>
    /// Model identifier, passed to the provider as is.
    /// </summary>
    [JsonPropertyName("model")]
    public string Model { get; }

    /// <summary>
    /// Overrides the provider default; required for <see cref="AiProvider.OpenAiCompatible"/>.
    /// </summary>
    [JsonPropertyName("base_url")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? BaseUrl { get; init; }

    /// <summary>
    /// Upper bound of tokens in each AI answer.
    /// </summary>
    [JsonPropertyName("max_output_tokens")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public uint? MaxOutputTokens { get; init; }

    /// <param name="sessionId">Session to describe.</param>
    /// <param name="provider">AI provider to call.</param>
    /// <param name="model">Model identifier, passed to the provider as is.</param>
    public RecordingAiAnalysisPayload(Guid sessionId, AiProvider provider, string model)
    {
        this.SessionId = sessionId;
        this.Provider = provider;
        this.Model = model;
    }
}
