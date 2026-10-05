using System.Text.Json.Serialization;

namespace Devolutions.Gateway.Utils;

[JsonConverter(typeof(JsonStringEnumConverter<AiProvider>))]
public enum AiProvider
{
    [JsonStringEnumMemberName("openai")]
    OpenAi,

    [JsonStringEnumMemberName("anthropic")]
    Anthropic,

    [JsonStringEnumMemberName("mistral")]
    Mistral,

    [JsonStringEnumMemberName("gemini")]
    Gemini,

    [JsonStringEnumMemberName("openai-compatible")]
    OpenAiCompatible,
}
