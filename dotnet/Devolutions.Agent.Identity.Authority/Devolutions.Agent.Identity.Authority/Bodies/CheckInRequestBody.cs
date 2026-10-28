namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The body of a <c>check-in</c> request: the agent's metadata.
/// </summary>
public sealed class CheckInRequestBody
{
    private CheckInRequestBody(AgentMetadata metadata)
    {
        Metadata = metadata;
    }

    /// <summary>
    /// The validated metadata.
    /// </summary>
    public AgentMetadata Metadata { get; }

    /// <summary>
    /// Parses and validates the body of a <c>check-in</c> request, <c>{ "metadata": { ... } }</c>.
    /// </summary>
    /// <remarks>
    /// The body is one JSON object without comments or trailing commas, nested at most 64 levels deep,
    /// that repeats no member name at any depth and whose strings are all Unicode text.
    /// <c>metadata</c> is an object that <see cref="AgentMetadata.Validate"/> accepts,
    /// a <c>null</c> member counts as absent, and other members are ignored.
    /// Authenticate the request first, since an authentication error wins over an invalid body.
    /// </remarks>
    /// <param name="utf8Json">The request body.</param>
    public static RequestBodyParseResult<CheckInRequestBody> Parse(ReadOnlySpan<byte> utf8Json)
    {
        return RequestBodyReader.ReadMetadata(utf8Json, metadata => new CheckInRequestBody(metadata));
    }
}
