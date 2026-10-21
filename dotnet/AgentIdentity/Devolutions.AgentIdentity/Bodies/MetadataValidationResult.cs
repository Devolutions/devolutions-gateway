using System.Diagnostics.CodeAnalysis;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The outcome of <see cref="AgentMetadata.Validate"/>: valid metadata, or the error that rejects it.
/// </summary>
public sealed class MetadataValidationResult
{
    private static readonly AgentIdentityError InvalidRequest =
        AgentIdentityError.From(AgentIdentityErrorCode.InvalidRequest);

    private MetadataValidationResult(AgentMetadata? metadata, AgentIdentityError? error, string? failureDetail)
    {
        Succeeded = metadata is not null;
        Metadata = metadata;
        Error = error;
        FailureDetail = failureDetail;
    }

    /// <summary>
    /// Whether the metadata is valid.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Metadata))]
    [MemberNotNullWhen(false, nameof(Error), nameof(FailureDetail))]
    public bool Succeeded { get; }

    /// <summary>
    /// The validated metadata, when <see cref="Succeeded"/> is true.
    /// </summary>
    public AgentMetadata? Metadata { get; }

    /// <summary>
    /// <c>400 invalid_request</c>, when <see cref="Succeeded"/> is false.
    /// </summary>
    public AgentIdentityError? Error { get; }

    /// <summary>
    /// Why the metadata is invalid, for the host's logs, when <see cref="Succeeded"/> is false.
    /// </summary>
    /// <remarks>
    /// The detail never repeats a key or value of the metadata: it names an entry by its position.
    /// </remarks>
    public string? FailureDetail { get; }

    internal static MetadataValidationResult Success(AgentMetadata metadata)
    {
        return new MetadataValidationResult(metadata, null, null);
    }

    internal static MetadataValidationResult Failure(string detail)
    {
        return new MetadataValidationResult(null, InvalidRequest, detail);
    }
}
