using System.Diagnostics.CodeAnalysis;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The outcome of <see cref="AgentMetadata.Validate"/>: valid metadata, or the error that rejects it.
/// </summary>
/// <remarks>
/// The error is <c>400 invalid_request</c>.
/// <see cref="AgentIdentityResult.FailureDetail"/> never repeats a key or value of the metadata:
/// it names an entry by its position.
/// </remarks>
public sealed class MetadataValidationResult : AgentIdentityResult
{
    private static readonly AgentIdentityError InvalidRequest =
        AgentIdentityError.From(AgentIdentityErrorCode.InvalidRequest);

    private MetadataValidationResult(AgentMetadata? metadata, AgentIdentityError? error, string? failureDetail)
        : base(error, failureDetail)
    {
        Metadata = metadata;
    }

    /// <summary>
    /// Whether the metadata is valid.
    /// </summary>
    [MemberNotNullWhen(true, nameof(Metadata))]
    public override bool Succeeded => Metadata is not null;

    /// <summary>
    /// The validated metadata, when <see cref="Succeeded"/> is true.
    /// </summary>
    public AgentMetadata? Metadata { get; }

    internal static MetadataValidationResult Success(AgentMetadata metadata)
    {
        return new MetadataValidationResult(metadata, null, null);
    }

    internal static MetadataValidationResult Failure(string detail)
    {
        return new MetadataValidationResult(null, InvalidRequest, detail);
    }
}
