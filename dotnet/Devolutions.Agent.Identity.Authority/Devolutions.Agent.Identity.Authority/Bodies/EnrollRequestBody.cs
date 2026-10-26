namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The body of an <c>enroll</c> request: the CSR of the key to enroll and the agent's metadata.
/// </summary>
public sealed class EnrollRequestBody
{
    private EnrollRequestBody(CertificateSigningRequest csr, AgentMetadata metadata)
    {
        Csr = csr;
        Metadata = metadata;
    }

    /// <summary>
    /// The validated CSR of the key to enroll.
    /// </summary>
    public CertificateSigningRequest Csr { get; }

    /// <summary>
    /// The validated metadata.
    /// </summary>
    public AgentMetadata Metadata { get; }

    /// <summary>
    /// Parses and validates the body of an <c>enroll</c> request, <c>{ "csr": "...", "metadata": { ... } }</c>.
    /// </summary>
    /// <remarks>
    /// The body is one JSON object without comments or trailing commas, nested at most 64 levels deep,
    /// that repeats no member name at any depth and whose strings are all Unicode text.
    /// <c>csr</c> is a canonical <c>base64</c> request that <see cref="CertificateSigningRequest.Validate"/> accepts,
    /// <c>metadata</c> is an object that <see cref="AgentMetadata.Validate"/> accepts,
    /// a <c>null</c> member counts as absent, and other members are ignored.
    /// Check the enrollment token first, since an authentication error wins over an invalid body.
    /// </remarks>
    /// <param name="utf8Json">The request body.</param>
    public static RequestBodyParseResult<EnrollRequestBody> Parse(ReadOnlySpan<byte> utf8Json)
    {
        return RequestBodyReader.ReadCsrAndMetadata(utf8Json, (csr, metadata) => new EnrollRequestBody(csr, metadata));
    }
}
