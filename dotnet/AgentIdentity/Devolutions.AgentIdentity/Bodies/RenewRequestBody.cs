namespace Devolutions.AgentIdentity;

/// <summary>
/// The body of a <c>renew</c> request: the CSR of the new key and the agent's metadata.
/// </summary>
public sealed class RenewRequestBody
{
    private RenewRequestBody(CertificateSigningRequest csr, AgentMetadata metadata)
    {
        Csr = csr;
        Metadata = metadata;
    }

    /// <summary>
    /// The validated CSR of the new key.
    /// </summary>
    public CertificateSigningRequest Csr { get; }

    /// <summary>
    /// The validated metadata.
    /// </summary>
    public AgentMetadata Metadata { get; }

    /// <summary>
    /// Parses and validates the body of a <c>renew</c> request, <c>{ "csr": "...", "metadata": { ... } }</c>.
    /// </summary>
    /// <remarks>
    /// The body is one JSON object without comments or trailing commas, nested at most 64 levels deep,
    /// that repeats no member name at any depth and whose strings are all Unicode text.
    /// <c>csr</c> is a canonical <c>base64</c> request that <see cref="CertificateSigningRequest.Validate"/> accepts,
    /// <c>metadata</c> is an object that <see cref="AgentMetadata.Validate"/> accepts,
    /// a <c>null</c> member counts as absent, and other members are ignored.
    /// Authenticate the request first, since an authentication error wins over an invalid body.
    /// </remarks>
    /// <param name="utf8Json">The request body.</param>
    public static RequestBodyParseResult<RenewRequestBody> Parse(ReadOnlySpan<byte> utf8Json)
    {
        return RequestBodyReader.ReadCsrAndMetadata(utf8Json, (csr, metadata) => new RenewRequestBody(csr, metadata));
    }
}
