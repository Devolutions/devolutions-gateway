namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The parts of an HTTP request that request authentication reads, as the host received them.
/// </summary>
public sealed class SignedHttpRequest
{
    /// <summary>
    /// Creates the request from what the host received.
    /// </summary>
    /// <param name="method">The request method, as received.</param>
    /// <param name="signatureInput">
    /// The <c>Signature-Input</c> field lines in received order; empty when the field is absent.
    /// </param>
    /// <param name="signature">
    /// The <c>Signature</c> field lines in received order; empty when the field is absent.
    /// </param>
    /// <param name="contentDigest">
    /// The <c>Content-Digest</c> field lines in received order; empty when the field is absent.
    /// </param>
    /// <param name="body">The request body, as received.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">A field line is null.</exception>
    public SignedHttpRequest(
        string method,
        IReadOnlyList<string> signatureInput,
        IReadOnlyList<string> signature,
        IReadOnlyList<string> contentDigest,
        ReadOnlyMemory<byte> body)
    {
        ArgumentNullException.ThrowIfNull(method);

        Method = method;
        SignatureInput = FieldLines.Copy(signatureInput, nameof(signatureInput));
        Signature = FieldLines.Copy(signature, nameof(signature));
        ContentDigest = FieldLines.Copy(contentDigest, nameof(contentDigest));
        Body = body;
    }

    /// <summary>
    /// The request method, as received.
    /// </summary>
    public string Method { get; }

    /// <summary>
    /// The <c>Signature-Input</c> field lines in received order.
    /// </summary>
    public IReadOnlyList<string> SignatureInput { get; }

    /// <summary>
    /// The <c>Signature</c> field lines in received order.
    /// </summary>
    public IReadOnlyList<string> Signature { get; }

    /// <summary>
    /// The <c>Content-Digest</c> field lines in received order.
    /// </summary>
    public IReadOnlyList<string> ContentDigest { get; }

    /// <summary>
    /// The request body, as received.
    /// </summary>
    public ReadOnlyMemory<byte> Body { get; }
}
