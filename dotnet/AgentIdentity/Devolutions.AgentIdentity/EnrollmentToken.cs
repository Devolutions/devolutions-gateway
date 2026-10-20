using System.Buffers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Devolutions.AgentIdentity;

/// <summary>
/// A new enrollment token, <c>dvaet1.&lt;bag&gt;.&lt;secret&gt;</c>,
/// which authorizes enrolling new identities and nothing else.
/// </summary>
/// <remarks>
/// The bag tells the agent where to enroll and is never trusted.
/// The secret authenticates the token, and the authority stores only its hash.
/// </remarks>
public sealed class EnrollmentToken
{
    /// <summary>
    /// The format version that starts every token this library creates or reads.
    /// </summary>
    internal const string Prefix = "dvaet1";

    /// <summary>
    /// The length of the secret segment: the base64url encoding of 32 bytes, without padding.
    /// </summary>
    internal const int SecretLength = 43;

    /// <summary>
    /// The largest token, in bytes; a token is ASCII, so this is also its largest number of characters.
    /// </summary>
    internal const int MaxLength = 4096;

    private const int SecretByteCount = 32;

    private EnrollmentToken(string value, byte[] secretHash)
    {
        Value = value;
        SecretHash = secretHash;
    }

    /// <summary>
    /// The token text, which the authority shows once, to the administrator who creates the token.
    /// </summary>
    /// <remarks>
    /// The authority never stores or logs the token text, not even partially; it stores <see cref="SecretHash"/>.
    /// </remarks>
    public string Value { get; }

    /// <summary>
    /// The SHA-256 of the ASCII text of the secret segment, under which the authority stores the token.
    /// </summary>
    /// <remarks>
    /// <see cref="EnrollmentAuthorization.ReadBearerToken"/> returns the same hash for the token text,
    /// so that the authority finds the token by it.
    /// </remarks>
    public ReadOnlyMemory<byte> SecretHash { get; }

    /// <summary>
    /// Creates a token for the authority that serves the agent-facing API under a product base URL.
    /// </summary>
    /// <remarks>
    /// The bag holds the JSON object <c>{"u": &lt;productBaseUrl&gt;}</c>,
    /// with the URL in normalized absolute form and without trailing slashes,
    /// since the agent appends <c>/api/agent-identity/v1/...</c> to it.
    /// The secret is 32 bytes from <paramref name="randomNumberGenerator"/>.
    /// </remarks>
    /// <param name="productBaseUrl">
    /// The absolute <c>https</c> URL of the product, such as <c>https://host/dvls</c>,
    /// without user information, query or fragment.
    /// </param>
    /// <param name="randomNumberGenerator">A cryptographically secure generator, which supplies the secret.</param>
    /// <exception cref="ArgumentNullException">An argument is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="productBaseUrl"/> is not an absolute <c>https</c> URL,
    /// has user information, a query or a fragment, or makes the token longer than 4096 bytes.
    /// </exception>
    public static EnrollmentToken Create(string productBaseUrl, RandomNumberGenerator randomNumberGenerator)
    {
        ArgumentNullException.ThrowIfNull(productBaseUrl);
        ArgumentNullException.ThrowIfNull(randomNumberGenerator);

        ArrayBufferWriter<byte> json = new();

        using (Utf8JsonWriter writer = new(json))
        {
            writer.WriteStartObject();
            writer.WriteString("u", BaseUrl.Normalize(productBaseUrl, "The product base URL", nameof(productBaseUrl)));
            writer.WriteEndObject();
        }

        string bag = StrictBase64.EncodeBase64Url(json.WrittenSpan);

        if (!(Prefix.Length + 1 + bag.Length + 1 + SecretLength <= MaxLength))
        {
            throw new ArgumentException(
                "The product base URL makes the token longer than 4096 bytes.",
                nameof(productBaseUrl));
        }

        Span<byte> secretBytes = stackalloc byte[SecretByteCount];
        randomNumberGenerator.GetBytes(secretBytes);
        string secret = StrictBase64.EncodeBase64Url(secretBytes);

        return new EnrollmentToken(Prefix + "." + bag + "." + secret, HashSecret(secret));
    }

    /// <summary>
    /// Returns the type name, never the token, so that logging the object reveals no part of the token.
    /// </summary>
    public override string ToString()
    {
        return nameof(EnrollmentToken);
    }

    /// <summary>
    /// Computes the hash under which the authority stores a token: the SHA-256 of the ASCII text of its secret.
    /// </summary>
    /// <remarks>
    /// The authority matches the secret text exactly, so the hash covers the text rather than the bytes it encodes.
    /// </remarks>
    /// <param name="secret">The secret segment of the token, in the base64url alphabet.</param>
    internal static byte[] HashSecret(ReadOnlySpan<char> secret)
    {
        byte[] ascii = new byte[secret.Length];
        Encoding.ASCII.GetBytes(secret, ascii);

        return SHA256.HashData(ascii);
    }
}
