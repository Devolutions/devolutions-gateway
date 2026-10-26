using System.Security.Cryptography;
using System.Text;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The proof in <c>Hello</c> that the agent holds the key of the certificate that opened the stream,
/// as CONTRACT.agent-identity.md §7.3 step 3 defines it.
/// </summary>
internal static class ChannelProof
{
    // The device key also signs request signature bases, which start with a quoted component name,
    // so no proof is ever a valid request signature, nor the reverse.
    private static ReadOnlySpan<byte> Domain => "devolutions-agent-identity/v1/channel-proof"u8;

    /// <summary>
    /// Builds the bytes that the proof signs: the domain, a zero byte, the challenge,
    /// then the UTF-8 bytes of the <c>nonce</c> parameter of the opening request.
    /// </summary>
    public static byte[] BuildInput(ReadOnlySpan<byte> challenge, string connectNonce)
    {
        return [.. Domain, 0x00, .. challenge, .. Encoding.UTF8.GetBytes(connectNonce)];
    }

    /// <summary>
    /// Verifies a proof, which fails unless it is a raw 64-byte <c>r‖s</c> signature by the key.
    /// </summary>
    /// <param name="subjectPublicKeyInfo">
    /// The P-256 key of the certificate that authenticated the opening request.
    /// </param>
    /// <param name="challenge">The random bytes of the Challenge that the stream sent.</param>
    /// <param name="connectNonce">The <c>nonce</c> parameter of the opening request.</param>
    /// <param name="proof">The <c>proof</c> of the <c>Hello</c>.</param>
    public static bool Verify(
        byte[] subjectPublicKeyInfo,
        ReadOnlySpan<byte> challenge,
        string connectNonce,
        ReadOnlySpan<byte> proof)
    {
        using ECDsa publicKey = ECDsa.Create();
        publicKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo, out _);

        return EcdsaP256Signature.Verify(publicKey, BuildInput(challenge, connectNonce), proof);
    }
}
