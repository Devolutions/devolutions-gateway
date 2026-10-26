using System.Security.Cryptography;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The signature algorithm of request signatures and channel proofs: ECDSA P-256 over SHA-256, as raw <c>r‖s</c>.
/// </summary>
internal static class EcdsaP256Signature
{
    /// <summary>
    /// The length of a signature: <c>r</c> and <c>s</c>, each a 32-byte big-endian unsigned integer.
    /// </summary>
    public const int Length = 64;

    /// <summary>
    /// Verifies a signature over data, as RFC 9421 §3.3.4 defines for <c>ecdsa-p256-sha256</c>.
    /// </summary>
    /// <param name="publicKey">A P-256 public key.</param>
    /// <param name="data">The signed bytes, which are hashed with SHA-256.</param>
    /// <param name="signature">The signature, which fails unless it is exactly 64 bytes.</param>
    public static bool Verify(ECDsa publicKey, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        return signature.Length == Length
            && publicKey.VerifyData(
                data,
                signature,
                HashAlgorithmName.SHA256,
                DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}
