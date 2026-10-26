using System.Security.Cryptography;
using System.Text;

namespace Devolutions.Agent.Identity.Authority.Tests;

/// <summary>
/// Channel proofs that a test signs as an agent would,
/// built from CONTRACT.agent-identity.md §7.3 step 3 rather than by the library.
/// </summary>
internal static class TestChannelProof
{
    /// <summary>
    /// Signs the domain, a zero byte, the challenge and the connect nonce with the key, as raw <c>r‖s</c>.
    /// </summary>
    /// <remarks>
    /// ECDSA signing is randomized, so each call returns another valid proof.
    /// </remarks>
    public static byte[] Sign(KeyVector key, ReadOnlySpan<byte> challenge, string connectNonce)
    {
        byte[] input =
        [
            .. "devolutions-agent-identity/v1/channel-proof"u8,
            0x00,
            .. challenge,
            .. Encoding.UTF8.GetBytes(connectNonce),
        ];

        using ECDsa privateKey = ECDsa.Create();
        privateKey.ImportPkcs8PrivateKey(key.PrivateKeyPkcs8, out _);

        return privateKey.SignData(
            input,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }
}
