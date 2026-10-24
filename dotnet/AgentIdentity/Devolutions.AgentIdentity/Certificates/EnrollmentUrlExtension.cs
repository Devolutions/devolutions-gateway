using System.Formats.Asn1;
using System.Security.Cryptography.X509Certificates;

namespace Devolutions.AgentIdentity;

/// <summary>
/// The enrollment URL extension of CONTRACT.agent-identity.md §4: a non-critical extension whose value is an IA5String
/// holding the <c>u</c> of the token that enrolled an identity, without trailing slashes.
/// </summary>
/// <remarks>
/// Every certificate issued for an identity carries it once with the same value,
/// and the agent's CSR requests it in an extensionRequest with the base URL it sends the request to.
/// </remarks>
internal static class EnrollmentUrlExtension
{
    // CONTRACT.agent-identity.md §4: the OID of the enrollment URL extension.
    public const string Oid = "1.3.6.1.4.1.32473.1.1";

    /// <summary>
    /// Creates the extension, non-critical, for an enrollment URL.
    /// </summary>
    /// <param name="enrollmentUrl">The enrollment URL, which is ASCII and has no trailing slash.</param>
    public static X509Extension Create(string enrollmentUrl)
    {
        AsnWriter writer = new(AsnEncodingRules.DER);
        writer.WriteCharacterString(UniversalTagNumber.IA5String, enrollmentUrl);

        return new X509Extension(Oid, writer.Encode(), critical: false);
    }

    /// <summary>
    /// Reads the enrollment URL from the value of the extension, or returns null when the value is not one IA5String.
    /// </summary>
    /// <param name="value">The contents of the extension's <c>extnValue</c> OCTET STRING.</param>
    public static string? ReadValue(ReadOnlyMemory<byte> value)
    {
        try
        {
            AsnReader reader = new(value, AsnEncodingRules.DER);
            string enrollmentUrl = reader.ReadCharacterString(UniversalTagNumber.IA5String);
            reader.ThrowIfNotEmpty();
            return enrollmentUrl;
        }
        catch (AsnContentException)
        {
            return null;
        }
    }
}
