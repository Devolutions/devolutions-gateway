using System.Buffers;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// Writes the bodies of the successful responses of the agent-facing endpoints, as UTF-8 JSON objects.
/// </summary>
/// <remarks>
/// Each body has exactly the members that CONTRACT.agent-identity.md §5 gives the response,
/// and no member is ever <c>null</c>.
/// A certificate is written as its DER in canonical <c>base64</c>, and a time as an RFC 3339 UTC timestamp.
/// </remarks>
public static class ResponseBodies
{
    /// <summary>
    /// Writes the body of a <c>trust-anchor</c> response: <c>roots</c>, the published root certificates.
    /// </summary>
    /// <remarks>
    /// The authority publishes one root normally, and the old and new roots during a rotation.
    /// The roots are written in the order given, each with its <c>certificate</c>, its <c>thumbprint</c>,
    /// and its <c>not_before</c> and <c>not_after</c>.
    /// A chain that validates against these roots says nothing about whether its identity is revoked.
    /// </remarks>
    /// <param name="roots">The published root certificates.</param>
    /// <exception cref="ArgumentNullException"><paramref name="roots"/> is null.</exception>
    /// <exception cref="ArgumentException"><paramref name="roots"/> is empty or holds null.</exception>
    public static byte[] TrustAnchor(IEnumerable<X509Certificate2> roots)
    {
        X509Certificate2[] published = Certificates(roots, nameof(roots));

        return Write(writer =>
        {
            writer.WriteStartArray("roots");

            foreach (X509Certificate2 root in published)
            {
                ReadOnlySpan<byte> der = root.RawDataMemory.Span;

                writer.WriteStartObject();
                writer.WriteBase64String("certificate", der);
                writer.WriteString("thumbprint", AgentIdentityProtocol.ComputeThumbprint(der));
                writer.WriteString("not_before", Timestamp(root.NotBefore));
                writer.WriteString("not_after", Timestamp(root.NotAfter));
                writer.WriteEndObject();
            }

            writer.WriteEndArray();
        });
    }

    /// <summary>
    /// Writes the body of an <c>enroll</c> response, for a new identity or a replay:
    /// <c>authority_id</c>, <c>identity_id</c>, <c>certificate_chain</c> and <c>config</c>.
    /// </summary>
    /// <remarks>
    /// The IDs are written as lowercase hyphenated UUIDs.
    /// </remarks>
    /// <param name="authorityId">The authority's ID, which never changes for the authority.</param>
    /// <param name="identityId">The identity's ID.</param>
    /// <param name="certificateChain">
    /// The chain of the identity's current certificate, leaf first: each certificate after the leaf issued the one
    /// before it.
    /// </param>
    /// <param name="config">The identity's config.</param>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="certificateChain"/> or <paramref name="config"/> is null.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// An ID is the nil UUID, which stands for no ID;
    /// or <paramref name="certificateChain"/> is empty, holds null, or is not leaf first.
    /// </exception>
    public static byte[] Enroll(
        Guid authorityId,
        Guid identityId,
        IEnumerable<X509Certificate2> certificateChain,
        IdentityConfig config)
    {
        CheckId(authorityId, "authority", nameof(authorityId));
        CheckId(identityId, "identity", nameof(identityId));
        X509Certificate2[] chain = LeafFirstChain(certificateChain);
        ArgumentNullException.ThrowIfNull(config);

        return Write(writer =>
        {
            writer.WriteString("authority_id", authorityId.ToString("D"));
            writer.WriteString("identity_id", identityId.ToString("D"));
            WriteChain(writer, chain);
            WriteConfig(writer, config);
        });
    }

    /// <summary>
    /// Writes the body of a <c>renew</c> response: <c>certificate_chain</c>.
    /// </summary>
    /// <param name="certificateChain">
    /// The chain of the identity's pending certificate, leaf first: each certificate after the leaf issued the one
    /// before it.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="certificateChain"/> is null.</exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="certificateChain"/> is empty, holds null, or is not leaf first.
    /// </exception>
    public static byte[] Renew(IEnumerable<X509Certificate2> certificateChain)
    {
        X509Certificate2[] chain = LeafFirstChain(certificateChain);

        return Write(writer => WriteChain(writer, chain));
    }

    /// <summary>
    /// Writes the body of a <c>check-in</c> response: <c>config</c> and <c>renewal_requested</c>.
    /// </summary>
    /// <param name="config">The identity's config.</param>
    /// <param name="renewalRequested">
    /// The identity's request-renewal flag, which the authority sets when it wants the identity to renew.
    /// </param>
    /// <exception cref="ArgumentNullException"><paramref name="config"/> is null.</exception>
    public static byte[] CheckIn(IdentityConfig config, bool renewalRequested)
    {
        ArgumentNullException.ThrowIfNull(config);

        return Write(writer =>
        {
            WriteConfig(writer, config);
            writer.WriteBoolean("renewal_requested", renewalRequested);
        });
    }

    private static byte[] Write(Action<Utf8JsonWriter> writeMembers)
    {
        ArrayBufferWriter<byte> buffer = new();

        using (Utf8JsonWriter writer = new(buffer))
        {
            writer.WriteStartObject();
            writeMembers(writer);
            writer.WriteEndObject();
        }

        return buffer.WrittenSpan.ToArray();
    }

    // Copies the certificates, so that the checks and the body see the same ones.
    private static X509Certificate2[] Certificates(IEnumerable<X509Certificate2> certificates, string paramName)
    {
        ArgumentNullException.ThrowIfNull(certificates, paramName);
        X509Certificate2[] copy = [.. certificates];

        if (copy.Length == 0)
        {
            throw new ArgumentException("There is no certificate.", paramName);
        }

        if (copy.Any(certificate => certificate is null))
        {
            throw new ArgumentException("A certificate is null.", paramName);
        }

        return copy;
    }

    private static X509Certificate2[] LeafFirstChain(IEnumerable<X509Certificate2> certificateChain)
    {
        X509Certificate2[] chain = Certificates(certificateChain, nameof(certificateChain));

        // RFC 5280 §4.1.2.6: a CA encodes its subject exactly as the issuer of each certificate it issues,
        // so a chain in another order fails this comparison.
        for (int i = 1; i < chain.Length; i++)
        {
            if (!chain[i - 1].IssuerName.RawData.AsSpan().SequenceEqual(chain[i].SubjectName.RawData))
            {
                throw new ArgumentException(
                    $"The subject of chain certificate {i + 1} is not the issuer of certificate {i}, "
                        + "so the chain is not leaf first.",
                    nameof(certificateChain));
            }
        }

        return chain;
    }

    // RFC 9562 §5.9: the nil UUID stands for the absence of a UUID, and both IDs are required.
    private static void CheckId(Guid id, string description, string paramName)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException($"The {description} ID is the nil UUID.", paramName);
        }
    }

    private static void WriteChain(Utf8JsonWriter writer, X509Certificate2[] chain)
    {
        writer.WriteStartArray("certificate_chain");

        foreach (X509Certificate2 certificate in chain)
        {
            writer.WriteBase64StringValue(certificate.RawDataMemory.Span);
        }

        writer.WriteEndArray();
    }

    private static void WriteConfig(Utf8JsonWriter writer, IdentityConfig config)
    {
        writer.WritePropertyName("config");

        // The config wrote these bytes itself when it was created.
        writer.WriteRawValue(config.Utf8Json, skipInputValidation: true);
    }

    // X509Certificate2 gives its validity in local time.
    // UNTESTED: the conversion is exact in the hour that a daylight-saving fall-back repeats,
    // because the local DateTime that X509Certificate2 returns keeps the ambiguous-DST bit,
    // which ToUniversalTime uses.
    // A wrong instant there publishes a root's validity an hour off on hosts outside UTC.
    // Keep the conversion straight from the property: arithmetic, formatting or a DateTimeOffset built from the
    // local value before ToUniversalTime loses the bit.
    private static string Timestamp(DateTime localTime)
    {
        return AgentIdentityProtocol.FormatTimestamp(new DateTimeOffset(localTime.ToUniversalTime()));
    }
}
