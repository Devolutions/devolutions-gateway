using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Devolutions.Agent.Identity.Authority.Tests;

/// <summary>
/// A request to sign, described by the parts of RFC 9421 that the profile constrains.
/// </summary>
/// <remarks>
/// The signature base is built here by string formatting from RFC 9421 §2.5, never through the library,
/// so that a library bug cannot make a request agree with it.
/// Component identifiers and parameter values are written as Signature-Input and the base hold them.
/// </remarks>
internal sealed record TestRequest
{
    public const string DefaultNonce = "AAECAwQFBgcICQoLDA0ODw";

    public required AgentOperation Operation { get; init; }

    /// <summary>
    /// The key that signs, whose thumbprint <see cref="Valid"/> also writes as <c>keyid</c>.
    /// </summary>
    public required KeyVector Key { get; init; }

    public string Method { get; init; } = "POST";

    /// <summary>
    /// The serialized component identifiers, such as <c>"@method"</c>.
    /// </summary>
    public required IReadOnlyList<string> Components { get; init; }

    /// <summary>
    /// The signature parameters in order, each with its serialized value, such as <c>"renew"</c> with its quotes.
    /// </summary>
    public required IReadOnlyList<(string Key, string Value)> Parameters { get; init; }

    public byte[] Body { get; init; } = [];

    /// <summary>
    /// The <c>Content-Digest</c> field value, which is also the value of a covered <c>content-digest</c>.
    /// </summary>
    public string? ContentDigest { get; init; }

    /// <summary>
    /// The value of <c>@signature-params</c> that the signature covers, as RFC 9421 §2.3 serializes it.
    /// </summary>
    public string SignatureParams => $"({string.Join(' ', Components)}){ParametersText}";

    /// <summary>
    /// The parameters as they follow the inner list, such as <c>;created=1;expires=61</c>.
    /// </summary>
    public string ParametersText =>
        string.Concat(Parameters.Select(parameter => $";{parameter.Key}={parameter.Value}"));

    // RFC 9421 §2.5.
    public string SignatureBase
    {
        get
        {
            StringBuilder builder = new();

            foreach (string component in Components)
            {
                builder.Append(component).Append(": ").Append(ComponentValue(component)).Append('\n');
            }

            return builder.Append("\"@signature-params\": ").Append(SignatureParams).ToString();
        }
    }

    /// <summary>
    /// A request that every rule of CONTRACT.agent-identity.md §6 accepts at <paramref name="now"/>,
    /// when its key is registered.
    /// </summary>
    public static TestRequest Valid(
        AgentOperation operation,
        DateTimeOffset now,
        KeyVector? key = null,
        string nonce = DefaultNonce)
    {
        key ??= TestVectors.Instance.Key("device-a");
        long created = now.ToUnixTimeSeconds();
        bool coversBody = operation is AgentOperation.Renew or AgentOperation.CheckIn;
        byte[] body = coversBody ? Encoding.UTF8.GetBytes("{\"metadata\":{\"hostname\":\"test-host\"}}") : [];

        return new TestRequest
        {
            Operation = operation,
            Key = key,
            Components = coversBody ? ["\"@method\"", "\"content-digest\""] : ["\"@method\""],
            Parameters =
            [
                ("created", created.ToString(CultureInfo.InvariantCulture)),
                ("expires", (created + 60).ToString(CultureInfo.InvariantCulture)),
                ("nonce", $"\"{nonce}\""),
                ("keyid", $"\"{key.Thumbprint}\""),
                ("alg", "\"ecdsa-p256-sha256\""),
                ("tag", $"\"{Tag(operation)}\""),
            ],
            Body = body,
            ContentDigest = coversBody ? Sha256Digest(body) : null,
        };
    }

    // CONTRACT.agent-identity.md §6, column "tag".
    public static string Tag(AgentOperation operation)
    {
        return operation switch
        {
            AgentOperation.Renew => "renew",
            AgentOperation.Confirm => "confirm",
            AgentOperation.CheckIn => "check-in",
            AgentOperation.Connect => "connect",
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "Not an operation."),
        };
    }

    // RFC 9530 §2.
    public static string Sha256Digest(byte[] body)
    {
        return $"sha-256=:{Convert.ToBase64String(SHA256.HashData(body))}:";
    }

    /// <summary>
    /// Replaces the serialized value of a parameter, keeping its position.
    /// </summary>
    public TestRequest WithParameter(string key, string value)
    {
        return this with
        {
            Parameters = [.. Parameters.Select(parameter => parameter.Key == key ? (key, value) : parameter)],
        };
    }

    /// <summary>
    /// Signs the base with <see cref="Key"/> and returns the signature in base64.
    /// </summary>
    /// <remarks>
    /// ECDSA signing is randomized, so each call returns another valid signature.
    /// </remarks>
    public string Sign()
    {
        using ECDsa privateKey = ECDsa.Create();
        privateKey.ImportPkcs8PrivateKey(Key.PrivateKeyPkcs8, out _);

        byte[] signature = privateKey.SignData(
            Encoding.UTF8.GetBytes(SignatureBase),
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        return Convert.ToBase64String(signature);
    }

    /// <summary>
    /// Signs until the base64 signature satisfies <paramref name="condition"/>.
    /// </summary>
    public string SignUntil(Func<string, bool> condition)
    {
        for (int attempt = 0; attempt < 1000; attempt++)
        {
            string signature = Sign();
            if (condition(signature))
            {
                return signature;
            }
        }

        throw new InvalidOperationException("No signature satisfied the condition.");
    }

    /// <summary>
    /// Builds the HTTP request, with each field written as the profile expects unless a test passes its own lines.
    /// </summary>
    public SignedHttpRequest ToHttpRequest(
        IReadOnlyList<string>? signatureInput = null,
        IReadOnlyList<string>? signature = null,
        IReadOnlyList<string>? contentDigest = null)
    {
        return new SignedHttpRequest(
            Method,
            signatureInput ?? [$"sig={SignatureParams}"],
            signature ?? [$"sig=:{Sign()}:"],
            contentDigest ?? (ContentDigest is null ? [] : [ContentDigest]),
            Body);
    }

    private string ComponentValue(string identifier)
    {
        if (identifier.StartsWith("\"@method\"", StringComparison.Ordinal))
        {
            return Method;
        }

        if (identifier.StartsWith("\"content-digest\"", StringComparison.Ordinal))
        {
            return ContentDigest
                ?? throw new InvalidOperationException("The request covers content-digest without one.");
        }

        throw new InvalidOperationException($"The request covers {identifier}, which it has no value for.");
    }
}

/// <summary>
/// Alterations of canonical base64 and base64url text that keep the value a lenient decoder reads.
/// </summary>
internal static class Base64Forms
{
    private const string Base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    private const string Base64UrlAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    /// <summary>
    /// Sets a pad bit of the final quantum, which RFC 4648 §3.5 leaves to the decoder.
    /// </summary>
    public static string WithNonZeroPadBits(string canonical, bool urlSafe)
    {
        string alphabet = urlSafe ? Base64UrlAlphabet : Base64Alphabet;
        string data = canonical.TrimEnd('=');

        // Only a final quantum of one or two bytes has pad bits.
        if (data.Length % 4 == 0)
        {
            throw new ArgumentException("The value has no pad bits.", nameof(canonical));
        }

        // The lowest bit of the last character is a pad bit.
        char last = data[^1];
        char altered = alphabet[alphabet.IndexOf(last, StringComparison.Ordinal) ^ 1];

        return string.Concat(data.AsSpan(0, data.Length - 1), [altered], canonical.AsSpan(data.Length));
    }

    public static string ToBase64UrlAlphabet(string base64)
    {
        return base64.Replace('+', '-').Replace('/', '_');
    }

    public static string ToBase64Alphabet(string base64Url)
    {
        return base64Url.Replace('-', '+').Replace('_', '/');
    }

    public static string Base64Url(byte[] bytes)
    {
        return ToBase64UrlAlphabet(Convert.ToBase64String(bytes)).TrimEnd('=');
    }
}
