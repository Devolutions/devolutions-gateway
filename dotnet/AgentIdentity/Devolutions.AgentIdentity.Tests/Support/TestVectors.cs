using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The shared vectors of <c>docs/agent-identity/test-vectors.json</c>, which the test project copies into its output.
/// </summary>
/// <remarks>
/// The BCL decodes the byte strings, never the library under test,
/// so that a decoding bug in the library cannot make a vector agree with it.
/// Loading fails on a missing or unknown member,
/// so that a change to the file that the loader does not model is noticed rather than ignored.
/// Unix-second timestamps are read as <see cref="DateTimeOffset"/>.
/// </remarks>
public sealed record TestVectors(
    int Version,
    string Description,
    string Evaluation,
    IReadOnlyList<KeyVector> Keys,
    RootVector Root,
    IReadOnlyDictionary<string, CsrVector> Csr,
    HttpSignatureVectors HttpSignature,
    ChannelProofVectors ChannelProof,
    [property: JsonPropertyName("rfc9421_b_2_4")] Rfc9421Vector Rfc9421B24)
{
    private const int SupportedVersion = 1;

    private static readonly Lazy<TestVectors> s_instance = new(Load);

    public static TestVectors Instance => s_instance.Value;

    public KeyVector Key(string name)
    {
        return Keys.Single(key => key.Name == name);
    }

    private static TestVectors Load()
    {
        JsonSerializerOptions options = new()
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
            RespectNullableAnnotations = true,
            RespectRequiredConstructorParameters = true,
            Converters = { new UnixSecondsConverter() },
        };

        using FileStream file = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "test-vectors.json"));
        TestVectors vectors = JsonSerializer.Deserialize<TestVectors>(file, options)
            ?? throw new InvalidDataException("The vector file holds null.");

        if (vectors.Version != SupportedVersion)
        {
            throw new InvalidDataException(
                $"The loader reads version {SupportedVersion} of the vector file, not version {vectors.Version}.");
        }

        return vectors;
    }
}

public sealed record KeyVector(
    string Name,
    Guid IdentityId,
    byte[] PrivateKeyPkcs8,
    byte[] PublicKeySec1,
    byte[] Certificate,
    string Thumbprint);

public sealed record RootVector(byte[] Certificate, string Thumbprint, byte[] PublicKeySec1);

public sealed record CsrVector(
    byte[] Csr,
    string Expected,
    string? Description = null,
    byte[]? PublicKeySec1 = null,
    byte[]? PrivateKeyPkcs8 = null);

public sealed record HttpSignatureVectors(
    IReadOnlyList<RegisteredCertificateVector> Registered,
    IReadOnlyList<HttpSignatureCaseVector> Cases,
    IReadOnlyList<HttpSignatureSequenceVector> Sequences)
{
    public RegisteredCertificateVector RegisteredCertificate(string name)
    {
        return Registered.Single(registered => registered.Name == name);
    }

    public HttpSignatureCaseVector Case(string name)
    {
        return Cases.Single(c => c.Name == name);
    }

    public HttpSignatureSequenceVector Sequence(string name)
    {
        return Sequences.Single(sequence => sequence.Name == name);
    }
}

public sealed record RegisteredCertificateVector(
    string Name,
    Guid IdentityId,
    [property: JsonPropertyName("keyid")] string KeyId,
    byte[] PublicKeySec1,
    byte[] Certificate,
    string CertificateStatus,
    bool IdentityRevoked,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter);

/// <param name="Expected"><c>ok</c> or the wire value of an error code.</param>
/// <param name="Body">The request body as JSON text, absent for operations without one.</param>
public sealed record HttpSignatureCaseVector(
    string Name,
    string Description,
    string Endpoint,
    string Method,
    DateTimeOffset Now,
    HttpSignatureHeaders Headers,
    string SignatureBase,
    string Expected,
    string? Body = null)
{
    // The vector's content digest covers the UTF-8 encoding of the body text.
    public byte[] BodyBytes => Body is null ? [] : Encoding.UTF8.GetBytes(Body);
}

/// <summary>
/// The fields of a request, each a single field line; an absent field is null.
/// </summary>
/// <param name="ContentType">A field that the signature profile does not cover.</param>
public sealed record HttpSignatureHeaders(
    [property: JsonPropertyName("signature-input")] string? SignatureInput = null,
    [property: JsonPropertyName("signature")] string? Signature = null,
    [property: JsonPropertyName("content-digest")] string? ContentDigest = null,
    [property: JsonPropertyName("content-type")] string? ContentType = null);

/// <param name="Steps">Names of cases to run in order against one nonce store.</param>
/// <param name="Expected">The outcome of each step, as in <see cref="HttpSignatureCaseVector.Expected"/>.</param>
public sealed record HttpSignatureSequenceVector(
    string Name,
    string Description,
    IReadOnlyList<string> Steps,
    IReadOnlyList<string> Expected);

/// <param name="ConnectNonce">
/// The <c>nonce</c> parameter of the opening request, whose UTF-8 bytes end the proof input.
/// </param>
/// <param name="Message">The proof input that the valid proof signs.</param>
public sealed record ChannelProofVectors(
    string Description,
    string Device,
    byte[] PublicKeySec1,
    byte[] Challenge,
    string ConnectNonce,
    string ConnectCase,
    [property: JsonPropertyName("message_hex"), JsonConverter(typeof(HexConverter))] byte[] Message,
    IReadOnlyList<ChannelProofCaseVector> Cases)
{
    public ChannelProofCaseVector Case(string name)
    {
        return Cases.Single(c => c.Name == name);
    }
}

public sealed record ChannelProofCaseVector(string Name, string Description, byte[] Proof, bool ExpectedValid);

public sealed record Rfc9421Vector(
    string Description,
    byte[] PublicKeySpki,
    string SignatureBase,
    byte[] Signature,
    bool ExpectedValid);

internal sealed class UnixSecondsConverter : JsonConverter<DateTimeOffset>
{
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return DateTimeOffset.FromUnixTimeSeconds(reader.GetInt64());
    }

    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
    {
        writer.WriteNumberValue(value.ToUnixTimeSeconds());
    }
}

internal sealed class HexConverter : JsonConverter<byte[]>
{
    public override byte[] Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        return Convert.FromHexString(reader.GetString() ?? throw new JsonException("Expected a hexadecimal string."));
    }

    public override void Write(Utf8JsonWriter writer, byte[] value, JsonSerializerOptions options)
    {
        writer.WriteStringValue(Convert.ToHexStringLower(value));
    }
}
