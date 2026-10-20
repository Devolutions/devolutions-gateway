using System.Diagnostics.CodeAnalysis;
using System.Text.Json;

namespace Devolutions.AgentIdentity;

/// <summary>
/// Reads the JSON request bodies with one set of rules,
/// so that every endpoint classifies a body, its CSR and its metadata the same way.
/// </summary>
internal static class RequestBodyReader
{
    public static RequestBodyParseResult<TBody> ReadCsrAndMetadata<TBody>(
        ReadOnlySpan<byte> utf8Json,
        Func<CertificateSigningRequest, AgentMetadata, TBody> create)
        where TBody : class
    {
        if (!TryRead(
            utf8Json,
            readsCsr: true,
            out CertificateSigningRequest? csr,
            out AgentMetadata? metadata,
            out string? failure))
        {
            return RequestBodyParseResult<TBody>.Failure(failure);
        }

        // A successful read with readsCsr set always yields a CSR.
        return RequestBodyParseResult<TBody>.Success(create(csr!, metadata));
    }

    public static RequestBodyParseResult<TBody> ReadMetadata<TBody>(
        ReadOnlySpan<byte> utf8Json,
        Func<AgentMetadata, TBody> create)
        where TBody : class
    {
        if (!TryRead(utf8Json, readsCsr: false, out _, out AgentMetadata? metadata, out string? failure))
        {
            return RequestBodyParseResult<TBody>.Failure(failure);
        }

        return RequestBodyParseResult<TBody>.Success(create(metadata));
    }

    private static bool TryRead(
        ReadOnlySpan<byte> utf8Json,
        bool readsCsr,
        out CertificateSigningRequest? csr,
        [NotNullWhen(true)] out AgentMetadata? metadata,
        [NotNullWhen(false)] out string? failure)
    {
        csr = null;
        metadata = null;

        failure = CheckJson(utf8Json);
        if (failure is not null)
        {
            return false;
        }

        // The check read the same bytes under the same default options, so parsing them succeeds.
        using JsonDocument document = JsonDocument.Parse(utf8Json.ToArray());
        JsonElement body = document.RootElement;

        if (body.ValueKind != JsonValueKind.Object)
        {
            failure = "The body is not a JSON object.";
            return false;
        }

        if (readsCsr && !TryReadCsr(body, out csr, out failure))
        {
            return false;
        }

        return TryReadMetadata(body, out metadata, out failure);
    }

    // Returns why the bytes are not one JSON text that every parser reads the same way, or null.
    // A repeated member name lets two parsers read two values (CONTRACT.md §1),
    // and so does a string that is not Unicode text (RFC 8259 §8.2).
    private static string? CheckJson(ReadOnlySpan<byte> utf8Json)
    {
        // The default options reject comments, trailing commas, content after the value and nesting beyond 64 levels.
        Utf8JsonReader reader = new(utf8Json);
        Stack<HashSet<string>> objects = new();

        try
        {
            while (reader.Read())
            {
                switch (reader.TokenType)
                {
                    case JsonTokenType.StartObject:
                        objects.Push(new HashSet<string>(StringComparer.Ordinal));
                        break;

                    case JsonTokenType.EndObject:
                        objects.Pop();
                        break;

                    case JsonTokenType.PropertyName:
                        // GetString unescapes the name, so names that differ only in their escapes count as repeated.
                        if (!objects.Peek().Add(reader.GetString()!))
                        {
                            return $"The body repeats a member name at byte {reader.TokenStartIndex}.";
                        }

                        break;

                    case JsonTokenType.String:
                        // The reader accepts an unpaired surrogate escape or invalid UTF-8 until a string is decoded.
                        _ = reader.GetString();
                        break;
                }
            }
        }
        catch (JsonException exception)
        {
            return $"The body is not valid JSON, at line {exception.LineNumber + 1}, "
                + $"byte {exception.BytePositionInLine + 1} of that line.";
        }
        catch (InvalidOperationException)
        {
            return $"The body holds a string that is not Unicode text at byte {reader.TokenStartIndex}.";
        }

        return null;
    }

    private static bool TryReadCsr(
        JsonElement body,
        [NotNullWhen(true)] out CertificateSigningRequest? csr,
        [NotNullWhen(false)] out string? failure)
    {
        csr = null;

        if (!body.TryGetProperty("csr", out JsonElement value) || value.ValueKind == JsonValueKind.Null)
        {
            failure = "The body has no csr.";
            return false;
        }

        if (value.ValueKind != JsonValueKind.String)
        {
            failure = "The csr is not a JSON string.";
            return false;
        }

        // CONTRACT.md §1: a base64 value in any form but its canonical one is invalid.
        if (!StrictBase64.TryDecodeBase64(value.GetString(), out byte[]? der))
        {
            failure = "The csr is not canonical base64.";
            return false;
        }

        CsrValidationResult result = CertificateSigningRequest.Validate(der);
        if (!result.Succeeded)
        {
            failure = result.FailureDetail;
            return false;
        }

        csr = result.Csr;
        failure = null;
        return true;
    }

    private static bool TryReadMetadata(
        JsonElement body,
        [NotNullWhen(true)] out AgentMetadata? metadata,
        [NotNullWhen(false)] out string? failure)
    {
        metadata = null;

        if (!body.TryGetProperty("metadata", out JsonElement value) || value.ValueKind == JsonValueKind.Null)
        {
            failure = "The body has no metadata.";
            return false;
        }

        if (value.ValueKind != JsonValueKind.Object)
        {
            failure = "The metadata is not a JSON object.";
            return false;
        }

        List<KeyValuePair<string, string>> entries = [];
        foreach (JsonProperty entry in value.EnumerateObject())
        {
            if (entry.Value.ValueKind != JsonValueKind.String)
            {
                failure = $"The value of metadata member {entries.Count + 1} is not a JSON string.";
                return false;
            }

            entries.Add(new KeyValuePair<string, string>(entry.Name, entry.Value.GetString()!));
        }

        MetadataValidationResult result = AgentMetadata.Validate(entries);
        if (!result.Succeeded)
        {
            failure = result.FailureDetail;
            return false;
        }

        metadata = result.Metadata;
        failure = null;
        return true;
    }
}
