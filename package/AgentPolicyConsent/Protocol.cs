using System.Buffers.Binary;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DevolutionsAgentPolicyConsent;

internal static class Protocol
{
    internal const string Version = PolicyConsentContract.ProtocolVersion;
    internal const string PipePrefix = "UniGetUI.PolicyElevation.";
    internal const int MaxRequestBodyBytes = 16_793_054;
    internal const int MaxResponseBodyBytes = 15_618;
    internal static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(45);
    internal static readonly TimeSpan ExchangeTimeout = TimeSpan.FromMinutes(2);
    internal static readonly TimeSpan ResponseWriteTimeout = TimeSpan.FromSeconds(10);

    internal static Arguments ParseArguments(string[] args)
    {
        if (args.Length != 10)
        {
            throw new ProtocolException("invalid argument count");
        }

        Dictionary<string, string> values = new(StringComparer.Ordinal);
        for (int index = 0; index < args.Length; index += 2)
        {
            if (!values.TryAdd(args[index], args[index + 1]))
            {
                throw new ProtocolException("duplicate argument");
            }
        }

        string protocol = Required(values, "--protocol");
        string pipe = Required(values, "--pipe");
        if (protocol != Version ||
            !pipe.StartsWith(PipePrefix, StringComparison.Ordinal) ||
            !IsLowerHex(pipe.AsSpan(PipePrefix.Length), 32) ||
            !int.TryParse(
                Required(values, "--parent-pid"),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out int parentPid) ||
            parentPid <= 0 ||
            !long.TryParse(
                Required(values, "--parent-created"),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out long parentCreated) ||
            parentCreated <= 0 ||
            !uint.TryParse(
                Required(values, "--session"),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out uint session) ||
            values.Count != 5)
        {
            throw new ProtocolException("invalid argument value");
        }

        return new Arguments(pipe, parentPid, parentCreated, session);
    }

    internal static void ValidateRequest(ElevationRequest request)
    {
        if (request.ProtocolVersion != Version ||
            !IsLowerHex(request.RequestId.AsSpan(), 32) ||
            request.Operation is not ("Update" or "ReplaceIdentity" or "Create" or "Repair") ||
            request.ConflictHandling is not ("Reject" or "ConfirmOverwrite") ||
            !IsCredential(request.ExpectedStoreToken, 512) ||
            !IsCredential(request.ValidationReceipt, 2048) ||
            request.Draft.ValueKind != JsonValueKind.Object)
        {
            throw new ProtocolException("invalid request");
        }
    }

    internal static void ValidateResponse(ElevationResponse response)
    {
        if (response.ProtocolVersion != Version ||
            !IsLowerHex(response.RequestId.AsSpan(), 32) ||
            response.Disposition is not ("Committed" or "Rejected" or "Unknown") ||
            !IsOptionalCredential(response.BrokerErrorCode, 64))
        {
            throw new ProtocolException("invalid response");
        }

        bool hasConflict =
            response.ConflictStoreToken is not null ||
            response.ConflictState is not null ||
            response.ConflictPolicyId is not null;
        switch (response.Disposition)
        {
            case "Committed" when
                response.BrokerStatusCode is null &&
                response.BrokerErrorCode is null &&
                IsCredential(response.CommittedStoreToken, 512) &&
                !hasConflict:
                return;
            case "Rejected" when
                response.CommittedStoreToken is null &&
                response.BrokerErrorCode is not null:
                ValidateConflict(response, hasConflict);
                return;
            case "Unknown" when
                response.CommittedStoreToken is null &&
                response.BrokerErrorCode is not null &&
                !hasConflict:
                return;
            default:
                throw new ProtocolException("invalid response shape");
        }
    }

    internal static async Task<byte[]> ReadFrameAsync(Stream stream, int maximum, CancellationToken cancellationToken)
    {
        byte[] header = new byte[4];
        await ReadExactlyAsync(stream, header, cancellationToken);
        uint length = BinaryPrimitives.ReadUInt32BigEndian(header);
        if (length == 0 || length > maximum)
        {
            throw new ProtocolException("invalid frame length");
        }

        byte[] body = GC.AllocateUninitializedArray<byte>(checked((int)length));
        await ReadExactlyAsync(stream, body, cancellationToken);
        return body;
    }

    internal static async Task WriteFrameAsync(
        Stream stream,
        ReadOnlyMemory<byte> body,
        int maximum,
        CancellationToken cancellationToken)
    {
        if (body.IsEmpty || body.Length > maximum)
        {
            throw new ProtocolException("invalid frame length");
        }

        byte[] header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, checked((uint)body.Length));
        await stream.WriteAsync(header, cancellationToken);
        await stream.WriteAsync(body, cancellationToken);
        await stream.FlushAsync(cancellationToken);
    }

    private static async Task ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[offset..], cancellationToken);
            if (read == 0)
            {
                throw new EndOfStreamException("unexpected end of elevation frame");
            }
            offset += read;
        }
    }

    private static string Required(Dictionary<string, string> values, string key) =>
        values.TryGetValue(key, out string? value) && value.Length != 0
            ? value
            : throw new ProtocolException("missing argument");

    private static bool IsLowerHex(ReadOnlySpan<char> value, int length) =>
        value.Length == length && value.IndexOfAnyExcept("0123456789abcdef") < 0;

    internal static bool IsCredential(string? value, int maximum) =>
        value is not null &&
        value.Length is > 0 &&
        value.Length <= maximum &&
        IsAsciiAlphaNumeric(value[0]) &&
        value.AsSpan(1).IndexOfAnyExcept("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~:-") < 0;

    private static bool IsOptionalCredential(string? value, int maximum) =>
        value is null || IsCredential(value, maximum);

    private static void ValidateConflict(ElevationResponse response, bool hasConflict)
    {
        if (response.BrokerErrorCode != "StalePolicyStoreToken")
        {
            if (hasConflict)
            {
                throw new ProtocolException("non-stale response carries conflict fields");
            }
            return;
        }

        if (!IsCredential(response.ConflictStoreToken, 512) ||
            response.ConflictState is not ("Active" or "Missing" or "Invalid") ||
            (response.ConflictState == "Active"
                ? !IsCredential(response.ConflictPolicyId, 2048)
                : response.ConflictPolicyId is not null))
        {
            throw new ProtocolException("invalid stale conflict");
        }
    }

    private static bool IsAsciiAlphaNumeric(char value) =>
        value is >= '0' and <= '9' or >= 'A' and <= 'Z' or >= 'a' and <= 'z';
}

internal sealed record Arguments(string PipeName, int ParentProcessId, long ParentCreatedUtcTicks, uint SessionId);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ElevationRequest(
    [property: JsonRequired] string ProtocolVersion,
    [property: JsonRequired] string RequestId,
    [property: JsonRequired] string Operation,
    [property: JsonRequired] string ConflictHandling,
    [property: JsonRequired] string ExpectedStoreToken,
    [property: JsonRequired] string ValidationReceipt,
    [property: JsonRequired] bool WarningsAcknowledged,
    [property: JsonRequired] JsonElement Draft);

[JsonUnmappedMemberHandling(JsonUnmappedMemberHandling.Disallow)]
internal sealed record ElevationResponse(
    [property: JsonRequired] string ProtocolVersion,
    [property: JsonRequired] string RequestId,
    [property: JsonRequired] string Disposition,
    [property: JsonRequired] int? BrokerStatusCode,
    [property: JsonRequired] string? BrokerErrorCode,
    [property: JsonRequired] string? CommittedStoreToken,
    [property: JsonRequired] string? ConflictStoreToken,
    [property: JsonRequired] string? ConflictState,
    [property: JsonRequired] string? ConflictPolicyId);

[JsonSourceGenerationOptions(
    PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase,
    PropertyNameCaseInsensitive = false,
    UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    DefaultIgnoreCondition = JsonIgnoreCondition.Never,
    GenerationMode = JsonSourceGenerationMode.Metadata)]
[JsonSerializable(typeof(ElevationRequest))]
[JsonSerializable(typeof(ElevationResponse))]
internal sealed partial class ProtocolJsonContext : JsonSerializerContext;

internal sealed class ProtocolException(string message) : Exception(message);
