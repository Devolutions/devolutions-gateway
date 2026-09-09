using System.Buffers;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace DevolutionsAgentPolicyConsent;

internal static class BrokerClient
{
    private const string PipeName = "Devolutions.Now.PackageBroker.v1";
    private const int MaximumHeaderBytes = 64 * 1024;
    private const int MaximumBrokerResponseBytes = 50_606_928;
    private static readonly TimeSpan ConnectTimeout = TimeSpan.FromSeconds(5);

    internal static async Task<ElevationResponse> ReplaceAsync(
        ElevationRequest request,
        CancellationToken cancellationToken)
    {
        byte[] body = CreateOfficialRequest(request);
        try
        {
            using NamedPipeClientStream pipe = new(
                ".",
                PipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.WriteThrough,
                System.Security.Principal.TokenImpersonationLevel.Anonymous);

            using CancellationTokenSource connectTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectTimeout.CancelAfter(ConnectTimeout);
            await pipe.ConnectAsync(connectTimeout.Token);
            using BrokerServerLease broker = BrokerServerLease.Open(pipe.SafePipeHandle);

            byte[] headers = Encoding.ASCII.GetBytes(
                $"PUT /v1/policy HTTP/1.1\r\nHost: now-package-broker\r\nConnection: close\r\n" +
                $"Content-Type: application/json\r\nAccept: application/json\r\nContent-Length: {body.Length}\r\n\r\n");
            await pipe.WriteAsync(headers, cancellationToken);
            await pipe.WriteAsync(body, cancellationToken);
            await pipe.FlushAsync(cancellationToken);

            byte[] response = await ReadBoundedAsync(
                pipe,
                MaximumBrokerResponseBytes + MaximumHeaderBytes,
                cancellationToken);
            return ParseResponse(request.RequestId, response);
        }
        catch (OperationCanceledException)
        {
            return Unknown(request.RequestId, null, "Timeout");
        }
        catch (IOException)
        {
            return Unknown(request.RequestId, null, "BrokerUnavailable");
        }
        catch (JsonException)
        {
            return Unknown(request.RequestId, null, "InvalidResponse");
        }
        catch (BrokerResponseException error)
        {
            return Unknown(request.RequestId, error.StatusCode, "InvalidResponse");
        }
        catch (InvalidOperationException)
        {
            return Unknown(request.RequestId, null, "InvalidResponse");
        }
        catch (ProtocolException)
        {
            return Unknown(request.RequestId, null, "InvalidResponse");
        }
    }

    internal static byte[] CreateOfficialRequest(ElevationRequest request)
    {
        ArrayBufferWriter<byte> buffer = new();
        using Utf8JsonWriter writer = new(buffer);
        writer.WriteStartObject();
        writer.WriteString("RequestKind", "PolicyReplacementRequest");
        writer.WriteString("RequestVersion", "1.0");
        writer.WriteString("ExpectedStoreToken", request.ExpectedStoreToken);
        writer.WriteString("Operation", request.Operation);
        writer.WriteString("ConflictHandling", request.ConflictHandling);
        writer.WriteBoolean("WarningsAcknowledged", request.WarningsAcknowledged);
        writer.WritePropertyName("Draft");
        request.Draft.WriteTo(writer);
        writer.WriteString("ValidationReceipt", request.ValidationReceipt);
        writer.WriteEndObject();
        writer.Flush();
        if (buffer.WrittenCount > 16_777_216)
        {
            throw new ProtocolException("official policy request exceeds broker limit");
        }
        return buffer.WrittenSpan.ToArray();
    }

    internal static ElevationResponse ParseResponse(string requestId, byte[] response)
    {
        ReadOnlySpan<byte> delimiter = "\r\n\r\n"u8;
        int headerEnd = response.AsSpan().IndexOf(delimiter);
        if (headerEnd < 0 || headerEnd > MaximumHeaderBytes)
        {
            throw new BrokerResponseException(null);
        }

        string statusLine = Encoding.ASCII.GetString(response.AsSpan(0, headerEnd)).Split("\r\n", 2)[0];
        string[] statusParts = statusLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (statusParts.Length < 2 || !int.TryParse(statusParts[1], out int status))
        {
            throw new BrokerResponseException(null);
        }

        ReadOnlyMemory<byte> body = response.AsMemory(headerEnd + delimiter.Length);
        if (body.IsEmpty)
        {
            return Unknown(requestId, status, "EmptyResponse");
        }

        try
        {
            return ParseResponseBody(requestId, status, body);
        }
        catch (Exception error) when (error is JsonException or InvalidOperationException or ProtocolException)
        {
            throw new BrokerResponseException(status, error);
        }
    }

    private static ElevationResponse ParseResponseBody(
        string requestId,
        int status,
        ReadOnlyMemory<byte> body)
    {
        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement payload = document.RootElement;
        if (status is >= 200 and <= 299)
        {
            RequireString(payload, "ResponseKind", "PolicyReplacementResponse");
            RequireString(payload, "ResponseVersion", "1.0");
            string token = RequireNestedString(payload, "Management", "StoreToken");
            ElevationResponse committed = new(
                Protocol.Version,
                requestId,
                "Committed",
                null,
                null,
                token,
                null,
                null,
                null);
            Protocol.ValidateResponse(committed);
            return committed;
        }

        RequireString(payload, "ResponseKind", "ErrorResponse");
        RequireString(payload, "ResponseVersion", "1.0");
        string code = RequireString(payload, "Code");
        string? conflictToken = null;
        string? conflictState = null;
        string? conflictPolicyId = null;
        if (code == "StalePolicyStoreToken")
        {
            JsonElement management = RequireObject(payload, "Management");
            conflictToken = RequireString(management, "StoreToken");
            conflictState = RequireString(management, "State");
            if (conflictState == "Active")
            {
                JsonElement policy = RequireObject(management, "Policy");
                JsonElement metadata = RequireObject(policy, "Metadata");
                conflictPolicyId = RequireString(metadata, "Id");
            }
        }
        ElevationResponse rejected = new(
            Protocol.Version,
            requestId,
            "Rejected",
            status,
            Truncate(code, 64),
            null,
            conflictToken,
            conflictState,
            conflictPolicyId);
        Protocol.ValidateResponse(rejected);
        return rejected;
    }

    private static void RequireString(JsonElement payload, string property, string expected)
    {
        if (!payload.TryGetProperty(property, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String ||
            value.GetString() != expected)
        {
            throw new InvalidOperationException("broker response contract mismatch");
        }
    }

    private static string RequireString(JsonElement payload, string property)
    {
        if (!payload.TryGetProperty(property, out JsonElement value) ||
            value.ValueKind != JsonValueKind.String ||
            value.GetString() is not { } result)
        {
            throw new InvalidOperationException("broker response contract mismatch");
        }
        return result;
    }

    private static string RequireNestedString(JsonElement payload, string parent, string property) =>
        RequireString(RequireObject(payload, parent), property);

    private static JsonElement RequireObject(JsonElement payload, string property)
    {
        if (!payload.TryGetProperty(property, out JsonElement value) ||
            value.ValueKind != JsonValueKind.Object)
        {
            throw new InvalidOperationException("broker response contract mismatch");
        }
        return value;
    }

    private static async Task<byte[]> ReadBoundedAsync(Stream stream, int maximum, CancellationToken cancellationToken)
    {
        using MemoryStream response = new();
        byte[] buffer = new byte[16 * 1024];
        while (true)
        {
            int read = await stream.ReadAsync(buffer, cancellationToken);
            if (read == 0)
            {
                return response.ToArray();
            }
            if (response.Length + read > maximum)
            {
                throw new InvalidOperationException("broker response exceeds limit");
            }
            response.Write(buffer, 0, read);
        }
    }

    private static ElevationResponse Unknown(string requestId, int? statusCode, string errorCode) =>
        new(Protocol.Version, requestId, "Unknown", statusCode, errorCode, null, null, null, null);

    private static string Truncate(string value, int maximum) =>
        value.Length <= maximum ? value : value[..maximum];

    private sealed class BrokerResponseException(int? statusCode, Exception? innerException = null)
        : Exception("broker response contract mismatch", innerException)
    {
        internal int? StatusCode { get; } = statusCode;
    }
}
