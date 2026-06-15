using System.IO.Pipes;
using System.Text;
using System.Text.Json;

namespace Devolutions.UniGetUI.Broker.Client;

/// <summary>
/// Client for communicating with the Devolutions Agent UniGetUI package broker over a
/// Windows named pipe using the HTTP/1.1 wire protocol.
/// </summary>
public sealed class BrokerClient : IDisposable
{
    public const string DefaultPipeName = "UniGetUI.PackageBroker.v1";

    private const string ProtocolVersion = "1.0";
    private const string RequestMediaType = "application/vnd.unigetui.package-request+json; version=1.0";
    private const string ResponseMediaType = "application/vnd.unigetui.package-broker-response+json; version=1.0";
    private const int ConnectTimeoutMs = 5000;
    private const int ReadTimeoutMs = 30000;

    private readonly string _pipeName;

    /// <summary>Optional diagnostic sink; receives human-readable trace lines.</summary>
    public Action<string>? Trace { get; init; }

    public BrokerClient(string? pipeName = null)
    {
        _pipeName = pipeName ?? DefaultPipeName;
    }

    /// <summary>Check whether the broker is reachable (pipe exists and answers the health check).</summary>
    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await SendHttpRequestAsync("GET", "/v1/health", null, null, cancellationToken).ConfigureAwait(false);
            return response.StatusCode == 200;
        }
        catch (Exception ex)
        {
            Trace?.Invoke($"Broker not available: {ex.GetType().Name}: {ex.Message}");
            return false;
        }
    }

    /// <summary>Evaluate a package operation against policy without executing it (dry-run).</summary>
    public Task<BrokerResponse?> EvaluateAsync(PackageRequest request, CancellationToken cancellationToken = default)
        => SendPackageOperationAsync(request, "/v1/package-operations/evaluate", cancellationToken);

    /// <summary>Submit a package operation for evaluation and (if allowed) elevated execution.</summary>
    public Task<BrokerResponse?> ExecuteAsync(PackageRequest request, CancellationToken cancellationToken = default)
        => SendPackageOperationAsync(request, "/v1/package-operations/execute", cancellationToken);

    /// <summary>
    /// Submit a package operation and poll until it reaches a terminal status
    /// (<see cref="OperationStatus.Completed"/> or <see cref="OperationStatus.Failed"/>).
    /// </summary>
    public async Task<StatusResponse?> ExecuteAndWaitAsync(
        PackageRequest request,
        CancellationToken cancellationToken = default,
        int pollIntervalMs = 500)
    {
        var executeResponse = await SendPackageOperationAsync(request, "/v1/package-operations/execute", cancellationToken).ConfigureAwait(false);
        if (executeResponse is null)
        {
            Trace?.Invoke("Execute request failed, cannot poll for status.");
            return null;
        }

        if (executeResponse.Decision != Decision.Allow)
        {
            Trace?.Invoke($"Operation denied by policy: {executeResponse.Reason}");
            return new StatusResponse
            {
                RequestId = request.RequestId,
                Status = OperationStatus.Failed,
                Note = $"Denied by policy: {executeResponse.Reason}",
            };
        }

        while (!cancellationToken.IsCancellationRequested)
        {
            await Task.Delay(pollIntervalMs, cancellationToken).ConfigureAwait(false);

            var status = await QueryStatusAsync(request.RequestId, request.Broker, cancellationToken).ConfigureAwait(false);
            if (status is null)
            {
                Trace?.Invoke("Status query returned null, retrying...");
                continue;
            }

            if (status.Status is OperationStatus.Completed or OperationStatus.Failed)
            {
                return status;
            }
        }

        return new StatusResponse
        {
            RequestId = request.RequestId,
            Status = OperationStatus.Failed,
            Note = "Operation polling was cancelled.",
        };
    }

    /// <summary>Query the status of a previously submitted package operation.</summary>
    public async Task<StatusResponse?> QueryStatusAsync(
        string requestId,
        BrokerContext brokerContext,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var statusRequest = new StatusRequest
            {
                RequestId = requestId,
                Broker = brokerContext,
            };

            var body = JsonSerializer.Serialize(statusRequest, BrokerJson.Options);

            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = "application/json",
                ["Accept"] = "application/json",
                ["UniGetUI-Protocol-Version"] = ProtocolVersion,
            };

            var response = await SendHttpRequestAsync("POST", "/v1/package-operations/status", body, headers, cancellationToken).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(response.Body))
            {
                Trace?.Invoke($"Empty status response body (status {response.StatusCode}).");
                return null;
            }

            return JsonSerializer.Deserialize<StatusResponse>(response.Body, BrokerJson.Options);
        }
        catch (Exception ex)
        {
            Trace?.Invoke($"Error querying operation status: {ex.Message}");
            return null;
        }
    }

    public void Dispose()
    {
        // No persistent resources to dispose.
    }

    private async Task<BrokerResponse?> SendPackageOperationAsync(PackageRequest request, string endpoint, CancellationToken cancellationToken)
    {
        try
        {
            var body = JsonSerializer.Serialize(request, BrokerJson.Options);

            var headers = new Dictionary<string, string>
            {
                ["Content-Type"] = RequestMediaType,
                ["Accept"] = ResponseMediaType,
                ["UniGetUI-Protocol-Version"] = ProtocolVersion,
                ["UniGetUI-Request-Id"] = request.RequestId,
            };

            var response = await SendHttpRequestAsync("POST", endpoint, body, headers, cancellationToken).ConfigureAwait(false);

            if (string.IsNullOrWhiteSpace(response.Body))
            {
                Trace?.Invoke($"Empty response body from broker (status {response.StatusCode}).");
                return null;
            }

            return JsonSerializer.Deserialize<BrokerResponse>(response.Body, BrokerJson.Options);
        }
        catch (Exception ex)
        {
            Trace?.Invoke($"Error communicating with broker: {ex.Message}");
            return null;
        }
    }

    /// <summary>Send a raw HTTP/1.1 request over the named pipe and read the response.</summary>
    private async Task<HttpPipeResponse> SendHttpRequestAsync(
        string method,
        string path,
        string? body,
        Dictionary<string, string>? extraHeaders,
        CancellationToken cancellationToken)
    {
        using var pipe = new NamedPipeClientStream(".", _pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

        using (var connectCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken))
        {
            connectCts.CancelAfter(ConnectTimeoutMs);
            await pipe.ConnectAsync(connectCts.Token).ConfigureAwait(false);
        }

        var requestBuilder = new StringBuilder();
        requestBuilder.Append($"{method} {path} HTTP/1.1\r\n");
        requestBuilder.Append("Host: unigetui-broker\r\n");
        requestBuilder.Append("Connection: close\r\n");

        if (extraHeaders is not null)
        {
            foreach (var (key, value) in extraHeaders)
            {
                if (!key.Equals("Host", StringComparison.OrdinalIgnoreCase))
                {
                    requestBuilder.Append($"{key}: {value}\r\n");
                }
            }
        }

        byte[]? bodyBytes = body is not null ? Encoding.UTF8.GetBytes(body) : null;
        requestBuilder.Append($"Content-Length: {bodyBytes?.Length ?? 0}\r\n");
        requestBuilder.Append("\r\n");

        var headerBytes = Encoding.ASCII.GetBytes(requestBuilder.ToString());
        await pipe.WriteAsync(headerBytes, cancellationToken).ConfigureAwait(false);
        if (bodyBytes is not null)
        {
            await pipe.WriteAsync(bodyBytes, cancellationToken).ConfigureAwait(false);
        }
        await pipe.FlushAsync(cancellationToken).ConfigureAwait(false);

        using var readCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        readCts.CancelAfter(ReadTimeoutMs);
        return await ReadHttpResponseAsync(pipe, readCts.Token).ConfigureAwait(false);
    }

    /// <summary>Parse an HTTP/1.1 response from the pipe stream.</summary>
    private static async Task<HttpPipeResponse> ReadHttpResponseAsync(Stream stream, CancellationToken ct)
    {
        var buffer = new byte[65536];
        var totalRead = 0;

        while (totalRead < buffer.Length)
        {
            var bytesRead = await stream.ReadAsync(buffer.AsMemory(totalRead, buffer.Length - totalRead), ct).ConfigureAwait(false);
            if (bytesRead == 0)
            {
                break;
            }
            totalRead += bytesRead;

            var currentText = Encoding.ASCII.GetString(buffer, 0, totalRead);
            var headerEnd = currentText.IndexOf("\r\n\r\n", StringComparison.Ordinal);
            if (headerEnd < 0)
            {
                continue;
            }

            var headerText = currentText[..headerEnd];
            var bodyStart = headerEnd + 4;

            var lines = headerText.Split("\r\n");
            var statusCode = int.Parse(lines[0].Split(' ')[1]);

            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            for (var i = 1; i < lines.Length; i++)
            {
                var colonIdx = lines[i].IndexOf(':');
                if (colonIdx > 0)
                {
                    headers[lines[i][..colonIdx].Trim()] = lines[i][(colonIdx + 1)..].Trim();
                }
            }

            var contentLength = 0;
            if (headers.TryGetValue("Content-Length", out var clStr))
            {
                contentLength = int.Parse(clStr);
            }

            var bodyBytesRead = totalRead - bodyStart;
            while (bodyBytesRead < contentLength)
            {
                if (bodyStart + contentLength > buffer.Length)
                {
                    var newBuffer = new byte[bodyStart + contentLength];
                    Buffer.BlockCopy(buffer, 0, newBuffer, 0, totalRead);
                    buffer = newBuffer;
                }

                var read = await stream.ReadAsync(buffer.AsMemory(bodyStart + bodyBytesRead, contentLength - bodyBytesRead), ct).ConfigureAwait(false);
                if (read == 0)
                {
                    break;
                }
                bodyBytesRead += read;
                totalRead += read;
            }

            var bodyText = Encoding.UTF8.GetString(buffer, bodyStart, contentLength);
            return new HttpPipeResponse(statusCode, bodyText);
        }

        throw new InvalidOperationException("Failed to read a complete HTTP response from the pipe.");
    }

    private readonly record struct HttpPipeResponse(int StatusCode, string Body);
}
