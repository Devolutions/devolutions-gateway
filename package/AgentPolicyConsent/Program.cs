using System.IO.Pipes;
using System.Security.Principal;
using System.Text.Json;

namespace DevolutionsAgentPolicyConsent;

internal static class Program
{
    private const int Success = 0;
    private const int InvalidArguments = 10;
    private const int ConnectionFailure = 11;
    private const int PeerAuthenticationFailure = 12;
    private const int ProtocolFailure = 13;
    private const int UnexpectedFailure = 14;

    private static async Task<int> Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            return InvalidArguments;
        }

        Arguments arguments;
        try
        {
            arguments = Protocol.ParseArguments(args);
        }
        catch (ProtocolException)
        {
            return InvalidArguments;
        }

        using CancellationTokenSource handshake = new(Protocol.ConnectTimeout);
        PeerLease peer;
        try
        {
            peer = await OpenPeerAsync(arguments, handshake.Token);
        }
        catch (OperationCanceledException)
        {
            return ConnectionFailure;
        }
        catch
        {
            return PeerAuthenticationFailure;
        }

        using (peer)
        using (NamedPipeClientStream pipe = new(
            ".",
            arguments.PipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous | PipeOptions.WriteThrough,
            TokenImpersonationLevel.Anonymous))
        {
            try
            {
                await pipe.ConnectAsync(handshake.Token);
                if (!Native.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out int serverProcessId))
                {
                    return PeerAuthenticationFailure;
                }
                peer.VerifyConnectedServer(serverProcessId);
                byte[] body = await Protocol.ReadFrameAsync(pipe, Protocol.MaxRequestBodyBytes, handshake.Token);
                ElevationRequest request = JsonSerializer.Deserialize(body, ProtocolJsonContext.Default.ElevationRequest)
                    ?? throw new ProtocolException("request is null");
                Protocol.ValidateRequest(request);
                peer.VerifyConnectedServer(serverProcessId);

                using CancellationTokenSource exchange = new(Protocol.ExchangeTimeout);
                using CancellationTokenSource brokerCancellation =
                    CancellationTokenSource.CreateLinkedTokenSource(exchange.Token);
                using CancellationTokenSource monitorCancellation =
                    CancellationTokenSource.CreateLinkedTokenSource(exchange.Token);
                Task monitor = MonitorHostAsync(pipe, brokerCancellation, monitorCancellation.Token);
                ElevationResponse response = await BrokerClient.ReplaceAsync(request, brokerCancellation.Token);
                monitorCancellation.Cancel();
                await IgnoreCancellationAsync(monitor);
                Protocol.ValidateResponse(response);

                byte[] responseBody = JsonSerializer.SerializeToUtf8Bytes(
                    response,
                    ProtocolJsonContext.Default.ElevationResponse);
                using CancellationTokenSource responseWrite = new(Protocol.ResponseWriteTimeout);
                await Protocol.WriteFrameAsync(
                    pipe,
                    responseBody,
                    Protocol.MaxResponseBodyBytes,
                    responseWrite.Token);
                return Success;
            }
            catch (OperationCanceledException)
            {
                return ConnectionFailure;
            }
            catch (IOException)
            {
                return ConnectionFailure;
            }
            catch (ProtocolException)
            {
                return ProtocolFailure;
            }
            catch (JsonException)
            {
                return ProtocolFailure;
            }
            catch
            {
                return UnexpectedFailure;
            }
        }
    }

    private static async Task<PeerLease> OpenPeerAsync(Arguments arguments, CancellationToken cancellationToken)
    {
        Task<PeerLease> open = Task.Run(() => PeerLease.Open(arguments));
        try
        {
            return await open.WaitAsync(cancellationToken);
        }
        catch
        {
            _ = open.ContinueWith(
                static completed =>
                {
                    if (completed.Status == TaskStatus.RanToCompletion)
                    {
                        completed.Result.Dispose();
                    }
                    _ = completed.Exception;
                },
                CancellationToken.None,
                TaskContinuationOptions.ExecuteSynchronously,
                TaskScheduler.Default);
            throw;
        }
    }

    private static async Task MonitorHostAsync(
        Stream pipe,
        CancellationTokenSource brokerCancellation,
        CancellationToken cancellationToken)
    {
        byte[] unexpected = new byte[1];
        try
        {
            int read = await pipe.ReadAsync(unexpected, cancellationToken);
            if (read is 0 or 1)
            {
                brokerCancellation.Cancel();
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (IOException)
        {
            brokerCancellation.Cancel();
        }
    }

    private static async Task IgnoreCancellationAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
    }
}
