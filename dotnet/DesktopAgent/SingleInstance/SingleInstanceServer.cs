using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Devolutions.Agent.Desktop.SingleInstance
{
    /// <summary>
    /// Receives arguments forwarded by later launches of the same user in the same session.
    /// </summary>
    internal sealed class SingleInstanceServer : IDisposable
    {
        private const int MaxConsecutiveFailures = 5;

        private readonly ProcessIdentity identity;

        private readonly Action<string[]> dispatch;

        private readonly Logger log;

        private readonly NamedPipeServerStream pipe;

        private volatile bool disposed;

        private SingleInstanceServer(NamedPipeServerStream pipe, ProcessIdentity identity, Action<string[]> dispatch, Logger log)
        {
            this.pipe = pipe;
            this.identity = identity;
            this.dispatch = dispatch;
            this.log = log;
        }

        /// <summary>
        /// Creates the pipe and starts listening, or returns null if the pipe cannot be created.
        /// </summary>
        public static SingleInstanceServer TryStart(ProcessIdentity identity, Action<string[]> dispatch, Logger log)
        {
            string pipeName = SingleInstancePipe.Name(identity);
            SafePipeHandle handle;

            try
            {
                handle = CreatePipe(pipeName, identity);
            }
            catch (Exception e)
            {
                log.Warn($"Failed to create single-instance pipe {pipeName}; arguments from later launches will be ignored: {e.Message}");
                return null;
            }

            NamedPipeServerStream pipe;

            try
            {
                pipe = new NamedPipeServerStream(PipeDirection.InOut, isAsync: true, isConnected: false, handle);
            }
            catch
            {
                handle.Dispose();
                throw;
            }

            SingleInstanceServer server = new(pipe, identity, dispatch, log);

            Thread thread = new(server.Run)
            {
                IsBackground = true,
                Name = "SingleInstanceServer",
            };
            thread.Start();

            return server;
        }

        public void Dispose()
        {
            this.disposed = true;
            this.pipe.Dispose();
        }

        private static SafePipeHandle CreatePipe(string pipeName, ProcessIdentity identity)
        {
            // Only the current user may open the pipe, and nobody is granted FILE_CREATE_PIPE_INSTANCE.
            PipeSecurity security = new();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new PipeAccessRule(identity.User, PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize, AccessControlType.Allow));

            byte[] securityDescriptor = security.GetSecurityDescriptorBinaryForm();
            GCHandle pinned = GCHandle.Alloc(securityDescriptor, GCHandleType.Pinned);

            try
            {
                NativeMethods.SECURITY_ATTRIBUTES attributes = new()
                {
                    nLength = Marshal.SizeOf<NativeMethods.SECURITY_ATTRIBUTES>(),
                    lpSecurityDescriptor = pinned.AddrOfPinnedObject(),
                    bInheritHandle = 0,
                };

                // FILE_FLAG_FIRST_PIPE_INSTANCE makes creation fail if any pipe with this name already exists.
                SafePipeHandle handle = NativeMethods.CreateNamedPipe(
                    $@"\\.\pipe\{pipeName}",
                    NativeMethods.PIPE_ACCESS_DUPLEX | NativeMethods.FILE_FLAG_FIRST_PIPE_INSTANCE | NativeMethods.FILE_FLAG_OVERLAPPED,
                    NativeMethods.PIPE_TYPE_BYTE | NativeMethods.PIPE_READMODE_BYTE | NativeMethods.PIPE_WAIT | NativeMethods.PIPE_REJECT_REMOTE_CLIENTS,
                    1,
                    4096,
                    4096,
                    0,
                    ref attributes);

                if (handle.IsInvalid)
                {
                    int error = Marshal.GetLastWin32Error();
                    handle.Dispose();
                    throw new Win32Exception(error);
                }

                return handle;
            }
            finally
            {
                pinned.Free();
            }
        }

        private void Run()
        {
            int consecutiveFailures = 0;

            // The single pipe instance is reused for every connection so that the name is never released while running.
            while (!this.disposed)
            {
                try
                {
                    this.pipe.WaitForConnection();
                }
                catch (Exception e) when (e is IOException || e is InvalidOperationException)
                {
                    if (this.disposed)
                    {
                        return;
                    }

                    // The client may have disconnected before the connection was accepted.
                    this.ResetConnection();

                    if (++consecutiveFailures >= MaxConsecutiveFailures)
                    {
                        this.log.Error($"Stopping single-instance server after repeated failures: {e}");
                        return;
                    }

                    continue;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }

                consecutiveFailures = 0;

                try
                {
                    this.HandleConnection();
                }
                catch (Exception e)
                {
                    if (this.disposed)
                    {
                        return;
                    }

                    this.log.Error($"Failed to handle single-instance connection: {e}");
                }

                try
                {
                    this.pipe.Disconnect();
                }
                catch (Exception e)
                {
                    if (this.disposed)
                    {
                        return;
                    }

                    this.log.Error($"Failed to disconnect single-instance client: {e}");
                    this.ResetConnection();
                }
            }
        }

        private void ResetConnection()
        {
            try
            {
                NativeMethods.DisconnectNamedPipe(this.pipe.SafePipeHandle);
            }
            catch (ObjectDisposedException)
            {
                // The server is shutting down.
            }
        }

        private void HandleConnection()
        {
            if (!NativeMethods.GetNamedPipeClientProcessId(this.pipe.SafePipeHandle, out uint clientProcessId))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            ProcessIdentity client = ProcessIdentity.FromProcessId(clientProcessId);

            if (!this.identity.Matches(client))
            {
                this.log.Warn($"Rejected single-instance connection from process {clientProcessId} ({client})");
                return;
            }

            Task<string[]> read = Task.Run(() => Protocol.ReadMessage(this.pipe));

            if (!SingleInstancePipe.Wait(read, () => NativeMethods.CancelIoEx(this.pipe.SafePipeHandle, IntPtr.Zero)))
            {
                this.log.Warn($"Timed out reading from single-instance client {clientProcessId}");
                return;
            }

            string[] args = read.GetAwaiter().GetResult();

            this.pipe.WriteByte(Protocol.Ack);
            this.pipe.Flush();

            this.dispatch(args);

            // Disconnecting discards unread data, so let the client read the acknowledgement and close its end first.
            Task<int> close = Task.Run(() => this.pipe.ReadByte());
            SingleInstancePipe.Wait(close, () => NativeMethods.CancelIoEx(this.pipe.SafePipeHandle, IntPtr.Zero));
        }
    }
}
