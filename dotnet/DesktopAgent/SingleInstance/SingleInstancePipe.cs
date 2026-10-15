using System;
using System.ComponentModel;
using System.IO;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Devolutions.Agent.Desktop.SingleInstance
{
    internal static class SingleInstancePipe
    {
        public const int ConnectTimeoutMs = 2000;

        public const int IoTimeoutMs = 5000;

        /// <summary>
        /// Pipe name scoped to one user in one session.
        /// </summary>
        public static string Name(ProcessIdentity identity) => $"Devolutions.Agent.Desktop.{identity.User.Value}.{identity.SessionId}";

        public static DateTime Deadline() => DateTime.UtcNow.AddMilliseconds(IoTimeoutMs);

        /// <summary>
        /// Reads from an asynchronous pipe, or throws <see cref="TimeoutException"/> once the read is cancelled and completed.
        /// </summary>
        public static int Read(PipeStream pipe, byte[] buffer, int offset, int count, DateTime deadline)
        {
            IAsyncResult result = pipe.BeginRead(buffer, offset, count, null, null);

            return Complete(pipe, result, pipe.EndRead, deadline);
        }

        /// <summary>
        /// Writes to an asynchronous pipe, or throws <see cref="TimeoutException"/> once the write is cancelled and completed.
        /// </summary>
        public static void Write(PipeStream pipe, byte[] buffer, DateTime deadline)
        {
            IAsyncResult result = pipe.BeginWrite(buffer, 0, buffer.Length, null, null);

            Complete(pipe, result, r =>
            {
                pipe.EndWrite(r);
                return 0;
            }, deadline);
        }

        /// <summary>
        /// Forwards <paramref name="args"/> to the running instance of the same user in the same session.
        /// </summary>
        /// <returns>True if the running instance acknowledged the arguments.</returns>
        public static bool Forward(ProcessIdentity identity, string[] args, Logger log)
        {
            string pipeName = Name(identity);

            using NamedPipeClientStream pipe = new(".", pipeName, PipeAccessRights.ReadData | PipeAccessRights.WriteData,
                PipeOptions.Asynchronous, TokenImpersonationLevel.Identification, HandleInheritability.None);

            try
            {
                pipe.Connect(ConnectTimeoutMs);
            }
            catch (TimeoutException)
            {
                log.Warn($"Timed out connecting to single-instance pipe {pipeName}");
                return false;
            }

            if (!NativeMethods.GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint serverProcessId))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            ProcessIdentity server = ProcessIdentity.FromProcessId(serverProcessId);

            if (!identity.Matches(server))
            {
                log.Warn($"Refusing to forward arguments: pipe {pipeName} is served by unexpected process {serverProcessId} ({server})");
                return false;
            }

            DateTime deadline = Deadline();
            byte[] ack = new byte[1];

            try
            {
                Write(pipe, Protocol.Encode(args), deadline);

                if (Read(pipe, ack, 0, 1, deadline) != 1 || ack[0] != Protocol.Ack)
                {
                    log.Warn($"Process {serverProcessId} did not acknowledge forwarded arguments");
                    return false;
                }
            }
            catch (TimeoutException)
            {
                log.Warn($"Timed out forwarding arguments to process {serverProcessId}");
                return false;
            }

            return true;
        }

        private static T Complete<T>(PipeStream pipe, IAsyncResult result, Func<IAsyncResult, T> end, DateTime deadline)
        {
            TimeSpan remaining = deadline - DateTime.UtcNow;

            if (result.AsyncWaitHandle.WaitOne(remaining > TimeSpan.Zero ? remaining : TimeSpan.Zero))
            {
                return end(result);
            }

            NativeMethods.CancelIoEx(pipe.SafePipeHandle, IntPtr.Zero);

            // Wait for the cancelled operation so that no I/O is pending when the pipe is reused or closed.
            try
            {
                end(result);
            }
            catch (Exception e) when (e is IOException || e is OperationCanceledException)
            {
                // Expected for a cancelled operation.
            }

            throw new TimeoutException("pipe operation timed out");
        }
    }
}
