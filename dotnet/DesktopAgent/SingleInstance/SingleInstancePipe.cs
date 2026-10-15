using System;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading.Tasks;

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

        /// <summary>
        /// Waits for <paramref name="task"/> to complete, or calls <paramref name="abort"/> and returns false on timeout.
        /// </summary>
        public static bool Wait(Task task, Action abort)
        {
            IAsyncResult result = task;

            if (result.AsyncWaitHandle.WaitOne(IoTimeoutMs))
            {
                return true;
            }

            abort();

            // Let the aborted I/O complete so the pipe is idle before it is reused or closed.
            result.AsyncWaitHandle.WaitOne(IoTimeoutMs);
            task.ContinueWith(t => _ = t.Exception, TaskContinuationOptions.OnlyOnFaulted | TaskContinuationOptions.ExecuteSynchronously);

            return false;
        }

        /// <summary>
        /// Forwards <paramref name="args"/> to the running instance of the same user in the same session.
        /// </summary>
        /// <returns>True if the running instance acknowledged the arguments.</returns>
        public static bool Forward(ProcessIdentity identity, string[] args, Logger log)
        {
            string pipeName = Name(identity);

            using NamedPipeClientStream pipe = new(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous, TokenImpersonationLevel.Identification);

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

            Task<int> exchange = Task.Run(() =>
            {
                Protocol.WriteMessage(pipe, args);
                return pipe.ReadByte();
            });

            if (!Wait(exchange, pipe.Dispose))
            {
                log.Warn($"Timed out forwarding arguments to process {serverProcessId}");
                return false;
            }

            if (exchange.GetAwaiter().GetResult() != Protocol.Ack)
            {
                log.Warn($"Process {serverProcessId} did not acknowledge forwarded arguments");
                return false;
            }

            return true;
        }
    }
}
