using System;
using System.ComponentModel;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32.SafeHandles;

namespace Devolutions.Agent.Desktop.Service
{
    /// <summary>
    /// Checks that a connected PEDM pipe is served by the Devolutions Agent service, before anything is sent to it.
    /// </summary>
    internal static class PedmServerVerifier
    {
        private const string AgentServiceName = "DevolutionsAgent";

        private const uint ScManagerConnect = 0x0001;
        private const uint ServiceQueryStatus = 0x0004;
        private const int ScStatusProcessInfo = 0;
        private const uint ServiceRunning = 4;

        /// <summary>
        /// Requires the Devolutions Agent service to be running, before the pipe is opened.
        /// A client is impersonable as soon as its connection is accepted, so it must not connect at all
        /// while the trusted server cannot be serving the pipe.
        /// </summary>
        public static void EnsureServiceRunning()
        {
            RequireAgentServiceProcessId();
        }

        private const int ConnectAttempts = 5;
        private const int ConnectTimeoutMilliseconds = 50;

        /// <summary>
        /// Connects the pipe within a bounded budget, re-checking the service before every attempt.
        /// A client is impersonable as soon as its connection is accepted, and the server prevents impersonation
        /// by not letting users create pipe instances and by holding the pipe name continuously, so the pipe must
        /// not be opened at all while the Agent service is not running: the service is checked before every
        /// attempt, and the wait per attempt is bounded.
        /// </summary>
        public static async Task ConnectAsync(NamedPipeClientStream pipe, CancellationToken cancellationToken)
        {
            for (int attempt = 1; ; attempt++)
            {
                EnsureServiceRunning();

                try
                {
                    await pipe.ConnectAsync(ConnectTimeoutMilliseconds, cancellationToken).ConfigureAwait(false);
                    return;
                }
                catch (TimeoutException) when (attempt < ConnectAttempts)
                {
                    // The pipe may appear shortly; retry while the service is running.
                }
            }
        }

        /// <summary>
        /// Requires the pipe to be owned by SYSTEM or Administrators, which a standard user cannot assign,
        /// and its server to be the Devolutions Agent service process.
        /// A pipe instance shares the security descriptor of its name, so the owner alone does not identify the server.
        /// These checks run after the connection is accepted, so they cannot by themselves prevent impersonation:
        /// the server prevents it by not letting users create pipe instances and by holding the pipe name
        /// continuously, and <see cref="EnsureServiceRunning"/> must run before the pipe is opened.
        /// </summary>
        public static void Verify(NamedPipeClientStream pipe)
        {
            var owner = pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;

            if (owner is null
                || !(owner.IsWellKnown(WellKnownSidType.LocalSystemSid) || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)))
            {
                throw new UnauthorizedAccessException("The PEDM pipe server is not trusted because the pipe is not owned by SYSTEM or Administrators.");
            }

            if (!GetNamedPipeServerProcessId(pipe.SafePipeHandle, out uint serverProcessId))
            {
                throw new UnauthorizedAccessException("The PEDM pipe server is not trusted because its process could not be identified.", new Win32Exception());
            }

            uint serviceProcessId = RequireAgentServiceProcessId();

            if (serverProcessId != serviceProcessId)
            {
                throw new UnauthorizedAccessException($"The PEDM pipe server is not trusted because it is not the {AgentServiceName} service process.");
            }
        }

        private static uint RequireAgentServiceProcessId()
        {
            return GetServiceProcessId(AgentServiceName);
        }

        private static uint GetServiceProcessId(string serviceName)
        {
            IntPtr manager = OpenSCManagerW(null, null, ScManagerConnect);

            if (manager == IntPtr.Zero)
            {
                throw new UnauthorizedAccessException("The PEDM pipe server is not trusted because the service control manager could not be queried.", new Win32Exception());
            }

            try
            {
                IntPtr service = OpenServiceW(manager, serviceName, ServiceQueryStatus);

                if (service == IntPtr.Zero)
                {
                    throw new UnauthorizedAccessException($"The PEDM pipe server is not trusted because the {serviceName} service could not be opened.", new Win32Exception());
                }

                try
                {
                    if (!QueryServiceStatusEx(service, ScStatusProcessInfo, out ServiceStatusProcess status, Marshal.SizeOf(typeof(ServiceStatusProcess)), out _))
                    {
                        throw new UnauthorizedAccessException($"The PEDM pipe server is not trusted because the {serviceName} service status could not be queried.", new Win32Exception());
                    }

                    if (status.CurrentState != ServiceRunning || status.ProcessId == 0)
                    {
                        throw new UnauthorizedAccessException($"The PEDM pipe server is not trusted because the {serviceName} service is not running.");
                    }

                    return status.ProcessId;
                }
                finally
                {
                    CloseServiceHandle(service);
                }
            }
            finally
            {
                CloseServiceHandle(manager);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ServiceStatusProcess
        {
            public uint ServiceType;
            public uint CurrentState;
            public uint ControlsAccepted;
            public uint Win32ExitCode;
            public uint ServiceSpecificExitCode;
            public uint CheckPoint;
            public uint WaitHint;
            public uint ProcessId;
            public uint ServiceFlags;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint serverProcessId);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenSCManagerW(string machineName, string databaseName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr OpenServiceW(IntPtr serviceManager, string serviceName, uint desiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool QueryServiceStatusEx(IntPtr service, int infoLevel, out ServiceStatusProcess buffer, int bufferSize, out int bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseServiceHandle(IntPtr handle);
    }
}