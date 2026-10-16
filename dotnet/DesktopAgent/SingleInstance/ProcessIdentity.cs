using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace Devolutions.Agent.Desktop.SingleInstance
{
    /// <summary>
    /// User, session and executable of a process, used to authenticate the other end of the single-instance pipe.
    /// </summary>
    internal sealed class ProcessIdentity
    {
        public ProcessIdentity(SecurityIdentifier user, int sessionId, string imagePath)
        {
            this.User = user ?? throw new ArgumentNullException(nameof(user));
            this.SessionId = sessionId;
            this.ImagePath = imagePath ?? throw new ArgumentNullException(nameof(imagePath));
        }

        public SecurityIdentifier User { get; }

        public int SessionId { get; }

        public string ImagePath { get; }

        public static ProcessIdentity Current() => FromProcessId((uint)Process.GetCurrentProcess().Id);

        public static ProcessIdentity FromProcessId(uint processId)
        {
            using SafeProcessHandle process = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, processId);

            if (process.IsInvalid)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            if (!NativeMethods.OpenProcessToken(process, NativeMethods.TOKEN_QUERY, out SafeAccessTokenHandle token))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            using (token)
            {
                SecurityIdentifier user = WithTokenInformation(token, NativeMethods.TokenUser,
                    buffer => new SecurityIdentifier(Marshal.ReadIntPtr(buffer)));
                int sessionId = WithTokenInformation(token, NativeMethods.TokenSessionId, buffer => Marshal.ReadInt32(buffer));

                return new ProcessIdentity(user, sessionId, QueryImagePath(process));
            }
        }

        /// <summary>
        /// Returns true when <paramref name="other"/> runs as the same user, in the same session, from the same executable.
        /// </summary>
        public bool Matches(ProcessIdentity other)
        {
            return other is not null
                && this.User.Equals(other.User)
                && this.SessionId == other.SessionId
                && string.Equals(this.ImagePath, other.ImagePath, StringComparison.OrdinalIgnoreCase);
        }

        public override string ToString() => $"{this.User.Value} session {this.SessionId} {this.ImagePath}";

        private static T WithTokenInformation<T>(SafeAccessTokenHandle token, int informationClass, Func<IntPtr, T> read)
        {
            NativeMethods.GetTokenInformation(token, informationClass, IntPtr.Zero, 0, out int length);

            if (length <= 0)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            IntPtr buffer = Marshal.AllocHGlobal(length);

            try
            {
                if (!NativeMethods.GetTokenInformation(token, informationClass, buffer, length, out _))
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }

                return read(buffer);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static string QueryImagePath(SafeProcessHandle process)
        {
            StringBuilder builder = new(1024);
            int size = builder.Capacity;

            if (!NativeMethods.QueryFullProcessImageName(process, 0, builder, ref size))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return builder.ToString(0, size);
        }
    }
}
