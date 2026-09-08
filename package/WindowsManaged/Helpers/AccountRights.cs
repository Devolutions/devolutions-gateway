using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using DevolutionsGateway.Actions;

namespace DevolutionsGateway.Helpers
{
    /// <summary>
    /// Local security policy account rights (privileges) management
    /// </summary>
    internal static class AccountRights
    {
        internal const string LogonAsService = "SeServiceLogonRight";

        /// <summary>
        /// Grant an account right to the account identified by <paramref name="sid"/>.
        /// Rights already held by the account are ignored.
        /// </summary>
        internal static void Grant(SecurityIdentifier sid, string right)
        {
            byte[] sidBytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(sidBytes, 0);

            IntPtr pSid = Marshal.AllocHGlobal(sidBytes.Length);
            IntPtr policy = IntPtr.Zero;

            try
            {
                Marshal.Copy(sidBytes, 0, pSid, sidBytes.Length);

                WinAPI.LSA_OBJECT_ATTRIBUTES attributes = new();
                WinAPI.LSA_UNICODE_STRING systemName = new();

                uint status = WinAPI.LsaOpenPolicy(ref systemName, ref attributes,
                    WinAPI.POLICY_LOOKUP_NAMES | WinAPI.POLICY_CREATE_ACCOUNT, out policy);

                ThrowIfFailed(status, nameof(WinAPI.LsaOpenPolicy));

                WinAPI.LSA_UNICODE_STRING[] rights = { WinAPI.LSA_UNICODE_STRING.FromString(right) };

                try
                {
                    status = WinAPI.LsaAddAccountRights(policy, pSid, rights, (uint)rights.Length);
                    ThrowIfFailed(status, nameof(WinAPI.LsaAddAccountRights));
                }
                finally
                {
                    rights[0].Free();
                }
            }
            finally
            {
                if (policy != IntPtr.Zero)
                {
                    WinAPI.LsaClose(policy);
                }

                Marshal.FreeHGlobal(pSid);
            }
        }

        private static void ThrowIfFailed(uint status, string function)
        {
            if (status == 0)
            {
                return;
            }

            int error = (int)WinAPI.LsaNtStatusToWinError(status);
            throw new Win32Exception(error, $"{function} failed (status: 0x{status:X8}, error: {error})");
        }
    }
}
