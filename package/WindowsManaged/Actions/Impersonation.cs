using System;
using System.ComponentModel;
using System.Security.Principal;

namespace DevolutionsGateway.Actions
{
    internal class Impersonation : IDisposable
    {
        private bool disposed;

        private WindowsImpersonationContext impersonationContext;

        internal Impersonation(string user, string domain, string password)
        {
            IntPtr userTokenDuplication = IntPtr.Zero;

            if (!WinAPI.LogonUser(user, domain, password, WinAPI.LOGON32_LOGON_SERVICE,
                    WinAPI.LOGON32_PROVIDER_DEFAULT, out IntPtr userToken))
            {
                throw new Win32Exception();
            }

            try
            {
                if (WinAPI.DuplicateToken(userToken, 2, ref userTokenDuplication))
                {
                    WindowsIdentity winid = new WindowsIdentity(userTokenDuplication);
                    this.impersonationContext = winid.Impersonate();
                }
                else
                {
                    throw new Win32Exception();
                }
            }
            finally
            {
                if (userTokenDuplication != IntPtr.Zero)
                {
                    WinAPI.CloseHandle(userTokenDuplication);
                }

                if (userToken != IntPtr.Zero)
                {
                    WinAPI.CloseHandle(userToken);
                }
            }
        }

        ~Impersonation()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        public void Revert()
        {
            if (impersonationContext == null)
            {
                return;
            }

            impersonationContext.Undo();
            impersonationContext = null;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposed)
            {
                return;
            }

            Revert();
            disposed = true;
        }
    }
}
