using System;
using System.ComponentModel;
using System.Runtime.InteropServices;

namespace DevolutionsAgent.Actions;

internal class ServiceManager : IDisposable
{
    private IntPtr hServiceManager = IntPtr.Zero;

    private readonly ILogger logger;

    internal IntPtr Handle => this.hServiceManager;

    public ServiceManager(uint desiredAccess, ILogger logger = null)
    {
        this.logger = logger ??= new NullLogger();

        this.hServiceManager = WinAPI.OpenSCManager(IntPtr.Zero, IntPtr.Zero, desiredAccess);

        if (this.hServiceManager == IntPtr.Zero)
        {
            logger.Log($"failed to open service manager with desired access {desiredAccess} (error: {Marshal.GetLastWin32Error()})");
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public void Dispose()
    {
        if (this.hServiceManager == IntPtr.Zero)
        {
            return;
        }

        WinAPI.CloseServiceHandle(this.hServiceManager);
        this.hServiceManager = IntPtr.Zero;
    }
}
