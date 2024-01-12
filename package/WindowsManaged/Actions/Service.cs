using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.ServiceProcess;
using System.Threading.Tasks;
using System.Threading;

namespace DevolutionsGateway.Actions;

internal class Service : IDisposable
{
    private IntPtr hService = IntPtr.Zero;

    private readonly ILogger logger;

    private readonly string name;

    internal IntPtr Handle => this.hService;

    public static bool TryOpen(ServiceManager serviceManager, string name, uint desiredAccess, out Service service, ILogger logger = null)
    {
        service = null;

        try
        {
            service = new Service(serviceManager, name, desiredAccess, logger);
            return true;
        }
        catch
        {
            return false;
        }
    }

    public Service(ServiceManager serviceManager, string name, uint desiredAccess, ILogger logger = null)
    {
        this.logger = logger ??= new NullLogger();
        this.name = name;

        logger.Log($"opening service {name} with desired access {desiredAccess}");

        this.hService = WinAPI.OpenService(serviceManager.Handle, name, desiredAccess);

        if (this.hService == IntPtr.Zero)
        {
            logger.Log($"failed to open service {name} with desired access {desiredAccess} (error: {Marshal.GetLastWin32Error()})");
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    public void Dispose()
    {
        if (this.hService == IntPtr.Zero)
        {
            return;
        }

        WinAPI.CloseServiceHandle(this.hService);
        this.hService = IntPtr.Zero;
    }

    public ServiceStartMode GetStartupType()
    {
        uint bytesNeeded = 0;
        const int errorInsufficientBuffer = 122;

        if (!WinAPI.QueryServiceConfig(this.Handle, IntPtr.Zero, bytesNeeded, ref bytesNeeded))
        {
            if (Marshal.GetLastWin32Error() != errorInsufficientBuffer)
            {
                logger.Log($"QueryServiceConfig failed (error: {Marshal.GetLastWin32Error()})");
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
        }

        using Buffer buffer = new((int)bytesNeeded);

        if (!WinAPI.QueryServiceConfig(this.Handle, buffer, bytesNeeded, ref bytesNeeded))
        {
            logger.Log($"QueryServiceConfig failed (error: {Marshal.GetLastWin32Error()})");
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        WinAPI.QUERY_SERVICE_CONFIG serviceConfig = Marshal.PtrToStructure<WinAPI.QUERY_SERVICE_CONFIG>(buffer);
        logger.Log($"service {name} has start type: {serviceConfig.dwStartType}");
        return (ServiceStartMode)serviceConfig.dwStartType;
    }

    public void SetStartupType(ServiceStartMode startMode)
    {
        logger.Log($"setting service {name} start mode to {startMode}");

        if (!WinAPI.ChangeServiceConfig(this.Handle, WinAPI.SERVICE_NO_CHANGE,
                (uint)startMode, WinAPI.SERVICE_NO_CHANGE, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
        {
            logger.Log($"ChangeServiceConfig failed (error: {Marshal.GetLastWin32Error()})");
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    /// <summary>
    /// Request the service to start if it's startup mode is "Automatic"
    /// </summary>
    public void StartIfNeeded()
    {
        ServiceStartMode currentStartMode = GetStartupType();

        if (currentStartMode != ServiceStartMode.Automatic)
        {
            logger.Log($"service {name} not configured for automatic start, not starting");
            return;
        }

        logger.Log($"starting service {name}");

        if (WinAPI.StartService(this.Handle, 0, IntPtr.Zero))
        {
            return;
        }

        const int errorServiceAlreadyRunning = 1056;

        if (Marshal.GetLastWin32Error() != errorServiceAlreadyRunning)
        {
            logger.Log($"StartService failed (error: {Marshal.GetLastWin32Error()})");
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
        else
        {
            logger.Log($"service {name} is already running");
        }
    }

    public void Restart()
    {
        if (!Stop(TimeSpan.FromSeconds(60)))
        {
            return;
        }

        logger.Log($"starting service {name}");

        if (!WinAPI.StartService(this.Handle, 0, IntPtr.Zero))
        {
            logger.Log($"StartService failed (error: {Marshal.GetLastWin32Error()})");
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }
    }

    // Returns `false` if the service already stopped or stop pending, `true` if we stopped the service
    private bool Stop(TimeSpan timeout)
    {
        logger.Log($"stopping service {name}");

        using Buffer pSsp = new(Marshal.SizeOf<WinAPI.SERVICE_STATUS_PROCESS>());

        if (!WinAPI.QueryServiceStatusEx(this.Handle, WinAPI.SC_STATUS_PROCESS_INFO, pSsp, (uint)Marshal.SizeOf<WinAPI.SERVICE_STATUS_PROCESS>(), out var dwBytesNeeded))
        {
            logger.Log($"QueryServiceStatusEx failed (error: {Marshal.GetLastWin32Error()})");
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        WinAPI.SERVICE_STATUS_PROCESS ssp = Marshal.PtrToStructure<WinAPI.SERVICE_STATUS_PROCESS>(pSsp);

        if (ssp.dwCurrentState == WinAPI.SERVICE_STOPPED)
        {
            logger.Log($"service {name} is already stopped");
            return false;
        }

        using CancellationTokenSource cts = new(timeout);

        while (ssp.dwCurrentState == WinAPI.SERVICE_STOP_PENDING)
        {
            uint waitTime = ssp.dwWaitHint / 10;

            if (waitTime < TimeSpan.FromSeconds(1).TotalMilliseconds)
            {
                waitTime = (uint)TimeSpan.FromSeconds(1).TotalMilliseconds;
            }
            else if (waitTime > TimeSpan.FromSeconds(10).TotalMilliseconds)
            {
                waitTime = (uint)TimeSpan.FromSeconds(10).TotalMilliseconds;
            }

            logger.Log($"service {name} is stop pending; waiting {waitTime}ms");

            Task.Delay((int)waitTime, cts.Token);

            if (!WinAPI.QueryServiceStatusEx(this.Handle, WinAPI.SC_STATUS_PROCESS_INFO, pSsp, (uint)Marshal.SizeOf<WinAPI.SERVICE_STATUS_PROCESS>(), out dwBytesNeeded))
            {
                logger.Log($"QueryServiceStatusEx failed (error: {Marshal.GetLastWin32Error()})");
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            ssp = Marshal.PtrToStructure<WinAPI.SERVICE_STATUS_PROCESS>(pSsp);

            if (ssp.dwCurrentState == WinAPI.SERVICE_STOPPED)
            {
                logger.Log($"service {name} is stopped");
                return false;
            }

            if (cts.IsCancellationRequested)
            {
                logger.Log($"timeout waiting for service {name} to stop");
                throw new OperationCanceledException();
            }
        }

        // Currently Devolutions Gateway has no dependent services; but if it did, we would need to stop them here

        using Buffer pSs = new(Marshal.SizeOf<WinAPI.SERVICE_STATUS>());

        logger.Log($"requesting service {name} to stop");

        if (!WinAPI.ControlService(this.Handle, WinAPI.SERVICE_CONTROL_STOP, pSs))
        {
            logger.Log($"ControlService failed (error: {Marshal.GetLastWin32Error()})");
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        while (ssp.dwCurrentState != WinAPI.SERVICE_STOPPED)
        {
            Task.Delay((int)ssp.dwWaitHint, cts.Token);

            if (!WinAPI.QueryServiceStatusEx(this.Handle, WinAPI.SC_STATUS_PROCESS_INFO, pSsp, (uint)Marshal.SizeOf<WinAPI.SERVICE_STATUS_PROCESS>(), out dwBytesNeeded))
            {
                logger.Log($"QueryServiceStatusEx failed (error: {Marshal.GetLastWin32Error()})");
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            ssp = Marshal.PtrToStructure<WinAPI.SERVICE_STATUS_PROCESS>(pSsp);

            if (ssp.dwCurrentState == WinAPI.SERVICE_STOPPED)
            {
                logger.Log($"service {name} is stopped");
                return true;
            }

            if (cts.IsCancellationRequested)
            {
                logger.Log($"timeout waiting for service {name} to stop");
                throw new OperationCanceledException();
            }
        }

        return true;
    }
}
