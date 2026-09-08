using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace DevolutionsGateway.Actions;

internal static class WinAPI
{
    internal static uint CREATE_ALWAYS = 2;

    internal static uint CREATE_NO_WINDOW = 0x08000000;

    internal const uint DACL_SECURITY_INFORMATION = 0x00000004;

    internal const int EM_SETCUEBANNER = 0x1501;
    
    internal static uint FILE_ATTRIBUTE_NORMAL = 0x00000080;

    internal static uint FILE_SHARE_READ = 0x00000001;

    internal static uint FILE_SHARE_WRITE = 0x00000002;

    internal const uint LOGON32_LOGON_NETWORK = 3;

    internal const uint LOGON32_PROVIDER_DEFAULT = 0;

    internal static uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x04;

    internal const uint POLICY_CREATE_ACCOUNT = 0x00000010;

    internal const uint POLICY_LOOKUP_NAMES = 0x00000800;

    internal const uint SC_MANAGER_ALL_ACCESS = 0xF003F;

    internal const uint SC_MANAGER_CONNECT = 0x0001;

    internal const uint SC_STATUS_PROCESS_INFO = 0;

    internal const uint SERVICE_CONTROL_STOP = 0x00000001;

    internal const uint SERVICE_NO_CHANGE = 0xFFFFFFFF;

    internal const uint SERVICE_CHANGE_CONFIG = 0x0002;

    internal const uint SERVICE_QUERY_CONFIG = 0x0001;

    internal const uint SERVICE_QUERY_STATUS = 0x0004;

    internal const uint SERVICE_START = 0x0010;

    internal const uint SERVICE_STOP = 0x0020;

    internal const uint SERVICE_STOP_PENDING = 0x00000003;

    internal const uint SERVICE_STOPPED = 0x00000001;

    internal static uint STARTF_USESTDHANDLES = 0x00000100;

    internal static int STD_INPUT_HANDLE = -10;

    internal static uint WAIT_TIMEOUT = 0x00000102;

    /* Generic access rights */

    internal const uint GENERAL_ALL = 0x10000000;

    internal const uint GENERIC_EXECUTE = 0x20000000;

    internal const uint GENERIC_WRITE = 0x40000000;

    internal const uint GENERIC_READ = 0x80000000;

    [StructLayout(LayoutKind.Sequential)]
    internal struct QUERY_SERVICE_CONFIG
    {
        internal uint dwServiceType;

        internal uint dwStartType;

        internal uint dwErrorControl;

        internal IntPtr lpBinaryPathName;

        internal IntPtr lpLoadOrderGroup;

        internal uint dwTagId;

        internal IntPtr lpDependencies;

        internal IntPtr lpServiceStartName;

        internal IntPtr lpDisplayName;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_OBJECT_ATTRIBUTES
    {
        internal uint Length;

        internal IntPtr RootDirectory;

        internal IntPtr ObjectName;

        internal uint Attributes;

        internal IntPtr SecurityDescriptor;

        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LSA_UNICODE_STRING
    {
        internal ushort Length;

        internal ushort MaximumLength;

        internal IntPtr Buffer;

        internal static LSA_UNICODE_STRING FromString(string value)
        {
            return new LSA_UNICODE_STRING
            {
                Buffer = Marshal.StringToHGlobalUni(value),
                Length = (ushort)(value.Length * sizeof(char)),
                MaximumLength = (ushort)((value.Length + 1) * sizeof(char)),
            };
        }

        internal void Free()
        {
            if (this.Buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(this.Buffer);
                this.Buffer = IntPtr.Zero;
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct PROCESS_INFORMATION
    {
        internal IntPtr hProcess;

        internal IntPtr hThread;

        internal uint dwProcessId;

        internal uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SECURITY_ATTRIBUTES
    { 
       internal uint nLength;

       internal IntPtr lpSecurityDescriptor;

       [MarshalAs(UnmanagedType.Bool)] 
       internal bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SERVICE_STATUS
    {
        public uint dwServiceType;

        public uint dwCurrentState;

        public uint dwControlsAccepted;

        public uint dwWin32ExitCode;

        public uint dwServiceSpecificExitCode;

        public uint dwCheckPoint;

        public uint dwWaitHint;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SERVICE_STATUS_PROCESS
    {
        internal uint dwServiceType;

        internal uint dwCurrentState;

        internal uint dwControlsAccepted;

        internal uint dwWin32ExitCode;

        internal uint dwServiceSpecificExitCode;

        internal uint dwCheckPoint;

        internal uint dwWaitHint;

        internal uint dwProcessId;

        internal uint dwServiceFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct STARTUPINFO
    {
        internal uint cb;

        internal IntPtr lpReserved;

        internal IntPtr lpDesktop;

        internal IntPtr lpTitle;

        internal uint dwX;

        internal uint dwY;

        internal uint dwXSize;

        internal uint dwYSize;

        internal uint dwXCountChars;

        internal uint dwYCountChars;

        internal uint dwFillAttributes;

        internal uint dwFlags;

        internal short wShowWindow;

        internal short cbReserved;

        internal IntPtr lpReserved2;

        internal IntPtr hStdInput;

        internal IntPtr hStdOutput;

        internal IntPtr hStdError;
    }

    [DllImport("advapi32", EntryPoint = "ChangeServiceConfigW", SetLastError = true)]
    internal static extern bool ChangeServiceConfig(
        IntPtr hService,
        uint nServiceType,
        uint nStartType,
        uint nErrorControl,
        IntPtr lpBinaryPathName,
        IntPtr lpLoadOrderGroup,
        IntPtr lpdwTagId,
        IntPtr lpDependencies,
        IntPtr lpServiceStartName,
        IntPtr lpPassword,
        IntPtr lpDisplayName);

    [DllImport("kernel32")]
    internal static extern bool CloseHandle(IntPtr handle);

    [DllImport("advapi32", EntryPoint = "CloseServiceHandle")]
    internal static extern int CloseServiceHandle(IntPtr hSCObject);

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string StringSecurityDescriptor, uint StringSDRevision, out IntPtr SecurityDescriptor, out UIntPtr SecurityDescriptorSize);


    [DllImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ControlService(IntPtr hService, uint dwControl, IntPtr lpServiceStatus);

    [DllImport("kernel32", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern SafeFileHandle CreateFile(
        [MarshalAs(UnmanagedType.LPWStr)] string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile
    );

    [DllImport("kernel32", EntryPoint = "CreateProcessW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool CreateProcess(
        [MarshalAs(UnmanagedType.LPWStr)] string lpApplicationName,
        [MarshalAs(UnmanagedType.LPWStr)] string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        IntPtr lpStartupInfo,
        IntPtr lpProcessInformation);

    [DllImport("kernel32", EntryPoint = "DeleteFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool DeleteFile(
        [MarshalAs(UnmanagedType.LPWStr)] 
        string lpFileName
    );

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("Kernel32", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Auto, SetLastError = true)]
    internal static extern uint GetFinalPathNameByHandle(
        IntPtr hFile,
        [MarshalAs(UnmanagedType.LPTStr)] 
        StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    [DllImport("kernel32", SetLastError = true)]
    internal static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32", EntryPoint = "GetTempFileNameW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint GetTempFileName(
        [MarshalAs(UnmanagedType.LPWStr)] string lpPathName,
        [MarshalAs(UnmanagedType.LPWStr)] string lpPrefixString,
        uint uUnique,
        [Out] StringBuilder lpTempFileName);
    
    [DllImport("kernel32", SetLastError = true)]
    internal static extern IntPtr LocalFree(IntPtr hMem);

    [DllImport("advapi32", EntryPoint = "LogonUserW", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool LogonUser(
        string username,
        string domain,
        string password,
        uint logonType,
        uint logonProvider,
        out IntPtr phToken);

    [DllImport("advapi32", SetLastError = true)]
    internal static extern uint LsaAddAccountRights(
        IntPtr PolicyHandle,
        IntPtr AccountSid,
        LSA_UNICODE_STRING[] UserRights,
        uint CountOfRights);

    [DllImport("advapi32", SetLastError = true)]
    internal static extern uint LsaClose(IntPtr ObjectHandle);

    [DllImport("advapi32", SetLastError = true)]
    internal static extern uint LsaNtStatusToWinError(uint Status);

    [DllImport("advapi32", SetLastError = true)]
    internal static extern uint LsaOpenPolicy(
        ref LSA_UNICODE_STRING SystemName,
        ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
        uint DesiredAccess,
        out IntPtr PolicyHandle);

    /// <remarks>
    /// Exported by logoncli.dll (there is no import library). Tests whether a standalone managed service
    /// account is installed on this host; group managed service accounts are only reported when installed too.
    /// </remarks>
    [DllImport("logoncli.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern uint NetIsServiceAccount(
        [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
        [MarshalAs(UnmanagedType.LPWStr)] string AccountName,
        [MarshalAs(UnmanagedType.Bool)] out bool IsService);

    [DllImport("kernel32", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool MoveFileEx(
        [MarshalAs(UnmanagedType.LPWStr)] string lpExistingFileName,
        IntPtr lpNewFileName,
        uint dwFlags
    );

    [DllImport("advapi32", EntryPoint = "OpenSCManagerW", SetLastError = true)]
    internal static extern IntPtr OpenSCManager(IntPtr machineName, IntPtr databaseName, uint dwAccess);

    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr OpenService(
        IntPtr hSCManager,
        [MarshalAs(UnmanagedType.LPWStr)] string lpServiceName,
        uint dwDesiredAccess);

    [DllImport("advapi32", EntryPoint = "QueryServiceConfigW", SetLastError = true)]
    internal static extern bool QueryServiceConfig(IntPtr hService, IntPtr lpServiceConfig, uint cbBufSize,
        ref uint pcbBytesNeeded);

    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryServiceStatusEx(IntPtr serviceHandle, uint infoLevel, IntPtr buffer, uint bufferSize,
        out uint bytesNeeded);

    [DllImport("user32", EntryPoint = "SendMessageW", CharSet = CharSet.Unicode)]
    internal static extern int SendMessage(
        IntPtr hWnd,
        int msg,
        int wParam,
        [MarshalAs(UnmanagedType.LPWStr)] string lParam);

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool SetFileSecurityW(string lpFileName, uint SecurityInformation, IntPtr pSecurityDescriptor);

    [DllImport("advapi32", EntryPoint = "StartServiceW", SetLastError = true)]
    internal static extern bool StartService(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32", SetLastError = true)]
    internal static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
