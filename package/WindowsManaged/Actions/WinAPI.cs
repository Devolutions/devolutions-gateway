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

    internal const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    internal static uint FILE_SHARE_READ = 0x00000001;

    internal static uint FILE_SHARE_WRITE = 0x00000002;

    internal static uint FILE_SHARE_DELETE = 0x00000004;

    internal const uint OPEN_EXISTING = 3;

    internal static uint LOGON32_LOGON_SERVICE = 5;

    internal static uint LOGON32_PROVIDER_DEFAULT = 0;

    internal static uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x04;

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

    /* Standard access rights */

    internal const uint DELETE = 0x00010000;

    internal const uint READ_CONTROL = 0x00020000;

    internal const uint SYNCHRONIZE = 0x00100000;

    internal const uint WRITE_DAC = 0x00040000;

    internal const uint WRITE_OWNER = 0x00080000;

    /* File access rights */

    internal const uint FILE_ADD_FILE = 2;

    internal const uint FILE_ADD_SUBDIRECTORY = 4;

    internal const uint FILE_APPEND_DATA = 4;

    internal const uint FILE_CREATE_PIPE_INSTANCE = 4;

    internal const uint FILE_DELETE_CHILD = 64;

    internal const uint FILE_EXECUTE = 32;

    internal const uint FILE_LIST_DIRECTORY = 1;

    internal const uint FILE_READ_ATTRIBUTES = 128;

    internal const uint FILE_READ_DATA = 1;

    internal const uint FILE_READ_EA = 8;

    internal const uint FILE_TRAVERSE = 32;

    internal const uint FILE_WRITE_ATTRIBUTES = 256;

    internal const uint FILE_WRITE_DATA = 2;

    internal const uint FILE_WRITE_EA = 16;

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

    [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool DuplicateToken(
        IntPtr token, 
        uint impersonationLevel, 
        ref IntPtr DuplicateTokenHandle);

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
