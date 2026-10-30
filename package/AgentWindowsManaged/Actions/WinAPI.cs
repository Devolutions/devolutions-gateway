using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DevolutionsAgent.Actions;

internal static class WinAPI
{
    internal const uint AUTHZ_RM_FLAG_NO_AUDIT = 0x1;

    internal const int AuthzContextInfoGroupsSids = 2;

    internal static uint CREATE_ALWAYS = 2;

    internal static uint CREATE_NO_WINDOW = 0x08000000;

    internal const uint DACL_SECURITY_INFORMATION = 0x00000004;

    internal const uint DELETE = 0x00010000;

    internal const int EM_SETCUEBANNER = 0x1501;

    internal const int ERROR_ALREADY_EXISTS = 183;

    internal const int ERROR_FILE_NOT_FOUND = 2;

    internal const int ERROR_PATH_NOT_FOUND = 3;

    internal const int ERROR_SHARING_VIOLATION = 32;

    internal const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;

    internal const uint FILE_DELETE_CHILD = 0x00000040;

    internal static uint FILE_ATTRIBUTE_NORMAL = 0x00000080;

    internal const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

    internal const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    internal const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;

    internal const uint FILE_READ_ATTRIBUTES = 0x00000080;

    internal const uint FILE_SHARE_DELETE = 0x00000004;

    internal static uint FILE_SHARE_READ = 0x00000001;

    internal static uint FILE_SHARE_WRITE = 0x00000002;

    internal const uint FILE_TRAVERSE = 0x00000020;

    internal const int FileDispositionInfo = 4;

    internal const uint GENERIC_ALL = 0x10000000;

    internal static uint GENERIC_WRITE = 0x40000000;

    internal const uint MAX_PREFERRED_LENGTH = 0xFFFFFFFF;

    internal static uint MOVEFILE_REPLACE_EXISTING = 0x1;

    internal static uint MOVEFILE_DELAY_UNTIL_REBOOT = 0x04;

    internal const uint NCRYPT_MACHINE_KEY_FLAG = 0x00000020;

    internal const uint NERR_Success = 0;

    internal const int NTE_NO_MORE_ITEMS = unchecked((int)0x8009002A);

    internal const uint OPEN_EXISTING = 3;

    internal const uint OWNER_SECURITY_INFORMATION = 0x00000001;

    internal const uint READ_CONTROL = 0x00020000;

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

    internal const ushort SE_DACL_AUTO_INHERIT_REQ = 0x0100;

    internal static uint STARTF_USESTDHANDLES = 0x00000100;

    internal static int STD_INPUT_HANDLE = -10;

    internal static uint WAIT_TIMEOUT = 0x00000102;

    internal const uint WRITE_DAC = 0x00040000;

    internal const uint WRITE_OWNER = 0x00080000;

    [StructLayout(LayoutKind.Sequential)]
    internal struct BY_HANDLE_FILE_INFORMATION
    {
        internal uint dwFileAttributes;

        internal System.Runtime.InteropServices.ComTypes.FILETIME ftCreationTime;

        internal System.Runtime.InteropServices.ComTypes.FILETIME ftLastAccessTime;

        internal System.Runtime.InteropServices.ComTypes.FILETIME ftLastWriteTime;

        internal uint dwVolumeSerialNumber;

        internal uint nFileSizeHigh;

        internal uint nFileSizeLow;

        internal uint nNumberOfLinks;

        internal uint nFileIndexHigh;

        internal uint nFileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct FILE_DISPOSITION_INFO
    {
        [MarshalAs(UnmanagedType.U1)] internal bool DeleteFile;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        internal uint LowPart;

        internal int HighPart;
    }

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
        [MarshalAs(UnmanagedType.Bool)] internal bool bInheritHandle;
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
    internal struct SID_AND_ATTRIBUTES
    {
        internal IntPtr Sid;

        internal uint Attributes;
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

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_GROUPS
    {
        internal uint GroupCount;

        // The first of GroupCount entries.
        internal SID_AND_ATTRIBUTES Groups;
    }

    [DllImport("authz")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AuthzFreeContext(IntPtr hAuthzClientContext);

    [DllImport("authz")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AuthzFreeResourceManager(IntPtr hAuthzResourceManager);

    [DllImport("authz", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AuthzGetInformationFromContext(
        IntPtr hAuthzClientContext,
        int InfoClass,
        uint BufferSize,
        out uint pSizeRequired,
        IntPtr Buffer);

    [DllImport("authz", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AuthzInitializeContextFromSid(
        uint Flags,
        byte[] UserSid,
        IntPtr hAuthzResourceManager,
        IntPtr pExpirationTime,
        LUID Identifier,
        IntPtr DynamicGroupArgs,
        out IntPtr phAuthzClientContext);

    [DllImport("authz", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool AuthzInitializeResourceManager(
        uint Flags,
        IntPtr pfnDynamicAccessCheck,
        IntPtr pfnComputeDynamicGroups,
        IntPtr pfnFreeDynamicGroups,
        string szResourceManagerName,
        out IntPtr phAuthzResourceManager);

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

    [DllImport("kernel32", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CreateDirectory(string lpPathName, ref SECURITY_ATTRIBUTES lpSecurityAttributes);

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
        [MarshalAs(UnmanagedType.LPWStr)] string lpFileName
    );

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetFileInformationByHandle(
        SafeFileHandle hFile,
        out BY_HANDLE_FILE_INFORMATION lpFileInformation);

    [DllImport("Kernel32", EntryPoint = "GetFinalPathNameByHandleW", CharSet = CharSet.Auto, SetLastError = true)]
    internal static extern uint GetFinalPathNameByHandle(
        IntPtr hFile,
        [MarshalAs(UnmanagedType.LPTStr)] StringBuilder lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    [DllImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool GetKernelObjectSecurity(
        SafeFileHandle Handle,
        uint RequestedInformation,
        byte[] pSecurityDescriptor,
        uint nLength,
        out uint lpnLengthNeeded);

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

    [DllImport("kernel32", EntryPoint = "MoveFileExW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool MoveFileEx(
        [MarshalAs(UnmanagedType.LPWStr)] string lpExistingFileName,
        [MarshalAs(UnmanagedType.LPWStr)] string lpNewFileName,
        uint dwFlags
    );

    [DllImport("netapi32")]
    internal static extern uint NetApiBufferFree(IntPtr Buffer);

    [DllImport("netapi32", CharSet = CharSet.Unicode)]
    internal static extern uint NetLocalGroupGetMembers(
        string servername,
        string localgroupname,
        uint level,
        out IntPtr bufptr,
        uint prefmaxlen,
        out uint entriesread,
        out uint totalentries,
        IntPtr resumehandle);

    [DllImport("ncrypt", CharSet = CharSet.Unicode)]
    internal static extern int NCryptEnumKeys(
        IntPtr hProvider,
        string pszScope,
        out IntPtr ppKeyName,
        ref IntPtr ppEnumState,
        uint dwFlags);

    [DllImport("ncrypt")]
    internal static extern int NCryptFreeBuffer(IntPtr pvInput);

    [DllImport("ncrypt")]
    internal static extern int NCryptFreeObject(IntPtr hObject);

    [DllImport("ncrypt", CharSet = CharSet.Unicode)]
    internal static extern int NCryptOpenStorageProvider(out IntPtr phProvider, string pszProviderName, uint dwFlags);

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

    [DllImport("kernel32", SetLastError = true)]
    internal static extern SafeFileHandle ReOpenFile(
        SafeFileHandle hOriginalFile,
        uint dwDesiredAccess,
        uint dwShareMode,
        uint dwFlagsAndAttributes);

    [DllImport("user32", EntryPoint = "SendMessageW", CharSet = CharSet.Unicode)]
    internal static extern int SendMessage(
        IntPtr hWnd,
        int msg,
        int wParam,
        [MarshalAs(UnmanagedType.LPWStr)] string lParam);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetFileInformationByHandle(
        SafeFileHandle hFile,
        int FileInformationClass,
        ref FILE_DISPOSITION_INFO lpFileInformation,
        uint dwBufferSize);

    [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern bool SetFileSecurityW(string lpFileName, uint SecurityInformation, IntPtr pSecurityDescriptor);

    [DllImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetSecurityDescriptorControl(
        IntPtr pSecurityDescriptor,
        ushort ControlBitsOfInterest,
        ushort ControlBitsToSet);

    [DllImport("advapi32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool SetKernelObjectSecurity(
        SafeFileHandle Handle,
        uint SecurityInformation,
        IntPtr SecurityDescriptor);

    [DllImport("advapi32", EntryPoint = "StartServiceW", SetLastError = true)]
    internal static extern bool StartService(IntPtr hService, uint dwNumServiceArgs, IntPtr lpServiceArgVectors);

    [DllImport("kernel32", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

    [DllImport("kernel32", SetLastError = true)]
    internal static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
}
