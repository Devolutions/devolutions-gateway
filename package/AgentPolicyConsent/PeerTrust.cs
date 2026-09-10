using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;

namespace DevolutionsAgentPolicyConsent;

internal sealed class PeerLease : IDisposable
{
    // SHA-256 digests of accepted UniGetUI signer SPKIs. Keep both keys during certificate rollover.
    internal const string TransitionUiSignerSpkiSha256 =
        PolicyConsentContract.TransitionUiSignerSpkiSha256;
    internal const string CurrentUiSignerSpkiSha256 =
        PolicyConsentContract.CurrentUiSignerSpkiSha256;

    internal const uint ProcessQueryLimitedInformation = 0x1000;
    internal const uint ProcessQueryInformation = 0x0400;
    internal const uint Synchronize = 0x0010_0000;
    internal const uint GenericRead = 0x8000_0000;
    internal const uint FileExecute = 0x20;
    internal const uint FileReadAttributes = 0x80;
    internal const uint ReadControl = 0x0002_0000;
    internal const uint FileShareRead = 0x1;
    internal const uint FileShareWrite = 0x2;
    internal const uint OpenExisting = 3;
    internal const uint FileAttributeReparsePoint = 0x400;
    internal const uint FileFlagBackupSemantics = 0x0200_0000;
    internal const uint FileFlagOpenReparsePoint = 0x0020_0000;
    internal const int ProcessImageFileMapping = 44;
    internal const uint StillActive = 259;

    private readonly SafeProcessHandle process;
    private readonly SafeFileHandle image;
    private readonly int processId;
    private readonly long createdUtcTicks;
    private readonly uint sessionId;

    private PeerLease(
        SafeProcessHandle process,
        SafeFileHandle image,
        int processId,
        long createdUtcTicks,
        uint sessionId)
    {
        this.process = process;
        this.image = image;
        this.processId = processId;
        this.createdUtcTicks = createdUtcTicks;
        this.sessionId = sessionId;
    }

    internal static PeerLease Open(Arguments arguments)
    {
        SafeProcessHandle process = Native.OpenProcess(
            ProcessQueryInformation | ProcessQueryLimitedInformation | Synchronize,
            false,
            arguments.ParentProcessId);
        if (process.IsInvalid)
        {
            throw new Win32Exception();
        }

        try
        {
            long created = CreationTime(process);
            uint session = SessionId(arguments.ParentProcessId);
            if (!MatchesProcessIdentity(
                    arguments,
                    arguments.ParentProcessId,
                    created,
                    session))
            {
                throw new InvalidOperationException("parent process identity mismatch");
            }

            string path = ImagePath(process);
            SafeFileHandle image = Native.CreateFile(
                path,
                GenericRead | FileExecute | Synchronize,
                FileShareRead,
                IntPtr.Zero,
                OpenExisting,
                0,
                IntPtr.Zero);
            if (image.IsInvalid)
            {
                throw new Win32Exception();
            }

            try
            {
                VerifyImageMapping(process, image);
                VerifyImageMetadata(path, image);
                using X509Certificate2 signer = VerifyAuthenticodeSigner(path, image, "parent image");
                VerifySigner(signer);
                VerifyImageMapping(process, image);
                EnsureActive(process);
                return new PeerLease(process, image, arguments.ParentProcessId, created, session);
            }
            catch
            {
                image.Dispose();
                throw;
            }
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }

    internal void VerifyConnectedServer(int serverProcessId)
    {
        Arguments expected = new(string.Empty, processId, createdUtcTicks, sessionId);
        if (!MatchesProcessIdentity(expected, serverProcessId, CreationTime(process), SessionId(serverProcessId)))
        {
            throw new InvalidOperationException("connected server process identity mismatch");
        }
        VerifyImageMapping(process, image);
        EnsureActive(process);
    }

    internal static bool IsAllowedSigner(string digest) =>
        FixedTimeEqualsHex(digest, CurrentUiSignerSpkiSha256) ||
        FixedTimeEqualsHex(digest, TransitionUiSignerSpkiSha256);

    internal static bool IsAllowedDevolutionsSigner(string thumbprint) =>
        PolicyConsentContract.DevolutionsSignerSha1Thumbprints.Any(
            expected => FixedTimeEqualsHex(thumbprint, expected, 40));

    internal static bool IsSupportedUiIdentity(string? productName, string? originalFilename, string? productVersion) =>
        string.Equals(productName, "UniGetUI", StringComparison.Ordinal) &&
        string.Equals(originalFilename, "UniGetUI.dll", StringComparison.OrdinalIgnoreCase) &&
        productVersion is not null &&
        Version.TryParse(productVersion.Split('+', '-', StringSplitOptions.TrimEntries)[0], out Version? parsed) &&
        parsed >= new Version(3, 3, 7);

    internal static bool MatchesProcessIdentity(
        Arguments expected,
        int processId,
        long createdUtcTicks,
        uint sessionId) =>
        processId == expected.ParentProcessId &&
        createdUtcTicks == expected.ParentCreatedUtcTicks &&
        sessionId == expected.SessionId;

    public void Dispose()
    {
        image.Dispose();
        process.Dispose();
    }

    private static void VerifyImageMetadata(string path, SafeFileHandle retainedImage)
    {
        VerifyPathIdentity(path, retainedImage);
        if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidOperationException("parent image is a reparse point");
        }

        FileVersionInfo version = FileVersionInfo.GetVersionInfo(path);
        if (!IsSupportedUiIdentity(version.ProductName, version.OriginalFilename, version.ProductVersion))
        {
            throw new InvalidOperationException("parent image product identity mismatch");
        }
        VerifyPathIdentity(path, retainedImage);
    }

    private static void VerifyPathIdentity(string path, SafeFileHandle retainedImage)
    {
        using SafeFileHandle reopened = Native.CreateFile(
            path,
            GenericRead | FileExecute | Synchronize,
            FileShareRead,
            IntPtr.Zero,
            OpenExisting,
            0,
            IntPtr.Zero);
        if (reopened.IsInvalid)
        {
            throw new Win32Exception();
        }
        if (!SameFile(retainedImage, reopened))
        {
            throw new InvalidOperationException("parent image path no longer identifies the retained image");
        }
    }

    internal static bool SameFile(SafeFileHandle left, SafeFileHandle right)
    {
        if (!Native.GetFileInformationByHandle(left, out Native.ByHandleFileInformation leftInfo) ||
            !Native.GetFileInformationByHandle(right, out Native.ByHandleFileInformation rightInfo))
        {
            throw new Win32Exception();
        }
        return leftInfo.VolumeSerialNumber == rightInfo.VolumeSerialNumber &&
            leftInfo.FileIndexHigh == rightInfo.FileIndexHigh &&
            leftInfo.FileIndexLow == rightInfo.FileIndexLow;
    }

    internal static bool IsLocalSystemProcess(SafeProcessHandle process)
    {
        if (!Native.OpenProcessToken(process, 0x0008, out SafeAccessTokenHandle token))
        {
            throw new Win32Exception();
        }
        using (token)
        {
            _ = Native.GetTokenInformation(token, 1, IntPtr.Zero, 0, out uint length);
            if (length == 0)
            {
                throw new Win32Exception();
            }

            IntPtr information = Marshal.AllocHGlobal(checked((int)length));
            try
            {
                if (!Native.GetTokenInformation(token, 1, information, length, out _))
                {
                    throw new Win32Exception();
                }
                IntPtr sid = Marshal.ReadIntPtr(information);
                return Native.IsWellKnownSid(sid, 22);
            }
            finally
            {
                Marshal.FreeHGlobal(information);
            }
        }
    }

    internal static X509Certificate2 VerifyAuthenticodeSigner(
        string path,
        SafeFileHandle image,
        string subject)
    {
        Guid action = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");
        Native.WinTrustFileInfo file = new(path, image.DangerousGetHandle());
        IntPtr filePointer = Marshal.AllocHGlobal(Marshal.SizeOf<Native.WinTrustFileInfo>());
        IntPtr dataPointer = Marshal.AllocHGlobal(Marshal.SizeOf<Native.WinTrustData>());
        bool fileInitialized = false;
        bool dataInitialized = false;
        try
        {
            Marshal.StructureToPtr(file, filePointer, false);
            fileInitialized = true;
            Native.WinTrustData data = new(filePointer);
            Marshal.StructureToPtr(data, dataPointer, false);
            dataInitialized = true;
            int status = Native.WinVerifyTrust(new IntPtr(-1), ref action, dataPointer);
            if (!IsAuthenticodeStatusAccepted(status))
            {
                throw new InvalidOperationException($"{subject} Authenticode validation failed (0x{status:X8})");
            }
            data = Marshal.PtrToStructure<Native.WinTrustData>(dataPointer);
            IntPtr providerData = Native.WTHelperProvDataFromStateData(data.StateData);
            IntPtr providerSigner = providerData == IntPtr.Zero
                ? IntPtr.Zero
                : Native.WTHelperGetProvSignerFromChain(providerData, 0, false, 0);
            if (providerSigner == IntPtr.Zero)
            {
                throw new InvalidOperationException($"{subject} Authenticode signer is unavailable");
            }

            Native.CryptProviderSigner signer = Marshal.PtrToStructure<Native.CryptProviderSigner>(providerSigner);
            if (signer.CertificateChainCount == 0 || signer.CertificateChain == IntPtr.Zero)
            {
                throw new InvalidOperationException($"{subject} Authenticode certificate chain is empty");
            }
            Native.CryptProviderCertificate certificate =
                Marshal.PtrToStructure<Native.CryptProviderCertificate>(signer.CertificateChain);
#pragma warning disable SYSLIB0057 // WinVerifyTrust returns the certificate context for the exact retained image.
            return new X509Certificate2(certificate.CertificateContext);
#pragma warning restore SYSLIB0057
        }
        finally
        {
            if (dataInitialized)
            {
                Native.WinTrustData data = Marshal.PtrToStructure<Native.WinTrustData>(dataPointer);
                if (data.StateData != IntPtr.Zero)
                {
                    data.StateAction = 2;
                    Marshal.StructureToPtr(data, dataPointer, true);
                    _ = Native.WinVerifyTrust(new IntPtr(-1), ref action, dataPointer);
                }
                Marshal.DestroyStructure<Native.WinTrustData>(dataPointer);
            }
            if (fileInitialized)
            {
                Marshal.DestroyStructure<Native.WinTrustFileInfo>(filePointer);
            }
            Marshal.FreeHGlobal(dataPointer);
            Marshal.FreeHGlobal(filePointer);
        }
    }

    internal static bool IsAuthenticodeStatusAccepted(int status) => status == 0;

    private static void VerifySigner(X509Certificate2 certificate)
    {
        byte[] subjectPublicKeyInfo;
        using (RSA? rsa = certificate.GetRSAPublicKey())
        {
            if (rsa is not null)
            {
                subjectPublicKeyInfo = rsa.ExportSubjectPublicKeyInfo();
            }
            else
            {
                using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
                subjectPublicKeyInfo = ecdsa?.ExportSubjectPublicKeyInfo()
                    ?? throw new InvalidOperationException("unsupported parent signer key");
            }
        }

        string digest = Convert.ToHexString(SHA256.HashData(subjectPublicKeyInfo)).ToLowerInvariant();
        if (!IsAllowedSigner(digest))
        {
            throw new InvalidOperationException("parent image signer is not authorized");
        }
    }

    private static bool FixedTimeEqualsHex(string candidate, string expected, int length = 64)
    {
        if (candidate.Length != length ||
            expected.Length != length ||
            candidate.AsSpan().IndexOfAnyExcept("0123456789abcdef") >= 0)
        {
            return false;
        }
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromHexString(candidate),
                Convert.FromHexString(expected));
        }
        catch (FormatException)
        {
            return false;
        }
    }

    internal static void VerifyImageMapping(SafeProcessHandle process, SafeFileHandle image)
    {
        IntPtr fileHandle = image.DangerousGetHandle();
        int status = Native.NtQueryInformationProcess(
            process.DangerousGetHandle(),
            ProcessImageFileMapping,
            ref fileHandle,
            IntPtr.Size,
            out _);
        if (status != 0)
        {
            throw new InvalidOperationException($"parent image mapping mismatch (0x{status:X8})");
        }
    }

    internal static void VerifyProtectedPath(SafeFileHandle handle, string subject, int tamperRights)
    {
        if (!Native.GetFileInformationByHandle(handle, out Native.ByHandleFileInformation information))
        {
            throw new Win32Exception();
        }
        if (IsReparsePoint(information.FileAttributes))
        {
            throw new InvalidOperationException($"{subject} is a reparse point");
        }

        uint error = Native.GetSecurityInfo(
            handle,
            1,
            0x1 | 0x4,
            out _,
            out _,
            out _,
            out _,
            out IntPtr securityDescriptor);
        if (error != 0)
        {
            throw new Win32Exception(checked((int)error));
        }

        try
        {
            int length = checked((int)Native.GetSecurityDescriptorLength(securityDescriptor));
            byte[] bytes = new byte[length];
            Marshal.Copy(securityDescriptor, bytes, 0, length);
            VerifyTrustedSecurityDescriptor(new RawSecurityDescriptor(bytes, 0), subject, tamperRights);
        }
        finally
        {
            _ = Native.LocalFree(securityDescriptor);
        }
    }

    internal static bool IsReparsePoint(uint attributes) =>
        (attributes & FileAttributeReparsePoint) != 0;

    internal const int FileTamperRights =
        0x0000_0002 | 0x0000_0004 | 0x0000_0010 | 0x0000_0100 |
        0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x1000_0000 | 0x4000_0000;
    internal const int ParentDirectoryTamperRights =
        0x0000_0002 | 0x0000_0004 | 0x0000_0040 |
        0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x1000_0000 | 0x4000_0000;
    internal const int AncestorDirectoryTamperRights =
        0x0000_0040 | 0x0001_0000 | 0x0004_0000 | 0x0008_0000 | 0x1000_0000;

    internal static void VerifyTrustedSecurityDescriptor(
        RawSecurityDescriptor descriptor,
        string subject,
        int tamperRights)
    {
        if (descriptor.Owner is not SecurityIdentifier owner || !IsTrustedWriter(owner))
        {
            throw new InvalidOperationException($"{subject} has an untrusted owner");
        }
        if (!descriptor.ControlFlags.HasFlag(ControlFlags.DiscretionaryAclPresent) ||
            descriptor.DiscretionaryAcl is not { Count: > 0 } dacl)
        {
            throw new InvalidOperationException($"{subject} has no protective DACL");
        }

        foreach (GenericAce generic in dacl)
        {
            if (generic.AceFlags.HasFlag(AceFlags.InheritOnly) || !IsAccessAllowedAce(generic.AceType))
            {
                continue;
            }
            if (generic is not QualifiedAce ace || ace is not KnownAce known)
            {
                throw new InvalidOperationException($"{subject} has an unsupported access-allowed entry");
            }
            if ((known.AccessMask & tamperRights) == 0)
            {
                continue;
            }
            if (ace.SecurityIdentifier is null || !IsTrustedWriter(ace.SecurityIdentifier))
            {
                throw new InvalidOperationException($"{subject} grants write access to an untrusted principal");
            }
        }
    }

    private static bool IsAccessAllowedAce(AceType type) =>
        type is AceType.AccessAllowed or
            AceType.AccessAllowedCompound or
            AceType.AccessAllowedObject or
            AceType.AccessAllowedCallback or
            AceType.AccessAllowedCallbackObject;

    private static bool IsTrustedWriter(SecurityIdentifier sid) =>
        sid.IsWellKnown(WellKnownSidType.LocalSystemSid) ||
        sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) ||
        string.Equals(
            sid.Value,
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            StringComparison.Ordinal);

    internal static string ImagePath(SafeProcessHandle process)
    {
        int capacity = 260;
        while (capacity <= 32_768)
        {
            StringBuilder path = new(capacity);
            int length = capacity;
            if (Native.QueryFullProcessImageName(process, 0, path, ref length))
            {
                return path.ToString();
            }
            if (Marshal.GetLastWin32Error() != 122)
            {
                throw new Win32Exception();
            }
            capacity *= 2;
        }
        throw new InvalidOperationException("parent image path is too long");
    }

    private static long CreationTime(SafeProcessHandle process)
    {
        if (!Native.GetProcessTimes(process, out long created, out _, out _, out _))
        {
            throw new Win32Exception();
        }
        return DateTime.FromFileTimeUtc(created).Ticks;
    }

    private static uint SessionId(int processId)
    {
        if (!Native.ProcessIdToSessionId(processId, out uint sessionId))
        {
            throw new Win32Exception();
        }
        return sessionId;
    }

    internal static void EnsureActive(SafeProcessHandle process)
    {
        if (!Native.GetExitCodeProcess(process, out uint exitCode))
        {
            throw new Win32Exception();
        }
        if (exitCode != StillActive)
        {
            throw new InvalidOperationException("parent process exited");
        }
    }
}

internal sealed class BrokerServerLease : IDisposable
{
    private const string AgentExecutableName = "DevolutionsAgent.exe";

    private readonly SafeProcessHandle process;
    private readonly SafeFileHandle image;
    private readonly List<SafeFileHandle> directories;

    private BrokerServerLease(
        SafeProcessHandle process,
        SafeFileHandle image,
        List<SafeFileHandle> directories)
    {
        this.process = process;
        this.image = image;
        this.directories = directories;
    }

    internal static BrokerServerLease Open(SafePipeHandle pipe)
    {
        if (!Native.GetNamedPipeServerProcessId(pipe, out int processId))
        {
            throw new Win32Exception();
        }

        SafeProcessHandle process = Native.OpenProcess(
            PeerLease.ProcessQueryInformation |
                PeerLease.ProcessQueryLimitedInformation |
                PeerLease.Synchronize,
            false,
            processId);
        if (process.IsInvalid)
        {
            throw new Win32Exception();
        }

        try
        {
            if (!PeerLease.IsLocalSystemProcess(process))
            {
                throw new InvalidOperationException("broker server is not running as LocalSystem");
            }
            string helperPath = Environment.ProcessPath
                ?? throw new InvalidOperationException("helper executable path is unavailable");
            string expectedPath = Path.Combine(
                Path.GetDirectoryName(helperPath)
                    ?? throw new InvalidOperationException("helper installation directory is unavailable"),
                AgentExecutableName);
            string serverPath = PeerLease.ImagePath(process);
            if (!IsExpectedPath(serverPath, expectedPath))
            {
                throw new InvalidOperationException("broker server is not the installed Agent");
            }

            SafeFileHandle image = Native.CreateFile(
                serverPath,
                PeerLease.GenericRead |
                    PeerLease.FileExecute |
                    PeerLease.ReadControl |
                    PeerLease.Synchronize,
                PeerLease.FileShareRead,
                IntPtr.Zero,
                PeerLease.OpenExisting,
                PeerLease.FileFlagOpenReparsePoint,
                IntPtr.Zero);
            if (image.IsInvalid)
            {
                throw new Win32Exception();
            }

            try
            {
                PeerLease.VerifyImageMapping(process, image);
                PeerLease.VerifyProtectedPath(image, "broker server image", PeerLease.FileTamperRights);
                using X509Certificate2 signer =
                    PeerLease.VerifyAuthenticodeSigner(serverPath, image, "broker server");
                string thumbprint = signer.GetCertHashString(HashAlgorithmName.SHA1).ToLowerInvariant();
                if (!PeerLease.IsAllowedDevolutionsSigner(thumbprint))
                {
                    throw new InvalidOperationException("broker server signer is not authorized");
                }
                List<SafeFileHandle>? directories = RetainProtectedDirectories(
                    Path.GetDirectoryName(expectedPath)
                        ?? throw new InvalidOperationException("Agent installation directory is unavailable"));
                try
                {
                    PeerLease.VerifyImageMapping(process, image);
                    PeerLease.EnsureActive(process);
                    if (!Native.GetNamedPipeServerProcessId(pipe, out int confirmedProcessId) ||
                        confirmedProcessId != processId)
                    {
                        throw new InvalidOperationException("broker server process changed during authentication");
                    }
                    return new BrokerServerLease(process, image, directories);
                }
                catch
                {
                    foreach (SafeFileHandle directory in directories)
                    {
                        directory.Dispose();
                    }
                    throw;
                }
            }
            catch
            {
                image.Dispose();
                throw;
            }
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }

    internal static bool IsExpectedPath(string actual, string expected) =>
        string.Equals(
            Path.GetFullPath(actual),
            Path.GetFullPath(expected),
            StringComparison.OrdinalIgnoreCase);

    public void Dispose()
    {
        foreach (SafeFileHandle directory in directories)
        {
            directory.Dispose();
        }
        image.Dispose();
        process.Dispose();
    }

    private static List<SafeFileHandle> RetainProtectedDirectories(string installationDirectory)
    {
        List<SafeFileHandle> handles = [];
        try
        {
            int tamperRights = PeerLease.ParentDirectoryTamperRights;
            for (DirectoryInfo? directory = new(Path.GetFullPath(installationDirectory));
                 directory is not null;
                 directory = directory.Parent)
            {
                SafeFileHandle handle = Native.CreateFile(
                    directory.FullName,
                    PeerLease.FileReadAttributes | PeerLease.ReadControl | PeerLease.Synchronize,
                    PeerLease.FileShareRead | PeerLease.FileShareWrite,
                    IntPtr.Zero,
                    PeerLease.OpenExisting,
                    PeerLease.FileFlagBackupSemantics | PeerLease.FileFlagOpenReparsePoint,
                    IntPtr.Zero);
                if (handle.IsInvalid)
                {
                    throw new Win32Exception();
                }
                handles.Add(handle);
                PeerLease.VerifyProtectedPath(
                    handle,
                    $"Agent installation directory '{directory.FullName}'",
                    tamperRights);
                tamperRights = PeerLease.AncestorDirectoryTamperRights;
            }
            return handles;
        }
        catch
        {
            foreach (SafeFileHandle handle in handles)
            {
                handle.Dispose();
            }
            throw;
        }
    }
}

internal static partial class Native
{
    internal const uint WtdRevokeWholeChain = 1;
    internal const uint WtdRevocationCheckChain = 0x0000_0040;
    internal const uint WtdCacheOnlyUrlRetrieval = 0x0000_1000;
    internal const uint WtdDisableMd2Md4 = 0x0000_2000;

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal readonly struct WinTrustFileInfo
    {
        internal readonly uint StructSize;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal readonly string FilePath;
        internal readonly IntPtr FileHandle;
        internal readonly IntPtr KnownSubject;

        internal WinTrustFileInfo(string filePath, IntPtr fileHandle)
        {
            StructSize = checked((uint)Marshal.SizeOf<WinTrustFileInfo>());
            FilePath = filePath;
            FileHandle = fileHandle;
            KnownSubject = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WinTrustData
    {
        internal uint StructSize;
        internal IntPtr PolicyCallbackData;
        internal IntPtr SipClientData;
        internal uint UiChoice;
        internal uint RevocationChecks;
        internal uint UnionChoice;
        internal IntPtr FileInfo;
        internal uint StateAction;
        internal IntPtr StateData;
        internal IntPtr UrlReference;
        internal uint ProviderFlags;
        internal uint UiContext;
        internal IntPtr SignatureSettings;

        internal WinTrustData(IntPtr fileInfo)
        {
            StructSize = checked((uint)Marshal.SizeOf<WinTrustData>());
            PolicyCallbackData = IntPtr.Zero;
            SipClientData = IntPtr.Zero;
            UiChoice = 2;
            RevocationChecks = WtdRevokeWholeChain;
            UnionChoice = 1;
            FileInfo = fileInfo;
            StateAction = 1;
            StateData = IntPtr.Zero;
            UrlReference = IntPtr.Zero;
            ProviderFlags = WtdRevocationCheckChain | WtdDisableMd2Md4;
            UiContext = 0;
            SignatureSettings = IntPtr.Zero;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct CryptProviderSigner
    {
        internal readonly uint StructSize;
        internal readonly NativeFileTime VerifyAsOf;
        internal readonly uint CertificateChainCount;
        internal readonly IntPtr CertificateChain;
        internal readonly uint SignerType;
        internal readonly IntPtr SignerInfo;
        internal readonly uint Error;
        internal readonly uint CounterSignerCount;
        internal readonly IntPtr CounterSigners;
        internal readonly IntPtr ChainContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct NativeFileTime
    {
        internal readonly uint LowDateTime;
        internal readonly uint HighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct ByHandleFileInformation
    {
        internal readonly uint FileAttributes;
        internal readonly NativeFileTime CreationTime;
        internal readonly NativeFileTime LastAccessTime;
        internal readonly NativeFileTime LastWriteTime;
        internal readonly uint VolumeSerialNumber;
        internal readonly uint FileSizeHigh;
        internal readonly uint FileSizeLow;
        internal readonly uint NumberOfLinks;
        internal readonly uint FileIndexHigh;
        internal readonly uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal readonly struct CryptProviderCertificate
    {
        internal readonly uint StructSize;
        internal readonly IntPtr CertificateContext;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageName(
        SafeProcessHandle process,
        uint flags,
        [Out] StringBuilder path,
        ref int size);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetProcessTimes(
        SafeProcessHandle process,
        out long creation,
        out long exit,
        out long kernel,
        out long user);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool ProcessIdToSessionId(int processId, out uint sessionId);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetFileInformationByHandle(
        SafeFileHandle file,
        out ByHandleFileInformation information);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool OpenProcessToken(
        SafeProcessHandle process,
        uint desiredAccess,
        out SafeAccessTokenHandle token);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetTokenInformation(
        SafeAccessTokenHandle token,
        int informationClass,
        IntPtr information,
        uint informationLength,
        out uint returnLength);

    [LibraryImport("advapi32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool IsWellKnownSid(IntPtr sid, int wellKnownSidType);

    [LibraryImport("advapi32.dll", SetLastError = true)]
    internal static partial uint GetSecurityInfo(
        SafeFileHandle handle,
        uint objectType,
        uint securityInformation,
        out IntPtr owner,
        out IntPtr group,
        out IntPtr dacl,
        out IntPtr sacl,
        out IntPtr securityDescriptor);

    [LibraryImport("advapi32.dll")]
    internal static partial uint GetSecurityDescriptorLength(IntPtr securityDescriptor);

    [LibraryImport("kernel32.dll")]
    internal static partial IntPtr LocalFree(IntPtr memory);

    [LibraryImport("kernel32.dll", EntryPoint = "CreateFileW", SetLastError = true, StringMarshalling = StringMarshalling.Utf16)]
    internal static partial SafeFileHandle CreateFile(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    internal static partial SafeProcessHandle OpenProcess(uint desiredAccess, [MarshalAs(UnmanagedType.Bool)] bool inherit, int processId);

    [LibraryImport("ntdll.dll")]
    internal static partial int NtQueryInformationProcess(
        IntPtr process,
        int informationClass,
        ref IntPtr information,
        int informationLength,
        out int returnLength);

    [LibraryImport("wintrust.dll", SetLastError = true)]
    internal static partial int WinVerifyTrust(IntPtr window, ref Guid action, IntPtr data);

    [LibraryImport("wintrust.dll")]
    internal static partial IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

    [LibraryImport("wintrust.dll")]
    internal static partial IntPtr WTHelperGetProvSignerFromChain(
        IntPtr providerData,
        uint signerIndex,
        [MarshalAs(UnmanagedType.Bool)] bool counterSigner,
        uint counterSignerIndex);

    [LibraryImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static partial bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out int processId);
}
