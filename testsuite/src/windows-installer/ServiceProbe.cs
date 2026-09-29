using System;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Principal;
using System.Text;

namespace GatewayInstallerTests
{
    public static class ServiceProbe
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);
        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);
        [DllImport("advapi32.dll")]
        private static extern uint LsaOpenPolicy(IntPtr system, ref ObjectAttributes attributes, uint access, out IntPtr policy);
        [DllImport("advapi32.dll")]
        private static extern uint LsaAddAccountRights(IntPtr policy, byte[] sid, UnicodeString[] rights, uint count);
        [DllImport("advapi32.dll")]
        private static extern uint LsaRemoveAccountRights(IntPtr policy, byte[] sid, bool all, IntPtr rights, uint count);
        [DllImport("advapi32.dll")]
        private static extern uint LsaClose(IntPtr policy);
        [DllImport("advapi32.dll")]
        private static extern uint LsaNtStatusToWinError(uint status);
        [DllImport("advapi32.dll")]
        private static extern uint LsaEnumerateAccountRights(IntPtr policy, byte[] sid, out IntPtr rights, out uint count);
        [DllImport("advapi32.dll")]
        private static extern uint LsaFreeMemory(IntPtr buffer);
        [DllImport("logoncli.dll", CharSet = CharSet.Unicode)]
        private static extern uint NetIsServiceAccount(string server, string account, out bool managed);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManager(string machine, string database, uint access);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenService(IntPtr manager, string name, uint access);
        [DllImport("advapi32.dll")]
        private static extern bool CloseServiceHandle(IntPtr handle);
        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ChangeServiceConfig(IntPtr service, uint type, uint start, uint error,
            string path, string group, IntPtr tag, string dependencies, string account, string password, string displayName);

        public static void RestoreGatewayAccount(string account, string password)
        {
            IntPtr manager = OpenSCManager(null, null, 1);
            if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            try
            {
                IntPtr service = OpenService(manager, "DevolutionsGateway", 2);
                if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                try
                {
                    if (!ChangeServiceConfig(service, UInt32.MaxValue, UInt32.MaxValue, UInt32.MaxValue,
                        null, null, IntPtr.Zero, null, account, password, null))
                        throw new Win32Exception(Marshal.GetLastWin32Error());
                }
                finally { CloseServiceHandle(service); }
            }
            finally { CloseServiceHandle(manager); }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeString
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr Buffer;
        }

        public static bool HasExplicitServiceLogonRight(string stringSid)
        {
            SecurityIdentifier sid = new SecurityIdentifier(stringSid);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            ObjectAttributes attributes = new ObjectAttributes { Length = (uint)Marshal.SizeOf(typeof(ObjectAttributes)) };
            IntPtr policy;
            CheckStatus(LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x800, out policy));
            try
            {
                IntPtr rights;
                uint count;
                uint status = LsaEnumerateAccountRights(policy, bytes, out rights, out count);
                if (status == 0xC0000034) return false;
                CheckStatus(status);
                try
                {
                    for (uint index = 0; index < count; index++)
                    {
                        UnicodeString right = (UnicodeString)Marshal.PtrToStructure(
                            IntPtr.Add(rights, checked((int)index * Marshal.SizeOf(typeof(UnicodeString)))), typeof(UnicodeString));
                        if (Marshal.PtrToStringUni(right.Buffer, right.Length / 2) == "SeServiceLogonRight") return true;
                    }
                    return false;
                }
                finally { LsaFreeMemory(rights); }
            }
            finally { LsaClose(policy); }
        }

        private static WindowsIdentity ServiceIdentity(int processId)
        {
            IntPtr process = OpenProcess(0x1000, false, processId);
            if (process == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed for service PID " + processId);
            try
            {
                IntPtr token;
                if (!OpenProcessToken(process, 0x000A, out token))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed for service PID " + processId);
                try { return new WindowsIdentity(token); }
                finally { CloseHandle(token); }
            }
            finally { CloseHandle(process); }
        }

        public static string UserSid(int processId)
        {
            using (WindowsIdentity identity = ServiceIdentity(processId))
                return identity.User.Value;
        }

        public static string[] GroupSids(int processId)
        {
            using (WindowsIdentity identity = ServiceIdentity(processId))
                return identity.Groups.Select(group => group.Value).ToArray();
        }

        public static bool CanOpen(int processId, string path, bool write)
        {
            using (WindowsIdentity identity = ServiceIdentity(processId))
            using (WindowsImpersonationContext impersonation = identity.Impersonate())
            {
                try
                {
                    using (FileStream stream = File.Open(path, FileMode.Open,
                        write ? FileAccess.ReadWrite : FileAccess.Read, FileShare.ReadWrite))
                        return true;
                }
                catch (UnauthorizedAccessException) { return false; }
            }
        }

        public static void WriteAndDelete(int processId, string path)
        {
            using (WindowsIdentity identity = ServiceIdentity(processId))
            using (WindowsImpersonationContext impersonation = identity.Impersonate())
            {
                File.WriteAllText(path, "service-token-write");
                if (File.ReadAllText(path) != "service-token-write")
                    throw new IOException("service-token readback failed");
                File.Delete(path);
            }
        }

        public static bool IsManaged(string samAccountName)
        {
            bool managed;
            CheckStatus(NetIsServiceAccount(null, samAccountName, out managed));
            return managed;
        }

        public static void CheckTls(int port, string thumbprint)
        {
            using (TcpClient client = new TcpClient())
            {
                client.ReceiveTimeout = 10000;
                client.SendTimeout = 10000;
                client.Connect("127.0.0.1", port);
                using (SslStream tls = new SslStream(client.GetStream(), false,
                    (sender, certificate, chain, errors) => certificate != null &&
                        String.Equals(certificate.GetCertHashString(), thumbprint, StringComparison.OrdinalIgnoreCase)))
                {
                    tls.AuthenticateAsClient("localhost", null, SslProtocols.Tls12, false);
                    byte[] request = Encoding.ASCII.GetBytes("GET /jet/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
                    tls.Write(request, 0, request.Length);
                    using (StreamReader reader = new StreamReader(tls))
                    {
                        string status = reader.ReadLine();
                        if (status == null || !status.Contains(" 200 "))
                            throw new IOException("TLS health request failed: " + status);
                    }
                }
            }
        }

        public static void SetTestAccountRights(string stringSid, bool remove)
        {
            SecurityIdentifier sid = new SecurityIdentifier(stringSid);
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            ObjectAttributes attributes = new ObjectAttributes { Length = (uint)Marshal.SizeOf(typeof(ObjectAttributes)) };
            IntPtr policy;
            CheckStatus(LsaOpenPolicy(IntPtr.Zero, ref attributes, 0x810, out policy));
            try
            {
                if (remove)
                {
                    uint status = LsaRemoveAccountRights(policy, bytes, true, IntPtr.Zero, 0);
                    if (status != 0xC0000034) // No rights were assigned to this test account.
                        CheckStatus(status);
                    return;
                }
                string right = "SeServiceLogonRight";
                UnicodeString value = new UnicodeString {
                    Buffer = Marshal.StringToHGlobalUni(right),
                    Length = (ushort)(right.Length * 2),
                    MaximumLength = (ushort)((right.Length + 1) * 2)
                };
                try { CheckStatus(LsaAddAccountRights(policy, bytes, new[] { value }, 1)); }
                finally { Marshal.FreeHGlobal(value.Buffer); }
            }
            finally { LsaClose(policy); }
        }

        private static void CheckStatus(uint status)
        {
            if (status != 0)
                throw new Win32Exception((int)LsaNtStatusToWinError(status));
        }
    }
}
