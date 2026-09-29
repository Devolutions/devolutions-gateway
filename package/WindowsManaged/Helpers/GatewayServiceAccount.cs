using System;
using System.ComponentModel;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using DevolutionsGateway.Actions;

namespace DevolutionsGateway.Helpers
{
    internal enum ServiceAccountKind
    {
        /// <summary>
        /// NT AUTHORITY\NetworkService, the default. Passwordless.
        /// </summary>
        NetworkService,

        /// <summary>
        /// The virtual account of the Gateway service itself (NT SERVICE\DevolutionsGateway). Passwordless.
        /// </summary>
        VirtualAccount,

        /// <summary>
        /// A standalone or group managed service account (DOMAIN\name$). Passwordless.
        /// </summary>
        ManagedServiceAccount,

        /// <summary>
        /// A regular local or domain user. Requires a password.
        /// </summary>
        User,
    }

    /// <summary>
    /// The Windows account the Gateway service is configured to log on as.
    /// </summary>
    internal sealed class GatewayServiceAccount
    {
        internal const string DefaultName = "NT AUTHORITY\\NetworkService";

        private const string VirtualAccountDomain = "NT SERVICE";

        private const string VirtualAccountSidPrefix = "S-1-5-80-";

        /// <summary>
        /// Canonical DOMAIN\Name form of the account, suitable for the service control manager.
        /// </summary>
        internal string Name { get; private set; }

        internal SecurityIdentifier Sid { get; private set; }

        internal ServiceAccountKind Kind { get; private set; }

        internal bool RequiresPassword => this.Kind == ServiceAccountKind.User;

        internal static SecurityIdentifier NetworkServiceSid => new(WellKnownSidType.NetworkServiceSid, null);

        internal static GatewayServiceAccount NetworkService => new()
        {
            Name = DefaultName,
            Sid = NetworkServiceSid,
            Kind = ServiceAccountKind.NetworkService,
        };

        /// <summary>
        /// Resolve an account name (as given on the command line or read back from the service control manager)
        /// into a SID and classify it. An empty name resolves to NETWORK SERVICE.
        /// </summary>
        /// <param name="name">The account name, in DOMAIN\Name, .\Name or UPN form</param>
        /// <param name="serviceName">The name of the service, used to validate a virtual account</param>
        /// <param name="account">The resolved account</param>
        /// <param name="error">A user-facing reason the account is not acceptable</param>
        internal static bool TryResolve(string name, string serviceName, out GatewayServiceAccount account, out string error)
        {
            account = null;
            error = null;

            name = (name ?? string.Empty).Trim();

            if (name.Length == 0)
            {
                account = NetworkService;
                return true;
            }

            if (name.StartsWith(".\\", StringComparison.Ordinal))
            {
                name = $"{Environment.MachineName}{name.Substring(1)}";
            }

            string virtualName = $"{VirtualAccountDomain}\\{serviceName}";
            if (string.Equals(name, virtualName, StringComparison.OrdinalIgnoreCase))
            {
                // SCM derives the service SID from the uppercase UTF-16 name, even before the service exists.
                using SHA1 hash = SHA1.Create();
                byte[] digest = hash.ComputeHash(Encoding.Unicode.GetBytes(serviceName.ToUpperInvariant()));
                string authorities = string.Join("-", Enumerable.Range(0, 5).Select(index => BitConverter.ToUInt32(digest, index * 4)));
                account = new GatewayServiceAccount
                {
                    Name = virtualName,
                    Sid = new SecurityIdentifier($"{VirtualAccountSidPrefix}{authorities}"),
                    Kind = ServiceAccountKind.VirtualAccount,
                };
                return true;
            }

            SecurityIdentifier sid;
            string canonicalName;
            int accountType;

            try
            {
                sid = (SecurityIdentifier)new NTAccount(name).Translate(typeof(SecurityIdentifier));
                canonicalName = ((NTAccount)sid.Translate(typeof(NTAccount))).Value;
                accountType = GetAccountType(sid);
            }
            catch (IdentityNotMappedException)
            {
                error = $"The service account '{name}' could not be found.";
                return false;
            }
            catch (Exception e)
            {
                error = $"The service account '{name}' could not be resolved: {e.Message}";
                return false;
            }

            if (sid.IsWellKnown(WellKnownSidType.NetworkServiceSid))
            {
                account = NetworkService;
                return true;
            }

            if (sid.IsWellKnown(WellKnownSidType.LocalSystemSid) || sid.IsWellKnown(WellKnownSidType.LocalServiceSid))
            {
                error = $"The service account '{canonicalName}' is not supported. Use NETWORK SERVICE, the NT SERVICE\\{serviceName} virtual account, a managed service account, or a user account.";
                return false;
            }

            if (sid.Value.StartsWith(VirtualAccountSidPrefix, StringComparison.Ordinal))
            {
                string expected = $"{VirtualAccountDomain}\\{serviceName}";

                if (!string.Equals(canonicalName, expected, StringComparison.OrdinalIgnoreCase))
                {
                    error = $"The virtual account '{canonicalName}' does not belong to this service. Use '{expected}'.";
                    return false;
                }

                account = new GatewayServiceAccount
                {
                    Name = expected,
                    Sid = sid,
                    Kind = ServiceAccountKind.VirtualAccount,
                };

                return true;
            }

            if (sid.AccountDomainSid is null)
            {
                error = $"'{canonicalName}' is not a user account and cannot be used as the service account.";
                return false;
            }

            bool managed;
            try
            {
                managed = IsManagedServiceAccount(canonicalName);
            }
            catch (Win32Exception e)
            {
                error = $"The managed service account status of '{canonicalName}' could not be checked: {e.Message}";
                return false;
            }

            if (!managed && accountType != 1) // SidTypeUser
            {
                error = $"'{canonicalName}' is not a user or an installed managed service account. Managed accounts must be installed on this host before setup.";
                return false;
            }

            account = new GatewayServiceAccount
            {
                Name = canonicalName,
                Sid = sid,
                Kind = managed ? ServiceAccountKind.ManagedServiceAccount : ServiceAccountKind.User,
            };

            return true;
        }

        /// <summary>
        /// Validate credentials before an upgrade can remove the existing service.
        /// </summary>
        internal bool TryValidatePassword(string password, out string error)
        {
            error = null;

            int separator = this.Name.IndexOf('\\');
            string domain = separator > 0 ? this.Name.Substring(0, separator) : null;
            string user = separator > 0 ? this.Name.Substring(separator + 1) : this.Name;

            if (!WinAPI.LogonUser(user, domain, password ?? string.Empty, WinAPI.LOGON32_LOGON_NETWORK, WinAPI.LOGON32_PROVIDER_DEFAULT, out IntPtr token))
            {
                int lastError = Marshal.GetLastWin32Error();

                switch (lastError)
                {
                    case 1326: // ERROR_LOGON_FAILURE
                        error = $"The password for the service account '{this.Name}' is incorrect.";
                        return false;
                    case 1330: // ERROR_PASSWORD_EXPIRED
                    case 1331: // ERROR_ACCOUNT_DISABLED
                    case 1793: // ERROR_ACCOUNT_EXPIRED
                    case 1907: // ERROR_PASSWORD_MUST_CHANGE
                    case 1909: // ERROR_ACCOUNT_LOCKED_OUT
                        error = $"The service account '{this.Name}' cannot log on: {new System.ComponentModel.Win32Exception(lastError).Message}";
                        return false;
                    default:
                        error = $"The credentials for '{this.Name}' could not be validated: {new Win32Exception(lastError).Message}";
                        return false;
                }
            }

            WinAPI.CloseHandle(token);
            return true;
        }

        private static bool IsManagedServiceAccount(string canonicalName)
        {
            int separator = canonicalName.IndexOf('\\');
            string samAccountName = separator >= 0 ? canonicalName.Substring(separator + 1) : canonicalName;

            if (!samAccountName.EndsWith("$", StringComparison.Ordinal) ||
                canonicalName.StartsWith($"{Environment.MachineName}\\", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            uint status = WinAPI.NetIsServiceAccount(null, canonicalName, out bool isServiceAccount);
            if (status != 0)
            {
                throw new Win32Exception((int)WinAPI.LsaNtStatusToWinError(status));
            }

            return isServiceAccount;
        }

        private static int GetAccountType(SecurityIdentifier sid)
        {
            byte[] bytes = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bytes, 0);
            uint nameLength = 0;
            uint domainLength = 0;
            WinAPI.LookupAccountSid(null, bytes, null, ref nameLength, null, ref domainLength, out int accountType);
            int error = Marshal.GetLastWin32Error();
            if (error != 122) // ERROR_INSUFFICIENT_BUFFER
            {
                throw new Win32Exception(error);
            }

            StringBuilder name = new(checked((int)nameLength));
            StringBuilder domain = new(checked((int)domainLength));
            if (!WinAPI.LookupAccountSid(null, bytes, name, ref nameLength, domain, ref domainLength, out accountType))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            return accountType;
        }
    }
}
