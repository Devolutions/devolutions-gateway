using System;
using System.IO;
using System.Linq;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;

namespace DevolutionsGateway.Helpers
{
    internal static class PrivateKeyPermissions
    {
        /// <summary>
        /// Returns true if the NETWORK SERVICE account has an explicit Allow rule granting Read
        /// permission on the certificate's private key file. Returns false if the key file cannot
        /// be located, the ACL cannot be read, or no such Allow rule is present.
        /// </summary>
        /// <remarks>
        /// This is an approximation of effective access — it does not honor:
        /// <list type="bullet">
        ///   <item>Explicit Deny rules on the NETWORK SERVICE SID (which would override an Allow
        ///   and block read access).</item>
        ///   <item>Permissions granted via group membership (NETWORK SERVICE is a member of
        ///   Authenticated Users and Users; if either group has Read on this file, NETWORK SERVICE
        ///   effectively does too — but this method returns false).</item>
        /// </list>
        /// Acceptable for the use case this helper serves: cert key files in
        /// <c>%ProgramData%\Microsoft\Crypto\Keys\</c> default to explicit per-identity ACLs without
        /// group inheritance for NETWORK SERVICE and without Deny rules, so the approximation is
        /// accurate in practice. A false negative leads to a redundant idempotent grant via
        /// <see cref="TryGrantNetworkServiceReadPermission"/>. A false positive (effective Deny we
        /// can't see) surfaces as a service start-time failure rather than at install time.
        /// </remarks>
        internal static bool HasNetworkServiceReadPermission(X509Certificate2 certificate)
        {
            if (!TryGetKeyFilePath(certificate, out string keyFilePath))
            {
                return false;
            }

            try
            {
                FileSecurity security = new FileInfo(keyFilePath).GetAccessControl();
                SecurityIdentifier networkService = new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null);

                AuthorizationRuleCollection rules = security.GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));

                return rules
                    .Cast<FileSystemAccessRule>()
                    .Any(r =>
                        r.IdentityReference.Equals(networkService) &&
                        r.AccessControlType == AccessControlType.Allow &&
                        (r.FileSystemRights & FileSystemRights.Read) == FileSystemRights.Read);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Grants NETWORK SERVICE Read permission on the certificate's private key file.
        /// Returns false (with error) if the key file cannot be located or the ACL cannot be modified.
        /// </summary>
        internal static bool TryGrantNetworkServiceReadPermission(X509Certificate2 certificate, out Exception error)
        {
            error = null;

            if (!TryGetKeyFilePath(certificate, out string keyFilePath))
            {
                error = new InvalidOperationException("Could not locate the private key file for this certificate.");
                return false;
            }

            try
            {
                FileInfo keyFileInfo = new FileInfo(keyFilePath);
                FileSecurity security = keyFileInfo.GetAccessControl();
                SecurityIdentifier networkService = new SecurityIdentifier(WellKnownSidType.NetworkServiceSid, null);

                // Skip if an identical explicit Allow rule already exists, so repeat calls don't
                // grow the ACL with duplicate entries.
                bool alreadyGranted = security
                    .GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
                    .Cast<FileSystemAccessRule>()
                    .Any(r =>
                        r.IdentityReference.Equals(networkService) &&
                        r.AccessControlType == AccessControlType.Allow &&
                        (r.FileSystemRights & FileSystemRights.Read) == FileSystemRights.Read);

                if (alreadyGranted)
                {
                    return true;
                }

                security.AddAccessRule(new FileSystemAccessRule(networkService, FileSystemRights.Read, AccessControlType.Allow));
                keyFileInfo.SetAccessControl(security);

                return true;
            }
            catch (Exception e)
            {
                error = e;
                return false;
            }
        }

        private static bool TryGetKeyFilePath(X509Certificate2 certificate, out string path)
        {
            path = null;

            if (certificate == null || !certificate.HasPrivateKey)
            {
                return false;
            }

            try
            {
                using (RSA rsa = certificate.GetRSAPrivateKey())
                {
                    if (rsa is RSACng rsaCng)
                    {
                        return TryFindKeyFileByUniqueName(rsaCng.Key.UniqueName, out path);
                    }
                }
            }
            catch
            {
            }

            try
            {
                using (ECDsa ecdsa = certificate.GetECDsaPrivateKey())
                {
                    if (ecdsa is ECDsaCng ecdsaCng)
                    {
                        return TryFindKeyFileByUniqueName(ecdsaCng.Key.UniqueName, out path);
                    }
                }
            }
            catch
            {
            }

            try
            {
                if (certificate.PrivateKey is RSACryptoServiceProvider csp)
                {
                    return TryFindCapiKeyFile(csp.CspKeyContainerInfo, out path);
                }
            }
            catch
            {
            }

            return false;
        }

        // On Windows 10+, `GetRSAPrivateKey` returns `RSACng` even for keys provisioned via a legacy
        // CAPI provider (e.g. "Microsoft Enhanced Cryptographic Provider v1.0"), because Windows
        // wraps CAPI keys through the CNG compatibility layer. The `UniqueName` returned by the
        // wrapper is a filename of the same shape in both cases — only the parent directory differs.
        // We therefore probe both the CNG (`Crypto\Keys`) and CAPI (`Crypto\RSA\MachineKeys`)
        // locations rather than trusting the wrapper type to imply storage location.
        private static bool TryFindKeyFileByUniqueName(string uniqueName, out string path)
        {
            path = null;

            if (string.IsNullOrEmpty(uniqueName))
            {
                return false;
            }

            string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
            string roamingAppData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            string[] candidates = new[]
            {
                Path.Combine(programData,    "Microsoft", "Crypto", "Keys",            uniqueName), // CNG  machine
                Path.Combine(programData,    "Microsoft", "Crypto", "RSA", "MachineKeys", uniqueName), // CAPI machine
                Path.Combine(roamingAppData, "Microsoft", "Crypto", "Keys",            uniqueName), // CNG  user
            };

            foreach (string candidate in candidates)
            {
                if (File.Exists(candidate))
                {
                    path = candidate;
                    return true;
                }
            }

            return false;
        }

        private static bool TryFindCapiKeyFile(CspKeyContainerInfo info, out string path)
        {
            path = null;

            if (info == null || string.IsNullOrEmpty(info.UniqueKeyContainerName))
            {
                return false;
            }

            // User-key CAPI paths require the user SID in the path and are not relevant
            // for server certificates, which are always stored in the machine key store.
            if (!info.MachineKeyStore)
            {
                return false;
            }

            string candidate = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft", "Crypto", "RSA", "MachineKeys", info.UniqueKeyContainerName);

            if (!File.Exists(candidate))
            {
                return false;
            }

            path = candidate;
            return true;
        }
    }
}
