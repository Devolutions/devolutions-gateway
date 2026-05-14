using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace DevolutionsGateway.Helpers
{
    internal enum CertificateChainStatus
    {
        /// Chain is complete from the file alone (or self-signed). No warning needed.
        Ok,
        /// Chain builds only because the system store has the intermediate. Soft warning:
        /// the gateway's server.crt won't include it, so clients on other machines may fail.
        SystemStoreRequired,
        /// Chain uses a weak signature algorithm (typically MD5 or SHA-1).
        /// Modern TLS clients are likely to reject the certificate.
        WeakSignature,
        /// Chain anchors at a root that is not in the system's Trusted Root store.
        /// Likely a private CA — clients without that root installed will fail to verify.
        UntrustedRoot,
        /// PartialChain even with the system store. Hard warning: no client can verify this cert.
        Incomplete,
        /// A certificate in the chain has an invalid signature.
        /// The chain may have been tampered with or is corrupted.
        InvalidSignature,
        /// The issuer is in the system's Untrusted Certificates store (actively distrusted).
        ExplicitDistrust,
        /// An exception prevented chain validation from completing.
        /// Distinct from Ok — the caller should treat this as "unable to determine."
        ValidationFailed,
    }

    [Flags]
    internal enum CertificateIssues
    {
        None = 0,
        /// Certificate validity period has not started yet.
        NotYetValid = 1 << 0,
        /// Certificate has expired.
        Expired = 1 << 1,
        /// Certificate is valid but expires within the warning threshold.
        ExpiringSoon = 1 << 2,
        /// Extended Key Usage extension is absent or does not include serverAuth (1.3.6.1.5.5.7.3.1).
        /// The gateway rejects this in strict mode; many TLS clients require it unconditionally.
        MissingServerAuthEku = 1 << 3,
        /// Subject Alternative Name extension is absent.
        /// The gateway rejects this in strict mode; all modern TLS clients require it.
        MissingSubjectAlternativeName = 1 << 4,
    }

    internal static class CertificateChain
    {
        private const string PemCertHeader = "-----BEGIN CERTIFICATE-----";
        private const string PemCertFooter = "-----END CERTIFICATE-----";
        private const string ServerAuthOid = "1.3.6.1.5.5.7.3.1";
        private const string SubjectAlternativeNameOid = "2.5.29.17";
        private const string ExtendedKeyUsageOid = "2.5.29.37";
        private const int ExpiringSoonDays = 30;

        /// <summary>
        /// Disposes every certificate in the collection. Safe to call with a null collection.
        /// Callers of TryLoad must invoke this once validation is complete to avoid leaking
        /// transient key files into %APPDATA%\Microsoft\Crypto\Keys.
        /// </summary>
        internal static void DisposeAll(X509Certificate2Collection certificates)
        {
            if (certificates == null)
            {
                return;
            }

            foreach (X509Certificate2 cert in certificates)
            {
                cert?.Dispose();
            }
        }

        /// <summary>
        /// Loads all certificates from a file. Handles PFX, PEM chains, and DER.
        /// Callers must pass the returned collection to <see cref="DisposeAll"/> when done.
        /// </summary>
        internal static bool TryLoad(string path, string password, out X509Certificate2Collection certificates, out Exception error)
        {
            certificates = null;
            error = null;

            try
            {
                string ext = Path.GetExtension(path);
                bool isPfx = string.Equals(ext, ".pfx", StringComparison.OrdinalIgnoreCase) ||
                             string.Equals(ext, ".p12", StringComparison.OrdinalIgnoreCase);

                if (isPfx)
                {
                    certificates = ImportPfx(path, password);
                    return true;
                }

                byte[] bytes = File.ReadAllBytes(path);
                string text = TryReadUtf8(bytes);

                if (text != null && text.Contains(PemCertHeader))
                {
                    certificates = LoadPemChain(text);
                    return true;
                }

                certificates = new X509Certificate2Collection(new X509Certificate2(bytes));
                return true;
            }
            catch (Exception e)
            {
                error = e;
                return false;
            }
        }

        /// <summary>
        /// Returns the leaf certificate (non-CA) from a collection, or the first cert if none qualifies.
        /// Returns null if the collection is null, empty, or an error occurs.
        /// </summary>
        internal static X509Certificate2 FindLeaf(X509Certificate2Collection certificates)
        {
            try
            {
                if (certificates == null || certificates.Count == 0)
                {
                    return null;
                }

                return certificates.Cast<X509Certificate2>().FirstOrDefault(c => !IsCa(c))
                       ?? certificates.Cast<X509Certificate2>().First();
            }
            catch
            {
                return null;
            }
        }

        /// <summary>
        /// Returns true when the certificate is self-signed (subject == issuer by raw bytes).
        /// Returns false if the certificate is null or an error occurs.
        /// </summary>
        internal static bool IsSelfSigned(X509Certificate2 certificate)
        {
            try
            {
                if (certificate == null)
                {
                    return false;
                }

                return certificate.SubjectName.RawData.SequenceEqual(certificate.IssuerName.RawData);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Returns true if the certificate is a CA certificate (BasicConstraints CA=true).
        /// Returns false if the certificate is null, lacks BasicConstraints, or an error occurs.
        /// </summary>
        internal static bool IsCertificateAuthority(X509Certificate2 certificate)
        {
            try
            {
                if (certificate == null)
                {
                    return false;
                }

                return IsCa(certificate);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Evaluates the chain completeness for a leaf certificate against the certs in the file.
        /// Returns Ok when the leaf is null (nothing to validate). Returns ValidationFailed when an
        /// exception is thrown during chain building, so callers can distinguish a clean build from
        /// an indeterminate outcome.
        /// </summary>
        internal static CertificateChainStatus CheckChain(X509Certificate2 leaf, X509Certificate2Collection fileCertificates)
        {
            if (leaf == null)
            {
                return CertificateChainStatus.Ok;
            }

            try
            {
                using (X509Chain chain = new X509Chain())
                {
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.ExtraStore.AddRange(fileCertificates);
                    chain.Build(leaf);

                    // Order is severity-first: a fundamental chain failure or a tampered/distrusted
                    // chain takes precedence over weaker issues like an untrusted root or weak hash.
                    if (HasStatus(chain, X509ChainStatusFlags.PartialChain))
                    {
                        return CertificateChainStatus.Incomplete;
                    }

                    if (HasStatus(chain, X509ChainStatusFlags.NotSignatureValid))
                    {
                        return CertificateChainStatus.InvalidSignature;
                    }

                    if (HasStatus(chain, X509ChainStatusFlags.ExplicitDistrust))
                    {
                        return CertificateChainStatus.ExplicitDistrust;
                    }

                    if (HasStatus(chain, X509ChainStatusFlags.UntrustedRoot))
                    {
                        return CertificateChainStatus.UntrustedRoot;
                    }

                    if (HasStatus(chain, X509ChainStatusFlags.HasWeakSignature))
                    {
                        return CertificateChainStatus.WeakSignature;
                    }

                    if (IntermediatesFromSystemStore(chain, fileCertificates))
                    {
                        return CertificateChainStatus.SystemStoreRequired;
                    }
                }

                return CertificateChainStatus.Ok;
            }
            catch
            {
                return CertificateChainStatus.ValidationFailed;
            }
        }

        private static bool HasStatus(X509Chain chain, X509ChainStatusFlags flag)
        {
            return chain.ChainStatus.Any(s => s.Status.HasFlag(flag));
        }

        /// <summary>
        /// Checks a leaf certificate for common issues that will cause the gateway or TLS clients to reject it.
        /// Returns None if the certificate is null or an error occurs, to avoid false positives.
        /// </summary>
        internal static CertificateIssues CheckCertificate(X509Certificate2 certificate)
        {
            if (certificate == null)
            {
                return CertificateIssues.None;
            }

            try
            {
                CertificateIssues issues = CertificateIssues.None;
                DateTime now = DateTime.Now;

                if (now < certificate.NotBefore)
                {
                    issues |= CertificateIssues.NotYetValid;
                }
                else if (now > certificate.NotAfter)
                {
                    issues |= CertificateIssues.Expired;
                }
                else if (certificate.NotAfter < now.AddDays(ExpiringSoonDays))
                {
                    issues |= CertificateIssues.ExpiringSoon;
                }

                bool hasServerAuthEku = false;
                bool hasEkuExtension = false;
                bool hasSan = false;

                foreach (X509Extension ext in certificate.Extensions)
                {
                    switch (ext.Oid.Value)
                    {
                        case ExtendedKeyUsageOid:
                            hasEkuExtension = true;
                            X509EnhancedKeyUsageExtension eku = ext as X509EnhancedKeyUsageExtension;
                            if (eku != null)
                            {
                                foreach (Oid usage in eku.EnhancedKeyUsages)
                                {
                                    if (usage.Value == ServerAuthOid)
                                    {
                                        hasServerAuthEku = true;
                                        break;
                                    }
                                }
                            }
                            break;

                        case SubjectAlternativeNameOid:
                            hasSan = true;
                            break;
                    }
                }

                // Absence of the EKU extension entirely is treated the same as EKU present
                // but serverAuth missing: the gateway flags both cases identically.
                if (!hasEkuExtension || !hasServerAuthEku)
                {
                    issues |= CertificateIssues.MissingServerAuthEku;
                }

                if (!hasSan)
                {
                    issues |= CertificateIssues.MissingSubjectAlternativeName;
                }

                return issues;
            }
            catch
            {
                return CertificateIssues.None;
            }
        }

        private static bool IntermediatesFromSystemStore(X509Chain chain, X509Certificate2Collection fileCertificates)
        {
            HashSet<string> fileThumbprints = new HashSet<string>(
                fileCertificates.Cast<X509Certificate2>().Select(c => c.Thumbprint),
                StringComparer.OrdinalIgnoreCase);

            // ChainElements[0] is the leaf, ChainElements[last] is the root.
            // Only intermediates (everything between) could have come from the system store.
            for (int i = 1; i < chain.ChainElements.Count - 1; i++)
            {
                if (!fileThumbprints.Contains(chain.ChainElements[i].Certificate.Thumbprint))
                {
                    return true;
                }
            }

            return false;
        }

        private static X509Certificate2Collection ImportPfx(string path, string password)
        {
            if (string.IsNullOrWhiteSpace(password))
            {
                // Null and empty string map to different Win32 PFXImportCertStore calls.
                // Try null first (most common), then empty string as a fallback for PFX files
                // that were created with an explicit empty password.
                try
                {
                    X509Certificate2Collection col = new X509Certificate2Collection();
                    col.Import(path, null, X509KeyStorageFlags.DefaultKeySet);
                    return col;
                }
                catch
                {
                    X509Certificate2Collection col = new X509Certificate2Collection();
                    col.Import(path, string.Empty, X509KeyStorageFlags.DefaultKeySet);
                    return col;
                }
            }

            X509Certificate2Collection result = new X509Certificate2Collection();
            result.Import(path, password, X509KeyStorageFlags.DefaultKeySet);
            return result;
        }

        private static X509Certificate2Collection LoadPemChain(string pem)
        {
            X509Certificate2Collection col = new X509Certificate2Collection();
            int pos = 0;

            while (true)
            {
                int start = pem.IndexOf(PemCertHeader, pos, StringComparison.Ordinal);
                if (start < 0)
                {
                    break;
                }

                int end = pem.IndexOf(PemCertFooter, start, StringComparison.Ordinal);
                if (end < 0)
                {
                    break;
                }

                end += PemCertFooter.Length;

                string body = pem.Substring(start + PemCertHeader.Length, end - PemCertFooter.Length - start - PemCertHeader.Length);
                byte[] der = Convert.FromBase64String(body.Trim());
                col.Add(new X509Certificate2(der));

                pos = end;
            }

            return col;
        }

        private static bool IsCa(X509Certificate2 certificate)
        {
            foreach (X509Extension ext in certificate.Extensions)
            {
                if (ext is X509BasicConstraintsExtension bc)
                {
                    return bc.CertificateAuthority;
                }
            }

            return false;
        }

        private static string TryReadUtf8(byte[] bytes)
        {
            try
            {
                return Encoding.UTF8.GetString(bytes);
            }
            catch
            {
                return null;
            }
        }
    }
}
