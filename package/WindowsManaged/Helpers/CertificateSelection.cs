using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace DevolutionsGateway.Helpers
{
    /// <summary>
    /// Replicates the Devolutions Gateway TLS certificate selection algorithm
    /// (<c>devolutions-gateway/src/tls.rs</c>). Used so installer-side cert selection — both in
    /// the UI and in deferred custom actions — picks the same certificate the Gateway service
    /// will pick at startup.
    /// </summary>
    internal static class CertificateSelection
    {
        /// <summary>
        /// Outcome of a <see cref="Select"/> call.
        /// </summary>
        internal sealed class Result
        {
            /// <summary>
            /// The certificate the Gateway would select, or <c>null</c> when no certificate
            /// qualified (either nothing matched the subject substring, or every match was
            /// filtered out by the prerequisites).
            /// </summary>
            internal X509Certificate2 Selected { get; set; }

            /// <summary>
            /// Total number of certificates whose subject simple-name matched the search
            /// string before any filtering. Zero when nothing matched at all.
            /// </summary>
            internal int MatchCount { get; set; }

            /// <summary>
            /// Number of matched certificates that were filtered out by the prerequisites.
            /// </summary>
            internal int FilteredCount { get; set; }

            /// <summary>
            /// Bitwise union of the issues that caused certificates to be filtered out.
            /// Together with <see cref="AllFiltered"/>, this explains why a search returned
            /// candidates but no usable certificate.
            /// </summary>
            internal CertificateIssues FilteredReasons { get; set; }

            /// <summary>
            /// Whether strict-mode filtering (requires <c>serverAuth</c> EKU and a SAN) was applied.
            /// </summary>
            internal bool StrictMode { get; set; }

            /// <summary>
            /// True when matches existed but every match was filtered out. Lets the caller
            /// distinguish "no matches" (cert just isn't there) from "matches but unusable"
            /// (cert exists but doesn't meet prerequisites — the user-facing warning case).
            /// </summary>
            internal bool AllFiltered => this.Selected == null && this.MatchCount > 0;
        }

        /// <summary>
        /// Performs the same selection the Gateway performs at startup:
        /// <list type="number">
        ///   <item>Open the requested store.</item>
        ///   <item>Find all certificates whose subject simple-name contains <paramref name="subjectName"/>
        ///         (case-insensitive substring, matching Windows <c>CERT_FIND_SUBJECT_STR</c>).</item>
        ///   <item>Reject not-yet-valid certificates. In strict mode, also reject certificates
        ///         missing the <c>serverAuth</c> EKU or a Subject Alternative Name extension.</item>
        ///   <item>Sort the remainder by <c>NotAfter</c> descending and take the first.</item>
        /// </list>
        /// The Gateway's private-key-accessibility filter (skip a cert whose key the service
        /// cannot acquire) is intentionally NOT replicated. The installer runs elevated and may
        /// need to operate on a cert even when NETWORK SERVICE cannot read its key today —
        /// which is exactly the case we're often here to fix.
        ///
        /// Ownership: the caller owns <see cref="Result.Selected"/> and must dispose it. All
        /// filtered and unselected candidates are disposed internally.
        /// </summary>
        internal static Result Select(
            StoreLocation location,
            StoreName storeName,
            string subjectName,
            bool strictMode)
        {
            Result result = new Result { StrictMode = strictMode };

            if (string.IsNullOrWhiteSpace(subjectName))
            {
                return result;
            }

            X509Certificate2Collection matches;

            try
            {
                using X509Store store = new X509Store(storeName, location);
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
                matches = store.Certificates.Find(X509FindType.FindBySubjectName, subjectName, validOnly: false);
            }
            catch
            {
                return result;
            }

            CertificateIssues disqualifiers = strictMode
                ? CertificateIssues.NotYetValid
                  | CertificateIssues.MissingServerAuthEku
                  | CertificateIssues.MissingSubjectAlternativeName
                : CertificateIssues.NotYetValid;

            List<X509Certificate2> kept = new List<X509Certificate2>();

            foreach (X509Certificate2 candidate in matches)
            {
                CertificateIssues disqualifying = CertificateChain.CheckCertificate(candidate) & disqualifiers;

                if (disqualifying != CertificateIssues.None)
                {
                    result.FilteredReasons |= disqualifying;
                    candidate.Dispose();
                    continue;
                }

                kept.Add(candidate);
            }

            result.MatchCount = matches.Count;
            result.FilteredCount = matches.Count - kept.Count;
            result.Selected = kept.OrderByDescending(c => c.NotAfter).FirstOrDefault();

            foreach (X509Certificate2 candidate in kept)
            {
                if (!ReferenceEquals(candidate, result.Selected))
                {
                    candidate.Dispose();
                }
            }

            return result;
        }
    }
}
