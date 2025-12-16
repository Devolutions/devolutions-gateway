using System;
using System.Collections.Generic;
using System.Linq;

namespace DevolutionsGateway.Helpers
{
    internal class CertificateExceptionStore
    {
        private readonly Dictionary<string, string> map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        private static string Key(string host, int port) => $"{host}:{port}";

        public bool TryAdd(string host, int port, string thumbprint)
        {
            if (string.IsNullOrWhiteSpace(host))
            {
                return false;
            }

            if (port <= 0)
            {
                return false;
            }

            if (string.IsNullOrWhiteSpace(thumbprint))
            {
                return false;
            }

            this.map[Key(host, port)] = thumbprint;

            return true;
        }

        public bool IsTrusted(string host, int port, string thumbprint)
        {
            if (!this.map.TryGetValue(Key(host, port), out string stored))
            {
                return false;
            }

            return string.Equals(stored, thumbprint, StringComparison.OrdinalIgnoreCase);
        }

        public string Serialize()
        {
            // single line: "host:port#thumb;host:port#thumb"
            return string.Join(";", this.map.Select(kvp => $"{kvp.Key}#{kvp.Value}"));
        }

        public static CertificateExceptionStore Deserialize(string input)
        {
            var store = new CertificateExceptionStore();

            if (string.IsNullOrWhiteSpace(input))
            {
                return store;
            }

            foreach (string entry in input.Split([';'], StringSplitOptions.RemoveEmptyEntries))
            {
                string trimmed = entry.Trim();

                int hash = trimmed.IndexOf('#');

                if (hash <= 0 || hash == trimmed.Length - 1)
                {
                    continue;
                }

                string hostPort = trimmed.Substring(0, hash).Trim();
                string thumb = trimmed.Substring(hash + 1).Trim();

                if (thumb.Length == 0)
                {
                    continue;
                }

                int colon = hostPort.LastIndexOf(':');

                if (colon <= 0 || colon == hostPort.Length - 1)
                {
                    continue;
                }

                string host = hostPort.Substring(0, colon).Trim();
                string portStr = hostPort.Substring(colon + 1).Trim();

                if (!int.TryParse(portStr, out int port) || port <= 0)
                {
                    continue;
                }

                store.TryAdd(host, port, thumb);
            }

            return store;
        }
    }
}
