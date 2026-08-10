using System;
using System.Linq;
using System.Net.NetworkInformation;

namespace DevolutionsAgent.Helpers;

internal static class DomainDetection
{
    public static string Detect()
    {
        string domain = IPGlobalProperties.GetIPGlobalProperties().DomainName?
            .Trim()
            .TrimEnd('.')
            .ToLowerInvariant();

        if (string.IsNullOrEmpty(domain))
        {
            return string.Empty;
        }

        string[] labels = domain.Split('.');
        return labels.Length >= 2 && labels.All(label => label.Length != 0)
            ? domain
            : string.Empty;
    }

    public static string ToWildcardRoute(string domain) =>
        string.IsNullOrEmpty(domain) || domain.StartsWith("*.", StringComparison.Ordinal)
            ? domain
            : $"*.{domain}";

    public static bool IsValidRoute(string route)
    {
        string name = route?.StartsWith("*.", StringComparison.Ordinal) == true
            ? route.Substring(2)
            : route;
        return !string.IsNullOrEmpty(name)
            && !name.Contains("*")
            && name.Split('.').All(label => label.Length != 0);
    }
}
