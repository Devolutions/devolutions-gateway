using DevolutionsAgent.Resources;

using Newtonsoft.Json.Linq;

using System;
using System.IO;
using System.Linq;

namespace DevolutionsAgent.Helpers;

internal static class AgentTunnelConfiguration
{
    public static string LoadAdvertiseDomains()
    {
        string path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            Includes.VENDOR_NAME,
            Includes.SHORT_NAME,
            "agent.json");

        if (!File.Exists(path))
        {
            return string.Empty;
        }

        JObject root = JObject.Parse(File.ReadAllText(path));
        if (root["Tunnel"]?["AdvertiseDomains"] is not JArray domains)
        {
            return string.Empty;
        }

        return string.Join(
            ", ",
            domains
                .Values<string>()
                .Where(domain => !string.IsNullOrWhiteSpace(domain)));
    }
}
