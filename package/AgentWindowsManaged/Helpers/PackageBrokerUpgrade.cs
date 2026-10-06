using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using DevolutionsAgent.Resources;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace DevolutionsAgent.Helpers
{
    /// <summary>
    /// Carries a hand-configured Package Broker over to the <c>F.PackageBroker</c> feature on upgrade.
    /// </summary>
    /// <remarks>
    /// Releases before the Package Broker setup option could only enable the broker by editing agent.json.
    /// Without this, upgrading from them would leave the new feature unselected, and the generic
    /// <c>ConfigureFeatures</c> action would then write <c>PackageBroker.Enabled = false</c>.
    /// Once the previous product defines the feature, its recorded state wins, so a deselection sticks.
    /// </remarks>
    internal static class PackageBrokerUpgrade
    {
        internal static string ConfigSection => Features.PACKAGE_BROKER_FEATURE.Id.Substring(Features.FEATURE_ID_PREFIX.Length);

        internal static string AgentConfigPath => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Devolutions", "Agent", "agent.json");

        /// <summary>
        /// Whether the upgrade should select <c>F.PackageBroker</c>.
        /// </summary>
        /// <param name="previousProductFeatures">Every feature defined by each installed product being upgraded, whatever its state.</param>
        /// <param name="agentConfig">The current agent.json content, or <c>null</c> when it can't be read.</param>
        internal static bool ShouldSelect(IEnumerable<IEnumerable<string>> previousProductFeatures, string agentConfig)
        {
            List<IEnumerable<string>> products = previousProductFeatures.ToList();

            if (products.Count == 0)
            {
                return false;
            }

            if (products.Any(features => features.Contains(Features.PACKAGE_BROKER_FEATURE.Id)))
            {
                return false;
            }

            return IsEnabledInConfig(agentConfig);
        }

        /// <summary>
        /// Whether agent.json content sets <c>PackageBroker.Enabled</c> to <c>true</c>. Never throws.
        /// </summary>
        internal static bool IsEnabledInConfig(string agentConfig)
        {
            if (string.IsNullOrWhiteSpace(agentConfig))
            {
                return false;
            }

            try
            {
                return JObject.Parse(agentConfig)[ConfigSection] is JObject section
                    && section["Enabled"] is JValue { Type: JTokenType.Boolean } enabled
                    && (bool)enabled;
            }
            catch (JsonException)
            {
                return false;
            }
        }

        /// <summary>
        /// Best-effort read of agent.json. Returns <c>null</c> when it is missing or unreadable.
        /// </summary>
        internal static string TryReadAgentConfig()
        {
            try
            {
                return File.Exists(AgentConfigPath) ? File.ReadAllText(AgentConfigPath) : null;
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
