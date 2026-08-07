using System;
using WixSharp;

namespace DevolutionsAgent.Properties
{
    internal partial class AgentProperties
    {
        private readonly Microsoft.Deployment.WindowsInstaller.Session installerSession;

        private readonly ISession runtimeSession;

        private Func<string, string> FnGetPropValue { get; }

        /// <summary>
        /// The default WiX INSTALLDIR property name
        /// </summary>
        public static string InstallDir = "INSTALLDIR";

        /// <summary>
        /// Agent tunnel enrollment string (DVLS-signed JWT verbatim)
        /// </summary>
        public static string AgentTunnelEnrollmentString = "AGENT_TUNNEL_ENROLLMENT_STRING";

        /// <summary>
        /// Comma-separated subnets to advertise (e.g., "10.10.0.0/24, 192.168.1.0/24")
        /// </summary>
        public static string AgentTunnelAdvertiseSubnets = "AGENT_TUNNEL_ADVERTISE_SUBNETS";

        /// <summary>
        /// Comma-separated DNS domains to advertise (e.g., "corp.example.com, lab.example.com")
        /// </summary>
        public static string AgentTunnelAdvertiseDomains = "AGENT_TUNNEL_ADVERTISE_DOMAINS";

        /// <summary>
        /// Whether the machine's detected DNS domain should be explicitly advertised
        /// </summary>
        public static string AgentTunnelIncludeDetectedDomain = "AGENT_TUNNEL_INCLUDE_DETECTED_DOMAIN";

        /// <summary>
        /// DNS domain detected for the interactive installer suggestion
        /// </summary>
        public static string AgentTunnelDetectedDomain = "AGENT_TUNNEL_DETECTED_DOMAIN";
        public static string AgentTunnelDomainsUiState = "AGENT_TUNNEL_DOMAINS_UI_STATE";

        public static string AgentTunnelEnrollmentStringEncoded = "AGENT_TUNNEL_ENROLLMENT_STRING_ENCODED";
        public static string AgentTunnelAdvertiseSubnetsEncoded = "AGENT_TUNNEL_ADVERTISE_SUBNETS_ENCODED";
        public static string AgentTunnelAdvertiseDomainsEncoded = "AGENT_TUNNEL_ADVERTISE_DOMAINS_ENCODED";
        public static string AgentTunnelIncludeDetectedDomainEncoded = "AGENT_TUNNEL_INCLUDE_DETECTED_DOMAIN_ENCODED";
        public static string AgentTunnelDetectedDomainEncoded = "AGENT_TUNNEL_DETECTED_DOMAIN_ENCODED";
        public static string AgentTunnelDomainsUiStateEncoded = "AGENT_TUNNEL_DOMAINS_UI_STATE_ENCODED";

        public const string DomainsUiNotShown = "not-shown";
        public const string DomainsUiUnchanged = "unchanged";
        public const string DomainsUiEdited = "edited";

        public AgentProperties(ISession runtimeSession)
        {
            this.runtimeSession = runtimeSession;
            this.FnGetPropValue = GetPropertyValueRuntimeSession;
        }

        public AgentProperties(Microsoft.Deployment.WindowsInstaller.Session installerSession)
        {
            this.installerSession = installerSession;
            this.FnGetPropValue = GetPropertyValueInstallerSession;
        }

        private string GetPropertyValueRuntimeSession(string name)
        {
            return this.runtimeSession.Property(name);
        }

        private string GetPropertyValueInstallerSession(string name)
        {
            return this.installerSession.Property(name);
        }
    }
}
