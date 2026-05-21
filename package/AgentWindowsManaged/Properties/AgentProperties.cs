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
        /// Optional gateway URL override. When set, the agent uses this URL instead of the JWT's
        /// jet_gw_url claim. Useful when the JWT was minted with a URL that isn't reachable from
        /// the agent's network (e.g. DVLS embedded "localhost" but the agent is remote).
        /// </summary>
        public static string AgentTunnelGatewayUrl = "AGENT_TUNNEL_GATEWAY_URL";

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
