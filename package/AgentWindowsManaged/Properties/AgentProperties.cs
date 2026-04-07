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
        /// Agent tunnel enrollment string (dgw-enroll:v1:...)
        /// </summary>
        public static string AgentTunnelEnrollmentString = "AGENT_TUNNEL_ENROLLMENT_STRING";

        /// <summary>
        /// Comma-separated subnets to advertise (e.g., "10.10.0.0/24, 192.168.1.0/24")
        /// </summary>
        public static string AgentTunnelAdvertiseSubnets = "AGENT_TUNNEL_ADVERTISE_SUBNETS";

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
