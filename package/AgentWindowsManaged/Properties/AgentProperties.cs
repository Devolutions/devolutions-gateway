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
