
using System;

namespace DevolutionsAgent.Properties
{
    /// <summary>
    /// do not modify the contents of this class with the code editor.
    /// </summary>
    internal partial class AgentProperties
    {
 
        internal static readonly WixProperty<Boolean> configureAgent = new()
        {
            Id = "P.CONFIGUREAGENT",
            Default = false,
            Name = "ConfigureAgent",
            Secure = false,
            Hidden = false,
            Encode = false,
            Public = true
        };

        /// <summary>`true` to configure the Agent interactively</summary>
        public Boolean ConfigureAgent
        {
            get
            {
                string stringValue = this.FnGetPropValue(configureAgent.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(configureAgent, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> debugPowerShell = new()
        {
            Id = "P.DEBUGPOWERSHELL",
            Default = false,
            Name = "DebugPowerShell",
            Secure = true,
            Hidden = false,
            Encode = false,
            Public = true
        };

        public Boolean DebugPowerShell
        {
            get
            {
                string stringValue = this.FnGetPropValue(debugPowerShell.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(debugPowerShell, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Guid> installId = new()
        {
            Id = "P.InstallId",
            Default = new Guid("00000000-0000-0000-0000-000000000000"),
            Name = "InstallId",
            Secure = false,
            Hidden = false,
            Encode = false,
            Public = false
        };

        public Guid InstallId
        {
            get
            {
                string stringValue = this.FnGetPropValue(installId.Id);
                return WixProperties.GetPropertyValue<Guid>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(installId, value); 
                }
            }
        }
 
        internal static readonly WixProperty<UInt32> netFx45Version = new()
        {
            Id = "P.NetFx45Version",
            Default = 0,
            Name = "NetFx45Version",
            Secure = false,
            Hidden = false,
            Encode = false,
            Public = false
        };

        public UInt32 NetFx45Version
        {
            get
            {
                string stringValue = this.FnGetPropValue(netFx45Version.Id);
                return WixProperties.GetPropertyValue<UInt32>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(netFx45Version, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> firstInstall = new()
        {
            Id = "P.FirstInstall",
            Default = false,
            Name = "FirstInstall",
            Secure = false,
            Hidden = false,
            Encode = false,
            Public = false
        };

        public Boolean FirstInstall
        {
            get
            {
                string stringValue = this.FnGetPropValue(firstInstall.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(firstInstall, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> upgrading = new()
        {
            Id = "P.Upgrading",
            Default = false,
            Name = "Upgrading",
            Secure = false,
            Hidden = false,
            Encode = false,
            Public = false
        };

        public Boolean Upgrading
        {
            get
            {
                string stringValue = this.FnGetPropValue(upgrading.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(upgrading, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> removingForUpgrade = new()
        {
            Id = "P.RemovingForUpgrade",
            Default = false,
            Name = "RemovingForUpgrade",
            Secure = false,
            Hidden = false,
            Encode = false,
            Public = false
        };

        public Boolean RemovingForUpgrade
        {
            get
            {
                string stringValue = this.FnGetPropValue(removingForUpgrade.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(removingForUpgrade, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> uninstalling = new()
        {
            Id = "P.Uninstalling",
            Default = false,
            Name = "Uninstalling",
            Secure = false,
            Hidden = false,
            Encode = false,
            Public = false
        };

        public Boolean Uninstalling
        {
            get
            {
                string stringValue = this.FnGetPropValue(uninstalling.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(uninstalling, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> maintenance = new()
        {
            Id = "P.Maintenance",
            Default = false,
            Name = "Maintenance",
            Secure = false,
            Hidden = false,
            Encode = false,
            Public = false
        };

        public Boolean Maintenance
        {
            get
            {
                string stringValue = this.FnGetPropValue(maintenance.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(maintenance, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> featuresToConfigure = new()
        {
            Id = "P.FeaturesToConfigure",
            Default = "",
            Name = "FeaturesToConfigure",
            Secure = false,
            Hidden = false,
            Encode = false,
            Public = false
        };

        public String FeaturesToConfigure
        {
            get
            {
                string stringValue = this.FnGetPropValue(featuresToConfigure.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(featuresToConfigure, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> psuServerUrl = new()
        {
            Id = "P.PSUSERVERURL",
            Default = "",
            Name = "PsuServerUrl",
            Secure = true,
            Hidden = false,
            Encode = true,
            Public = true
        };

        /// <summary>PSU endpoint URL (e.g. http://localhost:5000)</summary>
        public String PsuServerUrl
        {
            get
            {
                string stringValue = this.FnGetPropValue(psuServerUrl.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(psuServerUrl, value); 
                }
            }
        }

        internal static readonly WixProperty<String> psuServerUrlEncoded = new()
        {
            Id = "P.PSUSERVERURL_ENCODED",
            Default = string.Empty,
            Name = "PsuServerUrlEncoded",
            Secure = true,
            Hidden = true,
            Encode = false,
            Public = true /* Secure properties must be public */
        };

        public string PsuServerUrlEncoded
        {
            get
            {
                string stringValue = this.FnGetPropValue(psuServerUrlEncoded.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(psuServerUrlEncoded, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> psuAppToken = new()
        {
            Id = "P.PSUAPPTOKEN",
            Default = "",
            Name = "PsuAppToken",
            Secure = true,
            Hidden = true,
            Encode = true,
            Public = true
        };

        /// <summary>PSU application token, or a secret name when PsuAppTokenIsSecretReference is true</summary>
        public String PsuAppToken
        {
            get
            {
                string stringValue = this.FnGetPropValue(psuAppToken.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(psuAppToken, value); 
                }
            }
        }

        internal static readonly WixProperty<String> psuAppTokenEncoded = new()
        {
            Id = "P.PSUAPPTOKEN_ENCODED",
            Default = string.Empty,
            Name = "PsuAppTokenEncoded",
            Secure = true,
            Hidden = true,
            Encode = false,
            Public = true /* Secure properties must be public */
        };

        public string PsuAppTokenEncoded
        {
            get
            {
                string stringValue = this.FnGetPropValue(psuAppTokenEncoded.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(psuAppTokenEncoded, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> psuAppTokenIsSecretReference = new()
        {
            Id = "P.PSUAPPTOKENISSECRETREFERENCE",
            Default = false,
            Name = "PsuAppTokenIsSecretReference",
            Secure = true,
            Hidden = false,
            Encode = false,
            Public = true
        };

        /// <summary>`true` when PsuAppToken holds a SecretManagement secret name to inject as $secret:<name></summary>
        public Boolean PsuAppTokenIsSecretReference
        {
            get
            {
                string stringValue = this.FnGetPropValue(psuAppTokenIsSecretReference.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(psuAppTokenIsSecretReference, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> psuAgentId = new()
        {
            Id = "P.PSUAGENTID",
            Default = "",
            Name = "PsuAgentId",
            Secure = true,
            Hidden = false,
            Encode = true,
            Public = true
        };

        /// <summary>Optional stable agent identifier presented to PSU</summary>
        public String PsuAgentId
        {
            get
            {
                string stringValue = this.FnGetPropValue(psuAgentId.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(psuAgentId, value); 
                }
            }
        }

        internal static readonly WixProperty<String> psuAgentIdEncoded = new()
        {
            Id = "P.PSUAGENTID_ENCODED",
            Default = string.Empty,
            Name = "PsuAgentIdEncoded",
            Secure = true,
            Hidden = true,
            Encode = false,
            Public = true /* Secure properties must be public */
        };

        public string PsuAgentIdEncoded
        {
            get
            {
                string stringValue = this.FnGetPropValue(psuAgentIdEncoded.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(psuAgentIdEncoded, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> psuDisplayName = new()
        {
            Id = "P.PSUDISPLAYNAME",
            Default = "",
            Name = "PsuDisplayName",
            Secure = true,
            Hidden = false,
            Encode = true,
            Public = true
        };

        /// <summary>Optional friendly display name shown in PSU</summary>
        public String PsuDisplayName
        {
            get
            {
                string stringValue = this.FnGetPropValue(psuDisplayName.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(psuDisplayName, value); 
                }
            }
        }

        internal static readonly WixProperty<String> psuDisplayNameEncoded = new()
        {
            Id = "P.PSUDISPLAYNAME_ENCODED",
            Default = string.Empty,
            Name = "PsuDisplayNameEncoded",
            Secure = true,
            Hidden = true,
            Encode = false,
            Public = true /* Secure properties must be public */
        };

        public string PsuDisplayNameEncoded
        {
            get
            {
                string stringValue = this.FnGetPropValue(psuDisplayNameEncoded.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(psuDisplayNameEncoded, value); 
                }
            }
        }
 

        public static IWixProperty[] Properties =
        {
 
            configureAgent,
 
 
            debugPowerShell,
 
 
            installId,
 
 
            netFx45Version,
 
 
            firstInstall,
 
 
            upgrading,
 
 
            removingForUpgrade,
 
 
            uninstalling,
 
 
            maintenance,
 
 
            featuresToConfigure,
 
 
            psuServerUrl,
            psuServerUrlEncoded,
 
 
            psuAppToken,
            psuAppTokenEncoded,
 
 
            psuAppTokenIsSecretReference,
 
 
            psuAgentId,
            psuAgentIdEncoded,
 
 
            psuDisplayName,
            psuDisplayNameEncoded,
 
 
        };
    }
}

