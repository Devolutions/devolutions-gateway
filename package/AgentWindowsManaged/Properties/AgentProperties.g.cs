
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
 
        };
    }
}

