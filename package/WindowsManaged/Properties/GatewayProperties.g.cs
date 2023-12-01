
namespace DevolutionsGateway.Properties
{
    internal partial class GatewayProperties
    {
 
        internal static readonly WixProperty<string> _AccessUriHost = new()
        {
            Id = "P.ACCESSURIHOST",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string AccessUriHost
        {
            get
            {
                string stringValue = this.FnGetPropValue(_AccessUriHost.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_AccessUriHost, value); 
                }
            }
        }
 
        internal static readonly WixProperty<uint> _AccessUriPort = new()
        {
            Id = "P.ACCESSURIPORT",
            Default = 443,
            Secure = true,
            Hidden = false,
        };

        public uint AccessUriPort
        {
            get
            {
                string stringValue = this.FnGetPropValue(_AccessUriPort.Id);
                return WixProperties.GetPropertyValue<uint>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_AccessUriPort, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _AccessUriScheme = new()
        {
            Id = "P.ACCESSURISCHEME",
            Default = Constants.HttpsProtocol,
            Secure = true,
            Hidden = false,
        };

        public string AccessUriScheme
        {
            get
            {
                string stringValue = this.FnGetPropValue(_AccessUriScheme.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_AccessUriScheme, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _CertificateFile = new()
        {
            Id = "P.CERTIFICATEFILE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string CertificateFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificateFile.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificateFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _CertificatePassword = new()
        {
            Id = "P.CERTIFICATEPASSWORD",
            Default = string.Empty,
            Secure = true,
            Hidden = true,
        };

        public string CertificatePassword
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificatePassword.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificatePassword, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _CertificatePrivateKeyFile = new()
        {
            Id = "P.CERTIFICATEPRIVATEKEYFILE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string CertificatePrivateKeyFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificatePrivateKeyFile.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificatePrivateKeyFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<bool> _ConfigureGateway = new()
        {
            Id = "P.CONFIGUREGATEWAY",
            Default = false,
            Secure = false,
            Hidden = false,
        };

        /// `true` to configure the Gateway interactively
        public bool ConfigureGateway
        {
            get
            {
                string stringValue = this.FnGetPropValue(_ConfigureGateway.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_ConfigureGateway, value); 
                }
            }
        }
 
        internal static readonly WixProperty<bool> _HasPowerShell = new()
        {
            Id = "P.HASPOWERSHELL",
            Default = false,
            Secure = false,
            Hidden = false,
        };

        public bool HasPowerShell
        {
            get
            {
                string stringValue = this.FnGetPropValue(_HasPowerShell.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_HasPowerShell, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _HttpListenerHost = new()
        {
            Id = "P.HTTPLISTENERHOST",
            Default = "0.0.0.0",
            Secure = true,
            Hidden = false,
        };

        public string HttpListenerHost
        {
            get
            {
                string stringValue = this.FnGetPropValue(_HttpListenerHost.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_HttpListenerHost, value); 
                }
            }
        }
 
        internal static readonly WixProperty<uint> _HttpListenerPort = new()
        {
            Id = "P.HTTPLISTENERPORT",
            Default = 7171,
            Secure = true,
            Hidden = false,
        };

        public uint HttpListenerPort
        {
            get
            {
                string stringValue = this.FnGetPropValue(_HttpListenerPort.Id);
                return WixProperties.GetPropertyValue<uint>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_HttpListenerPort, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _HttpListenerScheme = new()
        {
            Id = "P.HTTPLISTENERSCHEME",
            Default = Constants.HttpsProtocol,
            Secure = true,
            Hidden = false,
        };

        public string HttpListenerScheme
        {
            get
            {
                string stringValue = this.FnGetPropValue(_HttpListenerScheme.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_HttpListenerScheme, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _NoStartService = new()
        {
            Id = "P.DGW.NO_START_SERVICE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string NoStartService
        {
            get
            {
                string stringValue = this.FnGetPropValue(_NoStartService.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_NoStartService, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _PowerShellPath = new()
        {
            Id = "P.POWERSHELLPATH",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string PowerShellPath
        {
            get
            {
                string stringValue = this.FnGetPropValue(_PowerShellPath.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_PowerShellPath, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _PublicKeyFile = new()
        {
            Id = "P.PUBLICKEYFILE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string PublicKeyFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(_PublicKeyFile.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_PublicKeyFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<int> _ServiceStart = new()
        {
            Id = "P.SERVICESTART",
            Default = 3,
            Secure = true,
            Hidden = false,
        };

        public int ServiceStart
        {
            get
            {
                string stringValue = this.FnGetPropValue(_ServiceStart.Id);
                return WixProperties.GetPropertyValue<int>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_ServiceStart, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _TcpListenerHost = new()
        {
            Id = "P.TCPLISTENERHOST",
            Default = "0.0.0.0",
            Secure = true,
            Hidden = false,
        };

        public string TcpListenerHost
        {
            get
            {
                string stringValue = this.FnGetPropValue(_TcpListenerHost.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_TcpListenerHost, value); 
                }
            }
        }
 
        internal static readonly WixProperty<uint> _TcpListenerPort = new()
        {
            Id = "P.TCPLISTENERPORT",
            Default = 8181,
            Secure = true,
            Hidden = false,
        };

        public uint TcpListenerPort
        {
            get
            {
                string stringValue = this.FnGetPropValue(_TcpListenerPort.Id);
                return WixProperties.GetPropertyValue<uint>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_TcpListenerPort, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _TcpListenerScheme = new()
        {
            Id = "P.TCPLISTENERSCHEME",
            Default = Constants.TcpProtocol,
            Secure = true,
            Hidden = false,
        };

        public string TcpListenerScheme
        {
            get
            {
                string stringValue = this.FnGetPropValue(_TcpListenerScheme.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_TcpListenerScheme, value); 
                }
            }
        }
 
        internal static readonly WixProperty<bool> _FirstInstall = new()
        {
            Id = "P.FIRSTINSTALL",
            Default = false,
            Secure = true,
            Hidden = false,
        };

        public bool FirstInstall
        {
            get
            {
                string stringValue = this.FnGetPropValue(_FirstInstall.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_FirstInstall, value); 
                }
            }
        }
 
        internal static readonly WixProperty<bool> _Upgrading = new()
        {
            Id = "P.UPGRADING",
            Default = false,
            Secure = true,
            Hidden = false,
        };

        public bool Upgrading
        {
            get
            {
                string stringValue = this.FnGetPropValue(_Upgrading.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_Upgrading, value); 
                }
            }
        }
 
        internal static readonly WixProperty<bool> _RemovingForUpgrade = new()
        {
            Id = "P.REMOVINGFORUPGRADE",
            Default = false,
            Secure = true,
            Hidden = false,
        };

        public bool RemovingForUpgrade
        {
            get
            {
                string stringValue = this.FnGetPropValue(_RemovingForUpgrade.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_RemovingForUpgrade, value); 
                }
            }
        }
 
        internal static readonly WixProperty<bool> _Uninstalling = new()
        {
            Id = "P.UNINSTALLING",
            Default = false,
            Secure = true,
            Hidden = false,
        };

        public bool Uninstalling
        {
            get
            {
                string stringValue = this.FnGetPropValue(_Uninstalling.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_Uninstalling, value); 
                }
            }
        }
 
        internal static readonly WixProperty<bool> _Maintenance = new()
        {
            Id = "P.MAINTENANCE",
            Default = false,
            Secure = true,
            Hidden = false,
        };

        public bool Maintenance
        {
            get
            {
                string stringValue = this.FnGetPropValue(_Maintenance.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_Maintenance, value); 
                }
            }
        }
 

        public static IWixProperty[] Properties =
        {
 
            _AccessUriHost,
 
            _AccessUriPort,
 
            _AccessUriScheme,
 
            _CertificateFile,
 
            _CertificatePassword,
 
            _CertificatePrivateKeyFile,
 
            _ConfigureGateway,
 
            _HasPowerShell,
 
            _HttpListenerHost,
 
            _HttpListenerPort,
 
            _HttpListenerScheme,
 
            _NoStartService,
 
            _PowerShellPath,
 
            _PublicKeyFile,
 
            _ServiceStart,
 
            _TcpListenerHost,
 
            _TcpListenerPort,
 
            _TcpListenerScheme,
 
            _FirstInstall,
 
            _Upgrading,
 
            _RemovingForUpgrade,
 
            _Uninstalling,
 
            _Maintenance,
 
        };
    }
}

