
using StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation;
using StoreName = System.Security.Cryptography.X509Certificates.StoreName;

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
 
        internal static readonly WixProperty<Constants.CertificateMode> _CertificateMode = new()
        {
            Id = "P.CERTIFICATEMODE",
            Default = Constants.CertificateMode.External,
            Secure = true,
            Hidden = false,
        };

        public Constants.CertificateMode CertificateMode
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificateMode.Id);
                return WixProperties.GetPropertyValue<Constants.CertificateMode>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificateMode, value); 
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
 
        internal static readonly WixProperty<StoreLocation> _CertificateLocation = new()
        {
            Id = "P.CERTIFICATELOCATION",
            Default = StoreLocation.CurrentUser,
            Secure = true,
            Hidden = false,
        };

        public StoreLocation CertificateLocation
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificateLocation.Id);
                return WixProperties.GetPropertyValue<StoreLocation>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificateLocation, value); 
                }
            }
        }
 
        internal static readonly WixProperty<StoreName> _CertificateStore = new()
        {
            Id = "P.CERTIFICATESTORE",
            Default = StoreName.My,
            Secure = true,
            Hidden = true,
        };

        public StoreName CertificateStore
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificateStore.Id);
                return WixProperties.GetPropertyValue<StoreName>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificateStore, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _CertificateName = new()
        {
            Id = "P.CERTIFICATENAME",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string CertificateName
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificateName.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificateName, value); 
                }
            }
        }
 
        internal static readonly WixProperty<bool> _GenerateCertificate = new()
        {
            Id = "P.GENERATECERTIFICATE",
            Default = false,
            Secure = true,
            Hidden = false,
        };

        public bool GenerateCertificate
        {
            get
            {
                string stringValue = this.FnGetPropValue(_GenerateCertificate.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_GenerateCertificate, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Constants.CertificateFindType> _CertificateFindType = new()
        {
            Id = "P.CERTIFICATEFINDTYPE",
            Default = Constants.CertificateFindType.Thumbprint,
            Secure = false,
            Hidden = false,
        };

        public Constants.CertificateFindType CertificateFindType
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificateFindType.Id);
                return WixProperties.GetPropertyValue<Constants.CertificateFindType>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificateFindType, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _CertificateSearchText = new()
        {
            Id = "P.CERTIFICATESEARCHTEXT",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string CertificateSearchText
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificateSearchText.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificateSearchText, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _CertificateThumbprint = new()
        {
            Id = "P.CERTIFICATETHUMBPRINT",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string CertificateThumbprint
        {
            get
            {
                string stringValue = this.FnGetPropValue(_CertificateThumbprint.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_CertificateThumbprint, value); 
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

        /// <summary>`true` to configure the Gateway interactively</summary>
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
 
        internal static readonly WixProperty<string> _PrivateKeyFile = new()
        {
            Id = "P.PRIVATEKEYFILE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string PrivateKeyFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(_PrivateKeyFile.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_PrivateKeyFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<bool> _GenerateKeyPair = new()
        {
            Id = "P.GENERATEKEYPAIR",
            Default = false,
            Secure = true,
            Hidden = false,
        };

        public bool GenerateKeyPair
        {
            get
            {
                string stringValue = this.FnGetPropValue(_GenerateKeyPair.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_GenerateKeyPair, value); 
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
 
        internal static readonly WixProperty<bool> _ConfigureWebApp = new()
        {
            Id = "P.CONFIGUREWEBAPP",
            Default = false,
            Secure = true,
            Hidden = false,
        };

        /// <summary>`true` to configure the standalone web application interactively</summary>
        public bool ConfigureWebApp
        {
            get
            {
                string stringValue = this.FnGetPropValue(_ConfigureWebApp.Id);
                return WixProperties.GetPropertyValue<bool>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_ConfigureWebApp, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Constants.AuthenticationMode> _AuthenticationMode = new()
        {
            Id = "P.AUTHENTICATIONMODE",
            Default = Constants.AuthenticationMode.None,
            Secure = true,
            Hidden = true,
        };

        public Constants.AuthenticationMode AuthenticationMode
        {
            get
            {
                string stringValue = this.FnGetPropValue(_AuthenticationMode.Id);
                return WixProperties.GetPropertyValue<Constants.AuthenticationMode>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_AuthenticationMode, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _WebUsername = new()
        {
            Id = "P.WEBUSERNAME",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
        };

        public string WebUsername
        {
            get
            {
                string stringValue = this.FnGetPropValue(_WebUsername.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_WebUsername, value); 
                }
            }
        }
 
        internal static readonly WixProperty<string> _WebPassword = new()
        {
            Id = "P.WEBPASSWORD",
            Default = string.Empty,
            Secure = true,
            Hidden = true,
        };

        public string WebPassword
        {
            get
            {
                string stringValue = this.FnGetPropValue(_WebPassword.Id);
                return WixProperties.GetPropertyValue<string>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_WebPassword, value); 
                }
            }
        }
 
        internal static readonly WixProperty<uint> _NetFx45Version = new()
        {
            Id = "P.NETFX45VERSION",
            Default = 0,
            Secure = false,
            Hidden = false,
        };

        public uint NetFx45Version
        {
            get
            {
                string stringValue = this.FnGetPropValue(_NetFx45Version.Id);
                return WixProperties.GetPropertyValue<uint>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(_NetFx45Version, value); 
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
 
            _CertificateMode,
 
            _CertificateFile,
 
            _CertificatePassword,
 
            _CertificatePrivateKeyFile,
 
            _CertificateLocation,
 
            _CertificateStore,
 
            _CertificateName,
 
            _GenerateCertificate,
 
            _CertificateFindType,
 
            _CertificateSearchText,
 
            _CertificateThumbprint,
 
            _ConfigureGateway,
 
            _HasPowerShell,
 
            _HttpListenerHost,
 
            _HttpListenerPort,
 
            _HttpListenerScheme,
 
            _PublicKeyFile,
 
            _PrivateKeyFile,
 
            _GenerateKeyPair,
 
            _PowerShellPath,
 
            _NoStartService,
 
            _ServiceStart,
 
            _TcpListenerHost,
 
            _TcpListenerPort,
 
            _TcpListenerScheme,
 
            _ConfigureWebApp,
 
            _AuthenticationMode,
 
            _WebUsername,
 
            _WebPassword,
 
            _NetFx45Version,
 
            _FirstInstall,
 
            _Upgrading,
 
            _RemovingForUpgrade,
 
            _Uninstalling,
 
            _Maintenance,
 
        };
    }
}

