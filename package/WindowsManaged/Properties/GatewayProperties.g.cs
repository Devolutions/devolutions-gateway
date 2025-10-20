
using StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation;
using StoreName = System.Security.Cryptography.X509Certificates.StoreName;
using ServiceStartMode = System.ServiceProcess.ServiceStartMode;
using System;
using static DevolutionsGateway.Properties.Constants;

namespace DevolutionsGateway.Properties
{
    /// <summary>
    /// do not modify the contents of this class with the code editor.
    /// </summary>
    public partial class Constants
    {
 
        public const string HttpProtocol = "http";
 
        public const string HttpsProtocol = "https";
 
        public const string TcpProtocol = "tcp";

 
        public enum AuthenticationMode 
        {
            None,
            Custom,
        }
 
        public enum CertificateMode 
        {
            External,
            System,
        }
 
        public enum CertificateFindType 
        {
            Thumbprint,
            SubjectName,
        }
 
        public enum CustomizeMode 
        {
            Now,
            Later,
        }
    }

    /// <summary>
    /// do not modify the contents of this class with the code editor.
    /// </summary>
    internal partial class GatewayProperties
    {
 
        internal static readonly WixProperty<String> accessUriHost = new()
        {
            Id = "P.ACCESSURIHOST",
            Default = "",
            Name = "AccessUriHost",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String AccessUriHost
        {
            get
            {
                string stringValue = this.FnGetPropValue(accessUriHost.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(accessUriHost, value); 
                }
            }
        }
 
        internal static readonly WixProperty<UInt32> accessUriPort = new()
        {
            Id = "P.ACCESSURIPORT",
            Default = 7171,
            Name = "AccessUriPort",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public UInt32 AccessUriPort
        {
            get
            {
                string stringValue = this.FnGetPropValue(accessUriPort.Id);
                return WixProperties.GetPropertyValue<UInt32>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(accessUriPort, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> accessUriScheme = new()
        {
            Id = "P.ACCESSURISCHEME",
            Default = "https",
            Name = "AccessUriScheme",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String AccessUriScheme
        {
            get
            {
                string stringValue = this.FnGetPropValue(accessUriScheme.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(accessUriScheme, value); 
                }
            }
        }
 
        internal static readonly WixProperty<CertificateMode> certificateMode = new()
        {
            Id = "P.CERTIFICATEMODE",
            Default = CertificateMode.External,
            Name = "CertificateMode",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public CertificateMode CertificateMode
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateMode.Id);
                return WixProperties.GetPropertyValue<CertificateMode>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateMode, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> certificateFile = new()
        {
            Id = "P.CERTIFICATEFILE",
            Default = "",
            Name = "CertificateFile",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String CertificateFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateFile.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> certificatePassword = new()
        {
            Id = "P.CERTIFICATEPASSWORD",
            Default = "",
            Name = "CertificatePassword",
            Secure = true,
            Hidden = true,
            Public = true
        };

        public String CertificatePassword
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificatePassword.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificatePassword, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> certificatePrivateKeyFile = new()
        {
            Id = "P.CERTIFICATEPRIVATEKEYFILE",
            Default = "",
            Name = "CertificatePrivateKeyFile",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String CertificatePrivateKeyFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificatePrivateKeyFile.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificatePrivateKeyFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<StoreLocation> certificateLocation = new()
        {
            Id = "P.CERTIFICATELOCATION",
            Default = StoreLocation.CurrentUser,
            Name = "CertificateLocation",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public StoreLocation CertificateLocation
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateLocation.Id);
                return WixProperties.GetPropertyValue<StoreLocation>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateLocation, value); 
                }
            }
        }
 
        internal static readonly WixProperty<StoreName> certificateStore = new()
        {
            Id = "P.CERTIFICATESTORE",
            Default = StoreName.My,
            Name = "CertificateStore",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public StoreName CertificateStore
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateStore.Id);
                return WixProperties.GetPropertyValue<StoreName>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateStore, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> certificateName = new()
        {
            Id = "P.CERTIFICATENAME",
            Default = "",
            Name = "CertificateName",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String CertificateName
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateName.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateName, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> generateCertificate = new()
        {
            Id = "P.GENERATECERTIFICATE",
            Default = false,
            Name = "GenerateCertificate",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public Boolean GenerateCertificate
        {
            get
            {
                string stringValue = this.FnGetPropValue(generateCertificate.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(generateCertificate, value); 
                }
            }
        }
 
        internal static readonly WixProperty<CertificateFindType> certificateFindType = new()
        {
            Id = "P.CertificateFindType",
            Default = CertificateFindType.Thumbprint,
            Name = "CertificateFindType",
            Secure = false,
            Hidden = false,
            Public = false
        };

        public CertificateFindType CertificateFindType
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateFindType.Id);
                return WixProperties.GetPropertyValue<CertificateFindType>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateFindType, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> certificateSearchText = new()
        {
            Id = "P.CertificateSearchText",
            Default = "",
            Name = "CertificateSearchText",
            Secure = false,
            Hidden = true,
            Public = false
        };

        public String CertificateSearchText
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateSearchText.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateSearchText, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> certificateThumbprint = new()
        {
            Id = "P.CertificateThumbprint",
            Default = "",
            Name = "CertificateThumbprint",
            Secure = false,
            Hidden = true,
            Public = false
        };

        public String CertificateThumbprint
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateThumbprint.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateThumbprint, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> devolutionsServerUrl = new()
        {
            Id = "P.DEVOLUTIONSSERVERURL",
            Default = "",
            Name = "DevolutionsServerUrl",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String DevolutionsServerUrl
        {
            get
            {
                string stringValue = this.FnGetPropValue(devolutionsServerUrl.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(devolutionsServerUrl, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> configureGateway = new()
        {
            Id = "P.CONFIGUREGATEWAY",
            Default = false,
            Name = "ConfigureGateway",
            Secure = false,
            Hidden = false,
            Public = true
        };

        /// <summary>`true` to configure the Gateway interactively</summary>
        public Boolean ConfigureGateway
        {
            get
            {
                string stringValue = this.FnGetPropValue(configureGateway.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(configureGateway, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> hasPowerShell = new()
        {
            Id = "P.HasPowerShell",
            Default = false,
            Name = "HasPowerShell",
            Secure = false,
            Hidden = false,
            Public = false
        };

        public Boolean HasPowerShell
        {
            get
            {
                string stringValue = this.FnGetPropValue(hasPowerShell.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(hasPowerShell, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> httpListenerHost = new()
        {
            Id = "P.HTTPLISTENERHOST",
            Default = "0.0.0.0",
            Name = "HttpListenerHost",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String HttpListenerHost
        {
            get
            {
                string stringValue = this.FnGetPropValue(httpListenerHost.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(httpListenerHost, value); 
                }
            }
        }
 
        internal static readonly WixProperty<UInt32> httpListenerPort = new()
        {
            Id = "P.HTTPLISTENERPORT",
            Default = 7171,
            Name = "HttpListenerPort",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public UInt32 HttpListenerPort
        {
            get
            {
                string stringValue = this.FnGetPropValue(httpListenerPort.Id);
                return WixProperties.GetPropertyValue<UInt32>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(httpListenerPort, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> httpListenerScheme = new()
        {
            Id = "P.HTTPLISTENERSCHEME",
            Default = "https",
            Name = "HttpListenerScheme",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String HttpListenerScheme
        {
            get
            {
                string stringValue = this.FnGetPropValue(httpListenerScheme.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(httpListenerScheme, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> didChooseServerConfig = new()
        {
            Id = "P.DidChooseServerConfig",
            Default = false,
            Name = "DidChooseServerConfig",
            Secure = false,
            Hidden = false,
            Public = false
        };

        /// <summary>A helper to manage UI state</summary>
        public Boolean DidChooseServerConfig
        {
            get
            {
                string stringValue = this.FnGetPropValue(didChooseServerConfig.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(didChooseServerConfig, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> publicKeyFile = new()
        {
            Id = "P.PUBLICKEYFILE",
            Default = "",
            Name = "PublicKeyFile",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String PublicKeyFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(publicKeyFile.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(publicKeyFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> privateKeyFile = new()
        {
            Id = "P.PRIVATEKEYFILE",
            Default = "",
            Name = "PrivateKeyFile",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String PrivateKeyFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(privateKeyFile.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(privateKeyFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> generateKeyPair = new()
        {
            Id = "P.GENERATEKEYPAIR",
            Default = false,
            Name = "GenerateKeyPair",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public Boolean GenerateKeyPair
        {
            get
            {
                string stringValue = this.FnGetPropValue(generateKeyPair.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(generateKeyPair, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> powerShellPath = new()
        {
            Id = "P.PowerShellPath",
            Default = "",
            Name = "PowerShellPath",
            Secure = false,
            Hidden = true,
            Public = false
        };

        public String PowerShellPath
        {
            get
            {
                string stringValue = this.FnGetPropValue(powerShellPath.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(powerShellPath, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> noStartService = new()
        {
            Id = "P.DGW.NO_START_SERVICE",
            Default = "",
            Name = "NoStartService",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String NoStartService
        {
            get
            {
                string stringValue = this.FnGetPropValue(noStartService.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(noStartService, value); 
                }
            }
        }
 
        internal static readonly WixProperty<ServiceStartMode> serviceStart = new()
        {
            Id = "P.SERVICESTART",
            Default = ServiceStartMode.Manual,
            Name = "ServiceStart",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public ServiceStartMode ServiceStart
        {
            get
            {
                string stringValue = this.FnGetPropValue(serviceStart.Id);
                return WixProperties.GetPropertyValue<ServiceStartMode>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(serviceStart, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> tcpListenerHost = new()
        {
            Id = "P.TCPLISTENERHOST",
            Default = "0.0.0.0",
            Name = "TcpListenerHost",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String TcpListenerHost
        {
            get
            {
                string stringValue = this.FnGetPropValue(tcpListenerHost.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(tcpListenerHost, value); 
                }
            }
        }
 
        internal static readonly WixProperty<UInt32> tcpListenerPort = new()
        {
            Id = "P.TCPLISTENERPORT",
            Default = 8181,
            Name = "TcpListenerPort",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public UInt32 TcpListenerPort
        {
            get
            {
                string stringValue = this.FnGetPropValue(tcpListenerPort.Id);
                return WixProperties.GetPropertyValue<UInt32>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(tcpListenerPort, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> tcpListenerScheme = new()
        {
            Id = "P.TCPLISTENERSCHEME",
            Default = "tcp",
            Name = "TcpListenerScheme",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String TcpListenerScheme
        {
            get
            {
                string stringValue = this.FnGetPropValue(tcpListenerScheme.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(tcpListenerScheme, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> configureWebApp = new()
        {
            Id = "P.CONFIGUREWEBAPP",
            Default = false,
            Name = "ConfigureWebApp",
            Secure = true,
            Hidden = false,
            Public = true
        };

        /// <summary>`true` to configure the standalone web application interactively</summary>
        public Boolean ConfigureWebApp
        {
            get
            {
                string stringValue = this.FnGetPropValue(configureWebApp.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(configureWebApp, value); 
                }
            }
        }
 
        internal static readonly WixProperty<AuthenticationMode> authenticationMode = new()
        {
            Id = "P.AUTHENTICATIONMODE",
            Default = AuthenticationMode.Custom,
            Name = "AuthenticationMode",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public AuthenticationMode AuthenticationMode
        {
            get
            {
                string stringValue = this.FnGetPropValue(authenticationMode.Id);
                return WixProperties.GetPropertyValue<AuthenticationMode>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(authenticationMode, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> webUsername = new()
        {
            Id = "P.WEBUSERNAME",
            Default = "",
            Name = "WebUsername",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String WebUsername
        {
            get
            {
                string stringValue = this.FnGetPropValue(webUsername.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(webUsername, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> webPassword = new()
        {
            Id = "P.WEBPASSWORD",
            Default = "",
            Name = "WebPassword",
            Secure = true,
            Hidden = true,
            Public = true
        };

        public String WebPassword
        {
            get
            {
                string stringValue = this.FnGetPropValue(webPassword.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(webPassword, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> configureNgrok = new()
        {
            Id = "P.CONFIGURENGROK",
            Default = false,
            Name = "ConfigureNgrok",
            Secure = true,
            Hidden = false,
            Public = true
        };

        /// <summary>`true` to use ngrok for ingress listeners</summary>
        public Boolean ConfigureNgrok
        {
            get
            {
                string stringValue = this.FnGetPropValue(configureNgrok.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(configureNgrok, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> ngrokAuthToken = new()
        {
            Id = "P.NGROKAUTHTOKEN",
            Default = "",
            Name = "NgrokAuthToken",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String NgrokAuthToken
        {
            get
            {
                string stringValue = this.FnGetPropValue(ngrokAuthToken.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(ngrokAuthToken, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> ngrokHttpDomain = new()
        {
            Id = "P.NGROKHTTPDOMAIN",
            Default = "",
            Name = "NgrokHttpDomain",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String NgrokHttpDomain
        {
            get
            {
                string stringValue = this.FnGetPropValue(ngrokHttpDomain.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(ngrokHttpDomain, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> ngrokEnableTcp = new()
        {
            Id = "P.NGROKENABLETCP",
            Default = false,
            Name = "NgrokEnableTcp",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public Boolean NgrokEnableTcp
        {
            get
            {
                string stringValue = this.FnGetPropValue(ngrokEnableTcp.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(ngrokEnableTcp, value); 
                }
            }
        }
 
        internal static readonly WixProperty<String> ngrokRemoteAddress = new()
        {
            Id = "P.NGROKREMOTEADDRESS",
            Default = "",
            Name = "NgrokRemoteAddress",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String NgrokRemoteAddress
        {
            get
            {
                string stringValue = this.FnGetPropValue(ngrokRemoteAddress.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(ngrokRemoteAddress, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Boolean> enableCliGeneration = new()
        {
            Id = "P.ENABLECLIGENERATION",
            Default = false,
            Name = "EnableCliGeneration",
            Secure = false,
            Hidden = false,
            Public = true
        };

        public Boolean EnableCliGeneration
        {
            get
            {
                string stringValue = this.FnGetPropValue(enableCliGeneration.Id);
                return WixProperties.GetPropertyValue<Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(enableCliGeneration, value); 
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
            Id = "P.INSTALLID",
            Default = new Guid("00000000-0000-0000-0000-000000000000"),
            Name = "InstallId",
            Secure = true,
            Hidden = false,
            Public = true
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
 
        internal static readonly WixProperty<String> userTempPath = new()
        {
            Id = "P.USERTEMPPATH",
            Default = "",
            Name = "UserTempPath",
            Secure = true,
            Hidden = false,
            Public = true
        };

        public String UserTempPath
        {
            get
            {
                string stringValue = this.FnGetPropValue(userTempPath.Id);
                return WixProperties.GetPropertyValue<String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(userTempPath, value); 
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
 
            accessUriHost,
 
            accessUriPort,
 
            accessUriScheme,
 
            certificateMode,
 
            certificateFile,
 
            certificatePassword,
 
            certificatePrivateKeyFile,
 
            certificateLocation,
 
            certificateStore,
 
            certificateName,
 
            generateCertificate,
 
            certificateFindType,
 
            certificateSearchText,
 
            certificateThumbprint,
 
            devolutionsServerUrl,
 
            configureGateway,
 
            hasPowerShell,
 
            httpListenerHost,
 
            httpListenerPort,
 
            httpListenerScheme,
 
            didChooseServerConfig,
 
            publicKeyFile,
 
            privateKeyFile,
 
            generateKeyPair,
 
            powerShellPath,
 
            noStartService,
 
            serviceStart,
 
            tcpListenerHost,
 
            tcpListenerPort,
 
            tcpListenerScheme,
 
            configureWebApp,
 
            authenticationMode,
 
            webUsername,
 
            webPassword,
 
            configureNgrok,
 
            ngrokAuthToken,
 
            ngrokHttpDomain,
 
            ngrokEnableTcp,
 
            ngrokRemoteAddress,
 
            enableCliGeneration,
 
            debugPowerShell,
 
            installId,
 
            userTempPath,
 
            netFx45Version,
 
            firstInstall,
 
            upgrading,
 
            removingForUpgrade,
 
            uninstalling,
 
            maintenance,
 
        };
    }
}

