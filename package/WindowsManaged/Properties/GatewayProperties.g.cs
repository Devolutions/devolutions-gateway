
using StoreLocation = System.Security.Cryptography.X509Certificates.StoreLocation;
using StoreName = System.Security.Cryptography.X509Certificates.StoreName;
using ServiceStartMode = System.ServiceProcess.ServiceStartMode;
using System;

namespace DevolutionsGateway.Properties
{
    /// <summary>
    /// do not modify the contents of this class with the code editor.
    /// </summary>
    internal partial class GatewayProperties
    {
 
        internal static readonly WixProperty<System.String> accessUriHost = new()
        {
            Id = "P.ACCESSURIHOST",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "AccessUriHost",
        };

        public System.String AccessUriHost
        {
            get
            {
                string stringValue = this.FnGetPropValue(accessUriHost.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(accessUriHost, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.UInt32> accessUriPort = new()
        {
            Id = "P.ACCESSURIPORT",
            Default = 443,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "AccessUriPort",
        };

        public System.UInt32 AccessUriPort
        {
            get
            {
                string stringValue = this.FnGetPropValue(accessUriPort.Id);
                return WixProperties.GetPropertyValue<System.UInt32>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(accessUriPort, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> accessUriScheme = new()
        {
            Id = "P.ACCESSURISCHEME",
            Default = Constants.HttpsProtocol,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "AccessUriScheme",
        };

        public System.String AccessUriScheme
        {
            get
            {
                string stringValue = this.FnGetPropValue(accessUriScheme.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(accessUriScheme, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Constants.CertificateMode> certificateMode = new()
        {
            Id = "P.CERTIFICATEMODE",
            Default = Constants.CertificateMode.External,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Certificate Origin",
        };

        public Constants.CertificateMode CertificateMode
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateMode.Id);
                return WixProperties.GetPropertyValue<Constants.CertificateMode>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateMode, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> certificateFile = new()
        {
            Id = "P.CERTIFICATEFILE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Certificate File",
        };

        public System.String CertificateFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateFile.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> certificatePassword = new()
        {
            Id = "P.CERTIFICATEPASSWORD",
            Default = string.Empty,
            Secure = true,
            Hidden = true,
            Public = true,
            Summary = "Certificate Password",
        };

        public System.String CertificatePassword
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificatePassword.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificatePassword, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> certificatePrivateKeyFile = new()
        {
            Id = "P.CERTIFICATEPRIVATEKEYFILE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Certificate Private Key File",
        };

        public System.String CertificatePrivateKeyFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificatePrivateKeyFile.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificatePrivateKeyFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Security.Cryptography.X509Certificates.StoreLocation> certificateLocation = new()
        {
            Id = "P.CERTIFICATELOCATION",
            Default = StoreLocation.CurrentUser,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Certificate Location",
        };

        public System.Security.Cryptography.X509Certificates.StoreLocation CertificateLocation
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateLocation.Id);
                return WixProperties.GetPropertyValue<System.Security.Cryptography.X509Certificates.StoreLocation>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateLocation, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Security.Cryptography.X509Certificates.StoreName> certificateStore = new()
        {
            Id = "P.CERTIFICATESTORE",
            Default = StoreName.My,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Certificate Store",
        };

        public System.Security.Cryptography.X509Certificates.StoreName CertificateStore
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateStore.Id);
                return WixProperties.GetPropertyValue<System.Security.Cryptography.X509Certificates.StoreName>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateStore, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> certificateName = new()
        {
            Id = "P.CERTIFICATENAME",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Certificate Name",
        };

        public System.String CertificateName
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateName.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateName, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> generateCertificate = new()
        {
            Id = "P.GENERATECERTIFICATE",
            Default = false,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "GenerateCertificate",
        };

        public System.Boolean GenerateCertificate
        {
            get
            {
                string stringValue = this.FnGetPropValue(generateCertificate.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(generateCertificate, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Constants.CertificateFindType> certificateFindType = new()
        {
            Id = "P.CertificateFindType",
            Default = Constants.CertificateFindType.Thumbprint,
            Secure = false,
            Hidden = false,
            Public = false,
            Summary = "CertificateFindType",
        };

        public Constants.CertificateFindType CertificateFindType
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateFindType.Id);
                return WixProperties.GetPropertyValue<Constants.CertificateFindType>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateFindType, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> certificateSearchText = new()
        {
            Id = "P.CertificateSearchText",
            Default = string.Empty,
            Secure = false,
            Hidden = true,
            Public = false,
            Summary = "CertificateSearchText",
        };

        public System.String CertificateSearchText
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateSearchText.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateSearchText, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> certificateThumbprint = new()
        {
            Id = "P.CertificateThumbprint",
            Default = string.Empty,
            Secure = false,
            Hidden = true,
            Public = false,
            Summary = "CertificateThumbprint",
        };

        public System.String CertificateThumbprint
        {
            get
            {
                string stringValue = this.FnGetPropValue(certificateThumbprint.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(certificateThumbprint, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> configureGateway = new()
        {
            Id = "P.CONFIGUREGATEWAY",
            Default = false,
            Secure = false,
            Hidden = false,
            Public = true,
            Summary = "ConfigureGateway",
        };

        /// <summary>`true` to configure the Gateway interactively</summary>
        public System.Boolean ConfigureGateway
        {
            get
            {
                string stringValue = this.FnGetPropValue(configureGateway.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(configureGateway, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> hasPowerShell = new()
        {
            Id = "P.HasPowerShell",
            Default = false,
            Secure = false,
            Hidden = false,
            Public = false,
            Summary = "HasPowerShell",
        };

        public System.Boolean HasPowerShell
        {
            get
            {
                string stringValue = this.FnGetPropValue(hasPowerShell.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(hasPowerShell, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> httpListenerHost = new()
        {
            Id = "P.HTTPLISTENERHOST",
            Default = "0.0.0.0",
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "HttpListenerHost",
        };

        public System.String HttpListenerHost
        {
            get
            {
                string stringValue = this.FnGetPropValue(httpListenerHost.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(httpListenerHost, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.UInt32> httpListenerPort = new()
        {
            Id = "P.HTTPLISTENERPORT",
            Default = 7171,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "HttpListenerPort",
        };

        public System.UInt32 HttpListenerPort
        {
            get
            {
                string stringValue = this.FnGetPropValue(httpListenerPort.Id);
                return WixProperties.GetPropertyValue<System.UInt32>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(httpListenerPort, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> httpListenerScheme = new()
        {
            Id = "P.HTTPLISTENERSCHEME",
            Default = Constants.HttpsProtocol,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "HttpListenerScheme",
        };

        public System.String HttpListenerScheme
        {
            get
            {
                string stringValue = this.FnGetPropValue(httpListenerScheme.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(httpListenerScheme, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> publicKeyFile = new()
        {
            Id = "P.PUBLICKEYFILE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Public Key File",
        };

        public System.String PublicKeyFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(publicKeyFile.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(publicKeyFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> privateKeyFile = new()
        {
            Id = "P.PRIVATEKEYFILE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Private Key File",
        };

        public System.String PrivateKeyFile
        {
            get
            {
                string stringValue = this.FnGetPropValue(privateKeyFile.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(privateKeyFile, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> generateKeyPair = new()
        {
            Id = "P.GENERATEKEYPAIR",
            Default = false,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "GenerateKeyPair",
        };

        public System.Boolean GenerateKeyPair
        {
            get
            {
                string stringValue = this.FnGetPropValue(generateKeyPair.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(generateKeyPair, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> powerShellPath = new()
        {
            Id = "P.PowerShellPath",
            Default = string.Empty,
            Secure = false,
            Hidden = true,
            Public = false,
            Summary = "PowerShellPath",
        };

        public System.String PowerShellPath
        {
            get
            {
                string stringValue = this.FnGetPropValue(powerShellPath.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(powerShellPath, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> noStartService = new()
        {
            Id = "P.DGW.NO_START_SERVICE",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "NoStartService",
        };

        public System.String NoStartService
        {
            get
            {
                string stringValue = this.FnGetPropValue(noStartService.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(noStartService, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.ServiceProcess.ServiceStartMode> serviceStart = new()
        {
            Id = "P.SERVICESTART",
            Default = ServiceStartMode.Manual,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Service Start Mode",
        };

        public System.ServiceProcess.ServiceStartMode ServiceStart
        {
            get
            {
                string stringValue = this.FnGetPropValue(serviceStart.Id);
                return WixProperties.GetPropertyValue<System.ServiceProcess.ServiceStartMode>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(serviceStart, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> tcpListenerHost = new()
        {
            Id = "P.TCPLISTENERHOST",
            Default = "0.0.0.0",
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "TcpListenerHost",
        };

        public System.String TcpListenerHost
        {
            get
            {
                string stringValue = this.FnGetPropValue(tcpListenerHost.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(tcpListenerHost, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.UInt32> tcpListenerPort = new()
        {
            Id = "P.TCPLISTENERPORT",
            Default = 8181,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "TcpListenerPort",
        };

        public System.UInt32 TcpListenerPort
        {
            get
            {
                string stringValue = this.FnGetPropValue(tcpListenerPort.Id);
                return WixProperties.GetPropertyValue<System.UInt32>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(tcpListenerPort, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> tcpListenerScheme = new()
        {
            Id = "P.TCPLISTENERSCHEME",
            Default = Constants.TcpProtocol,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "TcpListenerScheme",
        };

        public System.String TcpListenerScheme
        {
            get
            {
                string stringValue = this.FnGetPropValue(tcpListenerScheme.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(tcpListenerScheme, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> configureWebApp = new()
        {
            Id = "P.CONFIGUREWEBAPP",
            Default = false,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "ConfigureWebApp",
        };

        /// <summary>`true` to configure the standalone web application interactively</summary>
        public System.Boolean ConfigureWebApp
        {
            get
            {
                string stringValue = this.FnGetPropValue(configureWebApp.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(configureWebApp, value); 
                }
            }
        }
 
        internal static readonly WixProperty<Constants.AuthenticationMode> authenticationMode = new()
        {
            Id = "P.AUTHENTICATIONMODE",
            Default = Constants.AuthenticationMode.None,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Authentication Mode",
        };

        public Constants.AuthenticationMode AuthenticationMode
        {
            get
            {
                string stringValue = this.FnGetPropValue(authenticationMode.Id);
                return WixProperties.GetPropertyValue<Constants.AuthenticationMode>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(authenticationMode, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> webUsername = new()
        {
            Id = "P.WEBUSERNAME",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Default User",
        };

        public System.String WebUsername
        {
            get
            {
                string stringValue = this.FnGetPropValue(webUsername.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(webUsername, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> webPassword = new()
        {
            Id = "P.WEBPASSWORD",
            Default = string.Empty,
            Secure = true,
            Hidden = true,
            Public = true,
            Summary = "Default Password",
        };

        public System.String WebPassword
        {
            get
            {
                string stringValue = this.FnGetPropValue(webPassword.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(webPassword, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> configureNgrok = new()
        {
            Id = "P.CONFIGURENGROK",
            Default = false,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "ConfigureNgrok",
        };

        /// <summary>`true` to use ngrok for ingress listeners</summary>
        public System.Boolean ConfigureNgrok
        {
            get
            {
                string stringValue = this.FnGetPropValue(configureNgrok.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(configureNgrok, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> ngrokAuthToken = new()
        {
            Id = "P.NGROKAUTHTOKEN",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Authentication Token",
        };

        public System.String NgrokAuthToken
        {
            get
            {
                string stringValue = this.FnGetPropValue(ngrokAuthToken.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(ngrokAuthToken, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> ngrokHttpDomain = new()
        {
            Id = "P.NGROKHTTPDOMAIN",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Domain",
        };

        public System.String NgrokHttpDomain
        {
            get
            {
                string stringValue = this.FnGetPropValue(ngrokHttpDomain.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(ngrokHttpDomain, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> ngrokEnableTcp = new()
        {
            Id = "P.NGROKENABLETCP",
            Default = false,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Native Client Access",
        };

        public System.Boolean NgrokEnableTcp
        {
            get
            {
                string stringValue = this.FnGetPropValue(ngrokEnableTcp.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(ngrokEnableTcp, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.String> ngrokRemoteAddress = new()
        {
            Id = "P.NGROKREMOTEADDRESS",
            Default = string.Empty,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "Remote Address",
        };

        public System.String NgrokRemoteAddress
        {
            get
            {
                string stringValue = this.FnGetPropValue(ngrokRemoteAddress.Id);
                return WixProperties.GetPropertyValue<System.String>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(ngrokRemoteAddress, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> debugPowerShell = new()
        {
            Id = "P.DEBUGPOWERSHELL",
            Default = false,
            Secure = true,
            Hidden = false,
            Public = true,
            Summary = "DebugPowerShell",
        };

        public System.Boolean DebugPowerShell
        {
            get
            {
                string stringValue = this.FnGetPropValue(debugPowerShell.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(debugPowerShell, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Guid> installId = new()
        {
            Id = "P.InstallId",
            Default = Guid.Empty,
            Secure = false,
            Hidden = false,
            Public = false,
            Summary = "InstallId",
        };

        public System.Guid InstallId
        {
            get
            {
                string stringValue = this.FnGetPropValue(installId.Id);
                return WixProperties.GetPropertyValue<System.Guid>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(installId, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.UInt32> netFx45Version = new()
        {
            Id = "P.NetFx45Version",
            Default = 0,
            Secure = false,
            Hidden = false,
            Public = false,
            Summary = "NetFx45Version",
        };

        public System.UInt32 NetFx45Version
        {
            get
            {
                string stringValue = this.FnGetPropValue(netFx45Version.Id);
                return WixProperties.GetPropertyValue<System.UInt32>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(netFx45Version, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> firstInstall = new()
        {
            Id = "P.FirstInstall",
            Default = false,
            Secure = false,
            Hidden = false,
            Public = false,
            Summary = "FirstInstall",
        };

        public System.Boolean FirstInstall
        {
            get
            {
                string stringValue = this.FnGetPropValue(firstInstall.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(firstInstall, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> upgrading = new()
        {
            Id = "P.Upgrading",
            Default = false,
            Secure = false,
            Hidden = false,
            Public = false,
            Summary = "Upgrading",
        };

        public System.Boolean Upgrading
        {
            get
            {
                string stringValue = this.FnGetPropValue(upgrading.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(upgrading, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> removingForUpgrade = new()
        {
            Id = "P.RemovingForUpgrade",
            Default = false,
            Secure = false,
            Hidden = false,
            Public = false,
            Summary = "RemovingForUpgrade",
        };

        public System.Boolean RemovingForUpgrade
        {
            get
            {
                string stringValue = this.FnGetPropValue(removingForUpgrade.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(removingForUpgrade, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> uninstalling = new()
        {
            Id = "P.Uninstalling",
            Default = false,
            Secure = false,
            Hidden = false,
            Public = false,
            Summary = "Uninstalling",
        };

        public System.Boolean Uninstalling
        {
            get
            {
                string stringValue = this.FnGetPropValue(uninstalling.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
            }
            set 
            { 
                if (this.runtimeSession is not null)
                {
                    this.runtimeSession.Set(uninstalling, value); 
                }
            }
        }
 
        internal static readonly WixProperty<System.Boolean> maintenance = new()
        {
            Id = "P.Maintenance",
            Default = false,
            Secure = false,
            Hidden = false,
            Public = false,
            Summary = "Maintenance",
        };

        public System.Boolean Maintenance
        {
            get
            {
                string stringValue = this.FnGetPropValue(maintenance.Id);
                return WixProperties.GetPropertyValue<System.Boolean>(stringValue);
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
 
            configureGateway,
 
            hasPowerShell,
 
            httpListenerHost,
 
            httpListenerPort,
 
            httpListenerScheme,
 
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

