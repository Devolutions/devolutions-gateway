using WixSharp;

namespace DevolutionsGateway.Resources
{
	public static class Strings
	{
		public static string I18n(this MsiRuntime runtime, string res)
		{
			return $"[{res}]".LocalizeWith(runtime.Localize);
		}
		/// <summary>
		/// 1033
		/// </summary>
		public const string Language = "Language";		
		/// <summary>
		/// Devolutions
		/// </summary>
		public const string VendorName = "VendorName";		
		/// <summary>
		/// Devolutions Inc.
		/// </summary>
		public const string VendorFullName = "VendorFullName";		
		/// <summary>
		/// A blazing fast relay server adaptable to different protocols and desired levels of traffic inspection.
		/// </summary>
		public const string ProductDescription = "ProductDescription";		
		/// <summary>
		/// There is a problem with the entered data. Please correct the issue and try again.
		/// </summary>
		public const string ThereIsAProblemWithTheEnteredData = "ThereIsAProblemWithTheEnteredData";		
		/// <summary>
		/// You must enter a valid port
		/// </summary>
		public const string YouMustEnterAValidPort = "YouMustEnterAValidPort";		
		/// <summary>
		/// You must enter a valid URL
		/// </summary>
		public const string YouMustEnterAValidUrl = "YouMustEnterAValidUrl";		
		/// <summary>
		/// You must provide a valid hostname
		/// </summary>
		public const string YouMustProvideAValidHostname = "YouMustProvideAValidHostname";		
		/// <summary>
		/// You must select a certificate from the system certificate store
		/// </summary>
		public const string YouMustSelectACertificateFromTheSystemCertificateStore = "YouMustSelectACertificateFromTheSystemCertificateStore";		
		/// <summary>
		/// You must provide a valid certificate file and either a password or private key file
		/// </summary>
		public const string YouMustProvideAValidCertificateAndPasswordOrKey = "YouMustProvideAValidCertificateAndPasswordOrKey";		
		/// <summary>
		/// The specified file was invalid or not accessible
		/// </summary>
		public const string TheSpecifiedFileWasInvalidOrNotAccessible = "TheSpecifiedFileWasInvalidOrNotAccessible";		
		/// <summary>
		/// No matching certificates found
		/// </summary>
		public const string NoMatchingCertificatesFound = "NoMatchingCertificatesFound";		
		/// <summary>
		/// An unexpected error occurred accessing the system certificate store: {0}
		/// </summary>
		public const string AnUnexpectedErrorOccurredAccessingTheSystemCertificateStoreX = "AnUnexpectedErrorOccurredAccessingTheSystemCertificateStoreX";		
		/// <summary>
		/// The authentication token is required
		/// </summary>
		public const string AuthenticationTokenIsRequired = "AuthenticationTokenIsRequired";		
		/// <summary>
		/// The domain is required and must be a valid hostname
		/// </summary>
		public const string DomainIsRequiredAndMustBeValid = "DomainIsRequiredAndMustBeValid";		
		/// <summary>
		/// The remote address is required
		/// </summary>
		public const string RemoteAddressIsRequired = "RemoteAddressIsRequired";		
		/// <summary>
		/// The remote address must be a valid host and port in the format {host}:{port}
		/// </summary>
		public const string RemoteAddressMustBeInTheFormat = "RemoteAddressMustBeInTheFormat";		
		/// <summary>
		/// You must enter a username
		/// </summary>
		public const string YouMustEnterAUsername = "YouMustEnterAUsername";		
		/// <summary>
		/// You must enter a password
		/// </summary>
		public const string YouMustEnterAPassword = "YouMustEnterAPassword";		
		/// <summary>
		/// You must confirm the password
		/// </summary>
		public const string YouMustConfirmThePassword = "YouMustConfirmThePassword";		
		/// <summary>
		/// Passwords do not match
		/// </summary>
		public const string PasswordsDoNotMatch = "PasswordsDoNotMatch";		
		/// <summary>
		/// This product requires at least Windows 8 / Windows Server 2012 R2
		/// </summary>
		public const string OS2Old = "OS2Old";		
		/// <summary>
		/// A newer version of this product is already installed.
		/// </summary>
		public const string NewerInstalled = "NewerInstalled";		
		/// <summary>
		/// You need to install the 64-bit version of this product on 64-bit Windows.
		/// </summary>
		public const string x64VersionRequired = "x64VersionRequired";		
		/// <summary>
		/// You need to install the 32-bit version of this product on 32-bit Windows.
		/// </summary>
		public const string x86VersionRequired = "x86VersionRequired";		
		/// <summary>
		/// Microsoft .NET Framework 4.8 is strongly recommended. Would you like to download it now?
		/// </summary>
		public const string DotNet48IsStrongRecommendedDownloadNow = "DotNet48IsStrongRecommendedDownloadNow";		
		/// <summary>
		/// The product requires Microsoft .NET Framework 4.7.1. Microsoft .NET Framework 4.8 is strongly recommended. Would you like to download it now?
		/// </summary>
		public const string Dotnet471IsRequired = "Dotnet471IsRequired";		
		/// <summary>
		/// This product requires Windows PowerShell 5.1
		/// </summary>
		public const string WindowsPowerShell51IsRequired = "WindowsPowerShell51IsRequired";		
		/// <summary>
		/// Find your public key for {0} or {1}
		/// </summary>
		public const string FindYourPublicKeyForXorX = "FindYourPublicKeyForXorX";		
		/// <summary>
		/// Devolutions Server
		/// </summary>
		public const string FindYourPublicKeyDevolutionsServerLink = "FindYourPublicKeyDevolutionsServerLink";		
		/// <summary>
		/// Devolutions Hub
		/// </summary>
		public const string FindYourPublicKeyDevolutionsHubLink = "FindYourPublicKeyDevolutionsHubLink";		
		/// <summary>
		/// Read more at {0}
		/// </summary>
		public const string NgrokReadMoreAtX = "NgrokReadMoreAtX";		
		/// <summary>
		/// ngrok.com
		/// </summary>
		public const string NgrokReadMoreLink = "NgrokReadMoreLink";		
		/// <summary>
		/// Provide your {0}
		/// </summary>
		public const string NgrokProvideYourX = "NgrokProvideYourX";		
		/// <summary>
		/// authentication token
		/// </summary>
		public const string NgrokAuthTokenLink = "NgrokAuthTokenLink";		
		/// <summary>
		/// The {0} for web client access
		/// </summary>
		public const string NgrokXForWebClientAccess = "NgrokXForWebClientAccess";		
		/// <summary>
		/// domain
		/// </summary>
		public const string NgrokDomainLink = "NgrokDomainLink";		
		/// <summary>
		/// The {0} for native client access
		/// </summary>
		public const string NgroXForNativeClientAccess = "NgroXForNativeClientAccess";		
		/// <summary>
		/// TCP address
		/// </summary>
		public const string NgrokTcpAddressLink = "NgrokTcpAddressLink";		
		/// <summary>
		/// View
		/// </summary>
		public const string ViewButton = "ViewButton";		
		/// <summary>
		/// Search
		/// </summary>
		public const string SearchButton = "SearchButton";		
		/// <summary>
		/// View Log
		/// </summary>
		public const string ViewLogButton = "ViewLogButton";		
		/// <summary>
		/// View configuration issues
		/// </summary>
		public const string ViewErrorsButton = "ViewErrorsButton";		
		/// <summary>
		/// Validate
		/// </summary>
		public const string ValidateButton = "ValidateButton";		
		/// <summary>
		/// Install Location
		/// </summary>
		public const string Group_InstallLocation = "Group_InstallLocation";		
		/// <summary>
		/// Service
		/// </summary>
		public const string Group_Service = "Group_Service";		
		/// <summary>
		/// ngrok
		/// </summary>
		public const string Group_Ngrok = "Group_Ngrok";		
		/// <summary>
		/// External Access
		/// </summary>
		public const string Group_ExternalAccess = "Group_ExternalAccess";		
		/// <summary>
		/// Listeners
		/// </summary>
		public const string Group_Listeners = "Group_Listeners";		
		/// <summary>
		/// Encryption Keys
		/// </summary>
		public const string Group_EncryptionKeys = "Group_EncryptionKeys";		
		/// <summary>
		/// Web App
		/// </summary>
		public const string Group_WebApp = "Group_WebApp";		
		/// <summary>
		/// Certificate
		/// </summary>
		public const string Group_Certificate = "Group_Certificate";		
		/// <summary>
		/// Now
		/// </summary>
		public const string CustomizeMode_Now = "CustomizeMode_Now";		
		/// <summary>
		/// Later
		/// </summary>
		public const string CustomizeMode_Later = "CustomizeMode_Later";		
		/// <summary>
		/// External
		/// </summary>
		public const string CertificateMode_External = "CertificateMode_External";		
		/// <summary>
		/// System
		/// </summary>
		public const string CertificateMode_System = "CertificateMode_System";		
		/// <summary>
		/// Thumbprint
		/// </summary>
		public const string CertificateFindType_Thumbprint = "CertificateFindType_Thumbprint";		
		/// <summary>
		/// Subject Name
		/// </summary>
		public const string CertificateFindType_SubjectName = "CertificateFindType_SubjectName";		
		/// <summary>
		/// None
		/// </summary>
		public const string AuthenticationMode_None = "AuthenticationMode_None";		
		/// <summary>
		/// Custom
		/// </summary>
		public const string AuthenticationMode_Custom = "AuthenticationMode_Custom";		
		/// <summary>
		/// Current User
		/// </summary>
		public const string StoreLocation_CurrentUser = "StoreLocation_CurrentUser";		
		/// <summary>
		/// Local Machine
		/// </summary>
		public const string StoreLocation_LocalMachine = "StoreLocation_LocalMachine";		
		/// <summary>
		/// Personal
		/// </summary>
		public const string StoreName_My = "StoreName_My";		
		/// <summary>
		/// Trusted Root Certification Authorities
		/// </summary>
		public const string StoreName_Root = "StoreName_Root";		
		/// <summary>
		/// Intermediate Certification Authorities
		/// </summary>
		public const string StoreName_CertificateAuthority = "StoreName_CertificateAuthority";		
		/// <summary>
		/// Trusted Publishers
		/// </summary>
		public const string StoreName_TrustedPublisher = "StoreName_TrustedPublisher";		
		/// <summary>
		/// Untrusted Certificates
		/// </summary>
		public const string StoreName_Disallowed = "StoreName_Disallowed";		
		/// <summary>
		/// Third-Party Root Certification Authorities
		/// </summary>
		public const string StoreName_AuthRoot = "StoreName_AuthRoot";		
		/// <summary>
		/// Trusted People
		/// </summary>
		public const string StoreName_TrustedPeople = "StoreName_TrustedPeople";		
		/// <summary>
		/// Other People
		/// </summary>
		public const string StoreName_AddressBook = "StoreName_AddressBook";		
		/// <summary>
		/// Boot
		/// </summary>
		public const string ServiceStartMode_Boot = "ServiceStartMode_Boot";		
		/// <summary>
		/// System
		/// </summary>
		public const string ServiceStartMode_System = "ServiceStartMode_System";		
		/// <summary>
		/// Automatic
		/// </summary>
		public const string ServiceStartMode_Automatic = "ServiceStartMode_Automatic";		
		/// <summary>
		/// Manual
		/// </summary>
		public const string ServiceStartMode_Manual = "ServiceStartMode_Manual";		
		/// <summary>
		/// Disabled
		/// </summary>
		public const string ServiceStartMode_Disabled = "ServiceStartMode_Disabled";		
		/// <summary>
		/// Certificate Source
		/// </summary>
		public const string Property_CertificateMode = "Property_CertificateMode";		
		/// <summary>
		/// Certificate File
		/// </summary>
		public const string Property_CertificateFile = "Property_CertificateFile";		
		/// <summary>
		/// Certificate Password
		/// </summary>
		public const string Property_CertificatePassword = "Property_CertificatePassword";		
		/// <summary>
		/// Certificate Private Key
		/// </summary>
		public const string Property_CertificatePrivateKeyFile = "Property_CertificatePrivateKeyFile";		
		/// <summary>
		/// Certificate Location
		/// </summary>
		public const string Property_CertificateLocation = "Property_CertificateLocation";		
		/// <summary>
		/// Certificate Store
		/// </summary>
		public const string Property_CertificateStore = "Property_CertificateStore";		
		/// <summary>
		/// Certificate Name
		/// </summary>
		public const string Property_CertificateName = "Property_CertificateName";		
		/// <summary>
		/// Public Key File
		/// </summary>
		public const string Property_PublicKeyFile = "Property_PublicKeyFile";		
		/// <summary>
		/// Private Key File
		/// </summary>
		public const string Property_PrivateKeyFile = "Property_PrivateKeyFile";		
		/// <summary>
		/// Service Start Mode
		/// </summary>
		public const string Property_ServiceStart = "Property_ServiceStart";		
		/// <summary>
		/// Authentication Mode
		/// </summary>
		public const string Property_AuthenticationMode = "Property_AuthenticationMode";		
		/// <summary>
		/// Default Username
		/// </summary>
		public const string Property_WebUsername = "Property_WebUsername";		
		/// <summary>
		/// Default Password
		/// </summary>
		public const string Property_WebPassword = "Property_WebPassword";		
		/// <summary>
		/// Authentication Token
		/// </summary>
		public const string Property_NgrokAuthToken = "Property_NgrokAuthToken";		
		/// <summary>
		/// Domain
		/// </summary>
		public const string Property_NgrokHttpDomain = "Property_NgrokHttpDomain";		
		/// <summary>
		/// TCP Address
		/// </summary>
		public const string Property_NgrokRemoteAddress = "Property_NgrokRemoteAddress";		
		/// <summary>
		/// Directory
		/// </summary>
		public const string Property_Directory = "Property_Directory";		
		/// <summary>
		/// Access URI
		/// </summary>
		public const string Property_AccessUri = "Property_AccessUri";		
		/// <summary>
		/// HTTP Listener
		/// </summary>
		public const string Property_HttpListener = "Property_HttpListener";		
		/// <summary>
		/// TCP Listener
		/// </summary>
		public const string Property_TcpListener = "Property_TcpListener";		
		/// <summary>
		/// A new key pair will be generated
		/// </summary>
		public const string Property_NewKeyPair = "Property_NewKeyPair";		
		/// <summary>
		/// A new self-signed certificate will be generated
		/// </summary>
		public const string Property_NewCertificate = "Property_NewCertificate";		
		/// <summary>
		/// Devolutions Server URL
		/// </summary>
		public const string Property_DevolutionsServerUrl = "Property_DevolutionsServerUrl";		
		/// <summary>
		/// Protocol
		/// </summary>
		public const string Protocol = "Protocol";		
		/// <summary>
		/// Host
		/// </summary>
		public const string Host = "Host";		
		/// <summary>
		/// Port
		/// </summary>
		public const string Port = "Port";		
		/// <summary>
		/// Please wait for UAC prompt to appear.If it appears minimized then active it from the taskbar.
		/// </summary>
		public const string UACPromptLabel = "UACPromptLabel";		
		/// <summary>
		/// Public Key Files (*.pem)
		/// </summary>
		public const string Filter_PublicKeyFiles = "Filter_PublicKeyFiles";		
		/// <summary>
		/// Private Key Files (*.key)
		/// </summary>
		public const string Filter_PrivateKeyFiles = "Filter_PrivateKeyFiles";		
		/// <summary>
		/// PFX Files (*.pfx, *.p12)
		/// </summary>
		public const string Filter_PfxFiles = "Filter_PfxFiles";		
		/// <summary>
		/// Certificate Files (*.pem, *.crt, *.cer)
		/// </summary>
		public const string Filter_CertificateFiles = "Filter_CertificateFiles";		
		/// <summary>
		/// All Files
		/// </summary>
		public const string Filter_AllFiles = "Filter_AllFiles";		
		/// <summary>
		/// [ProductName] Setup
		/// </summary>
		public const string GatewayDlg_Title = "GatewayDlg_Title";		
		/// <summary>
		/// Change destination folder
		/// </summary>
		public const string BrowseDlgTitle = "BrowseDlgTitle";		
		/// <summary>
		/// Browse to the destination folder
		/// </summary>
		public const string BrowseDlgDescription = "BrowseDlgDescription";		
		/// <summary>
		/// Destination Folder
		/// </summary>
		public const string InstallDirDlgTitle = "InstallDirDlgTitle";		
		/// <summary>
		/// Click Next to install to the default folder or click Change to choose another.
		/// </summary>
		public const string InstallDirDlgDescription = "InstallDirDlgDescription";		
		/// <summary>
		/// Installing [ProductName]
		/// </summary>
		public const string ProgressDlgTitleInstalling = "ProgressDlgTitleInstalling";		
		/// <summary>
		/// Changing [ProductName]
		/// </summary>
		public const string ProgressDlgTitleChanging = "ProgressDlgTitleChanging";		
		/// <summary>
		/// Repairing [ProductName]
		/// </summary>
		public const string ProgressDlgTitleRepairing = "ProgressDlgTitleRepairing";		
		/// <summary>
		/// Removing [ProductName]
		/// </summary>
		public const string ProgressDlgTitleRemoving = "ProgressDlgTitleRemoving";		
		/// <summary>
		/// Updating [ProductName]
		/// </summary>
		public const string ProgressDlgTitleUpdating = "ProgressDlgTitleUpdating";		
		/// <summary>
		/// Ready to install [ProductName]
		/// </summary>
		public const string VerifyReadyDlgInstallTitle = "VerifyReadyDlgInstallTitle";		
		/// <summary>
		/// Ready to change [ProductName]
		/// </summary>
		public const string VerifyReadyDlgChangeTitle = "VerifyReadyDlgChangeTitle";		
		/// <summary>
		/// Ready to repair [ProductName]
		/// </summary>
		public const string VerifyReadyDlgRepairTitle = "VerifyReadyDlgRepairTitle";		
		/// <summary>
		/// Ready to remove [ProductName]
		/// </summary>
		public const string VerifyReadyDlgRemoveTitle = "VerifyReadyDlgRemoveTitle";		
		/// <summary>
		/// Ready to update [ProductName]
		/// </summary>
		public const string VerifyReadyDlgUpdateTitle = "VerifyReadyDlgUpdateTitle";		
		/// <summary>
		/// Welcome to the [ProductName] 20[ProductVersion] Setup Wizard
		/// </summary>
		public const string WelcomeDlgTitle = "WelcomeDlgTitle";		
		/// <summary>
		/// Configuration
		/// </summary>
		public const string CustomInstallDlgTitle = "CustomInstallDlgTitle";		
		/// <summary>
		/// Choose how to configure [ProductName].
		/// </summary>
		public const string CustomInstallDlgDescription = "CustomInstallDlgDescription";		
		/// <summary>
		/// The Setup Wizard will generate a configuration which you can update later; or you can provide configuration information now.
		/// </summary>
		public const string CustomInstallDlgInfoLabel = "CustomInstallDlgInfoLabel";		
		/// <summary>
		/// Recommended for most installations. Generate a basic configuration using this installer and start the Gateway service automatically.
		/// </summary>
		public const string RecommendedForMostInstallations = "RecommendedForMostInstallations";		
		/// <summary>
		/// The Gateway service will need to be manually configured and started after installation.
		/// </summary>
		public const string RecommendedForManualInstallations = "RecommendedForManualInstallations";		
		/// <summary>
		/// Configure the Gateway installation
		/// </summary>
		public const string ConfigureTheGatewayInstallation = "ConfigureTheGatewayInstallation";		
		/// <summary>
		/// Configuration Options
		/// </summary>
		public const string ConfigurationOptions = "ConfigurationOptions";		
		/// <summary>
		/// Enable access over the internet using ngrok
		/// </summary>
		public const string EnableAccessOverTheInternetUsingNgrok = "EnableAccessOverTheInternetUsingNgrok";		
		/// <summary>
		/// Enable the Gateway web interface
		/// </summary>
		public const string EnableTheGatewayWebInterface = "EnableTheGatewayWebInterface";		
		/// <summary>
		/// Generate a self-signed HTTPS certificate
		/// </summary>
		public const string GenerateASelfSignedHttpsCertificate = "GenerateASelfSignedHttpsCertificate";		
		/// <summary>
		/// Generate encryption keys
		/// </summary>
		public const string GenerateEncryptionKeys = "GenerateEncryptionKeys";		
		/// <summary>
		/// External URL
		/// </summary>
		public const string AccessUriDlgTitle = "AccessUriDlgTitle";		
		/// <summary>
		/// URL to reach [ProductName].
		/// </summary>
		public const string AccessUriDlgDescription = "AccessUriDlgDescription";		
		/// <summary>
		/// The URI to reach the Gateway externally for HTTP operations. This may differ from the HTTP listener address in certain cases (for example, when using a reverse proxy such as IIS).
		/// </summary>
		public const string AccessUriDlgExplanation = "AccessUriDlgExplanation";		
		/// <summary>
		/// An insecure external URI is not recommended for production environments
		/// </summary>
		public const string AccessUriDlgHttpWarn = "AccessUriDlgHttpWarn";		
		/// <summary>
		/// Certificate
		/// </summary>
		public const string CertificateDlgTitle = "CertificateDlgTitle";		
		/// <summary>
		/// A certificate is required when using an HTTPS listener.
		/// </summary>
		public const string CertificateDlgDescription = "CertificateDlgDescription";		
		/// <summary>
		/// Certificate Configuration
		/// </summary>
		public const string CertificateDlgCertConfigLabel = "CertificateDlgCertConfigLabel";		
		/// <summary>
		/// Certificate File
		/// </summary>
		public const string CertificateDlgCertFileLabel = "CertificateDlgCertFileLabel";		
		/// <summary>
		/// Certificate Password
		/// </summary>
		public const string CertificateDlgCertPasswordLabel = "CertificateDlgCertPasswordLabel";		
		/// <summary>
		/// Private Key File
		/// </summary>
		public const string CertificateDlgCertKeyFileLabel = "CertificateDlgCertKeyFileLabel";		
		/// <summary>
		/// Certificate Source
		/// </summary>
		public const string CertificateSource = "CertificateSource";		
		/// <summary>
		/// Enter text to search
		/// </summary>
		public const string EnterTextToSearch = "EnterTextToSearch";		
		/// <summary>
		/// Search for a certificate to use
		/// </summary>
		public const string SearchForACertificateToUse = "SearchForACertificateToUse";		
		/// <summary>
		/// Store Location
		/// </summary>
		public const string StoreLocation = "StoreLocation";		
		/// <summary>
		/// Certificate Store
		/// </summary>
		public const string CertificateStore = "CertificateStore";		
		/// <summary>
		/// Search By
		/// </summary>
		public const string SearchBy = "SearchBy";		
		/// <summary>
		/// Search
		/// </summary>
		public const string Search = "Search";		
		/// <summary>
		/// Selected Certificate
		/// </summary>
		public const string SelectedCertificate = "SelectedCertificate";		
		/// <summary>
		/// Browse for a certificate to use
		/// </summary>
		public const string BrowseForACertificateToUse = "BrowseForACertificateToUse";		
		/// <summary>
		/// Encrypted private keys are not supported
		/// </summary>
		public const string EncryptedPrivateKeysAreNotSupported = "EncryptedPrivateKeysAreNotSupported";		
		/// <summary>
		/// Select the certificate to use
		/// </summary>
		public const string SelectTheCertificateToUse = "SelectTheCertificateToUse";		
		/// <summary>
		/// An X.509 certificate in PKCS#12 (PFX/P12) binary format or PEM-encoded
		/// </summary>
		public const string AnX509CertificateInBinaryOrPemEncoded = "AnX509CertificateInBinaryOrPemEncoded";		
		/// <summary>
		/// Listeners
		/// </summary>
		public const string ListenersDlgTitle = "ListenersDlgTitle";		
		/// <summary>
		/// HTTP(S) and TCP port listeners.
		/// </summary>
		public const string ListenersDlgDescription = "ListenersDlgDescription";		
		/// <summary>
		/// Listeners
		/// </summary>
		public const string ListenersDlgListenersLabel = "ListenersDlgListenersLabel";		
		/// <summary>
		/// HTTP Listener
		/// </summary>
		public const string ListenersDlgHTTPLabel = "ListenersDlgHTTPLabel";		
		/// <summary>
		/// TCP Listener
		/// </summary>
		public const string ListenersDlgTCPLabel = "ListenersDlgTCPLabel";		
		/// <summary>
		/// An HTTP listener does not require a certificate.
		/// </summary>
		public const string AnHttpListenerDoesNotRequireACert = "AnHttpListenerDoesNotRequireACert";		
		/// <summary>
		/// An HTTPS listener requires a certificate. The self-signed certificate generated by this installer is not trusted by default.
		/// </summary>
		public const string AnHttpsListenerRequiresACertSelfSigned = "AnHttpsListenerRequiresACertSelfSigned";		
		/// <summary>
		/// An HTTPS listener requires a certificate. You will be prompted to configure one.
		/// </summary>
		public const string AnHttpsListenerRequiresACert = "AnHttpsListenerRequiresACert";		
		/// <summary>
		/// Invalid port
		/// </summary>
		public const string InvalidPort = "InvalidPort";		
		/// <summary>
		/// The chosen port is available
		/// </summary>
		public const string ChosenPortAvailable = "ChosenPortAvailable";		
		/// <summary>
		/// The chosen port might not be available
		/// </summary>
		public const string ChosenPortNotAvailable = "ChosenPortNotAvailable";		
		/// <summary>
		/// The chosen port could not be checked
		/// </summary>
		public const string ChosenPortCouldNotBeChecked = "ChosenPortCouldNotBeChecked";		
		/// <summary>
		/// ngrok
		/// </summary>
		public const string NgrokListenersDlgTitle = "NgrokListenersDlgTitle";		
		/// <summary>
		/// ngrok listener configuration.
		/// </summary>
		public const string NgrokListenersDlgDescription = "NgrokListenersDlgDescription";		
		/// <summary>
		/// Use ngrok for simplified remote access from the Internet. Gateway listeners allow access from any IP address by default.
		/// </summary>
		public const string UseNgrokForSimplifiedRemoteAccess = "UseNgrokForSimplifiedRemoteAccess";		
		/// <summary>
		/// Auth Token
		/// </summary>
		public const string AuthToken = "AuthToken";		
		/// <summary>
		/// Domain
		/// </summary>
		public const string Domain = "Domain";		
		/// <summary>
		/// Native Client Access
		/// </summary>
		public const string NativeClientAccess = "NativeClientAccess";		
		/// <summary>
		/// Configure
		/// </summary>
		public const string Configure = "Configure";		
		/// <summary>
		/// Remote Address
		/// </summary>
		public const string RemoteAddress = "RemoteAddress";		
		/// <summary>
		/// Companion Server
		/// </summary>
		public const string PublicKeyServerDlgTitle = "PublicKeyServerDlgTitle";		
		/// <summary>
		/// Automatic server configuration
		/// </summary>
		public const string PublicKeyServerDlgDescription = "PublicKeyServerDlgDescription";		
		/// <summary>
		/// If you're using Devolutions Server, provide the address. This step is optional.
		/// </summary>
		public const string ProvideDvlsAddressIfUsing = "ProvideDvlsAddressIfUsing";		
		/// <summary>
		/// Automatic configuration with Devolutions Server
		/// </summary>
		public const string AutomaticConfigurationWithDvls = "AutomaticConfigurationWithDvls";		
		/// <summary>
		/// Manual configuration
		/// </summary>
		public const string ManualConfiguration = "ManualConfiguration";		
		/// <summary>
		/// The public key will be downloaded
		/// </summary>
		public const string ThePublicKeyWillBeDownloaded = "ThePublicKeyWillBeDownloaded";		
		/// <summary>
		/// You'll need to provide the companion server public key
		/// </summary>
		public const string YoullNeedToProvideThePublicKey = "YoullNeedToProvideThePublicKey";		
		/// <summary>
		/// Untrusted Certificate
		/// </summary>
		public const string UntrustedCertificate = "UntrustedCertificate";		
		/// <summary>
		/// The certificate for {0} is not trusted. Do you wish to proceed?
		/// </summary>
		public const string TheCertificateForXIsNotTrustedDoYouWishToProceed = "TheCertificateForXIsNotTrustedDoYouWishToProceed";		
		/// <summary>
		/// Encryption Keys
		/// </summary>
		public const string PublicKeyDlgTitle = "PublicKeyDlgTitle";		
		/// <summary>
		/// Keys for token creation and verification.
		/// </summary>
		public const string PublicKeyDlgDescription = "PublicKeyDlgDescription";		
		/// <summary>
		/// Provide an encryption key for token verification.
		/// </summary>
		public const string ProvideAnEncryptionKeyPairForTokenVerification = "ProvideAnEncryptionKeyPairForTokenVerification";		
		/// <summary>
		/// Provide an encryption key pair for token generation and verification.
		/// </summary>
		public const string ProvideAnEncryptionKeyPairForTokenCreationVerification = "ProvideAnEncryptionKeyPairForTokenCreationVerification";		
		/// <summary>
		/// Public Key File
		/// </summary>
		public const string PublicKeyFile = "PublicKeyFile";		
		/// <summary>
		/// The public key is used to verify tokens without specific restrictions
		/// </summary>
		public const string ThePublicKeyIsUsedTo = "ThePublicKeyIsUsedTo";		
		/// <summary>
		/// Private Key File
		/// </summary>
		public const string PrivateKeyFile = "PrivateKeyFile";		
		/// <summary>
		/// The private key is used to generate session tokens for the standalone web application
		/// </summary>
		public const string ThePrivateKeyIsUsedTo = "ThePrivateKeyIsUsedTo";		
		/// <summary>
		/// Provide a public key for token verification. The private key for token generation is provisioned by a companion service (e.g. Devolutions Server).
		/// </summary>
		public const string ProvideAPublicKeyForTokenVerification = "ProvideAPublicKeyForTokenVerification";		
		/// <summary>
		/// Web Application Options
		/// </summary>
		public const string WebAppDlgTitle = "WebAppDlgTitle";		
		/// <summary>
		/// Configuration for the embedded web application.
		/// </summary>
		public const string WebAppDlgDescription = "WebAppDlgDescription";		
		/// <summary>
		/// Choose the authentication method used when accessing the web application
		/// </summary>
		public const string ChooseTheAuthenticationMethod = "ChooseTheAuthenticationMethod";		
		/// <summary>
		/// Authentication
		/// </summary>
		public const string Authentication = "Authentication";		
		/// <summary>
		/// Default User
		/// </summary>
		public const string DefaultUser = "DefaultUser";		
		/// <summary>
		/// Username
		/// </summary>
		public const string Username = "Username";		
		/// <summary>
		/// Password
		/// </summary>
		public const string Password = "Password";		
		/// <summary>
		/// Confirm Password
		/// </summary>
		public const string ConfirmPassword = "ConfirmPassword";		
		/// <summary>
		/// Summary
		/// </summary>
		public const string SummaryDlgTitle = "SummaryDlgTitle";		
		/// <summary>
		/// Click Next to use this configuration or click Back to make changes.
		/// </summary>
		public const string SummaryDlgDescription = "SummaryDlgDescription";		
	}
}
