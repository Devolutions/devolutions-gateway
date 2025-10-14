namespace DevolutionsGateway.Properties
{
    public partial class Constants
    {
        internal const string SetDGatewayHostnameCommandFormat = "Set-DGatewayHostname {0}";

        internal const string SetDGatewayListenersCommandFormat = "$httpListener = New-DGatewayListener '{0}' '{1}'; $tcpListener = New-DGatewayListener 'tcp://*:{2}' 'tcp://*:{3}'; $listeners = $httpListener, $tcpListener; Set-DGatewayListeners $listeners";

        internal const string ImportDGatewayCertificateWithPasswordCommandFormat = "Import-DGatewayCertificate -CertificateFile '{0}' -Password '{1}'";

        internal const string ImportDGatewayCertificateWithPrivateKeyCommandFormat = "Import-DGatewayCertificate -CertificateFile '{0}' -PrivateKeyFile '{1}'";

        internal const string ImportDGatewayCertificateFromSystemFormat = "Set-DGatewayConfig -TlsCertificateSource {0} -TlsCertificateSubjectName {1} -TlsCertificateStoreName {2} -TlsCertificateStoreLocation {3}";

        internal const string ImportDGatewayProvisionerKeyCommand = "Import-DGatewayProvisionerKey";

        internal const string ImportDGatewayProvisionerKeyCommandFormat = "Import-DGatewayProvisionerKey -PublicKeyFile '{0}'";

        internal const string NewDGatewayCertificateCommand = "New-DGatewayCertificate";

        internal const string NewDGatewayProvisionerKeyPairCommand = "New-DGatewayProvisionerKeyPair -Force";

        internal const string NgrokUrl = "www.ngrok.com";

        internal const string NgrokAuthTokenUrl = "https://dashboard.ngrok.com/get-started/your-authtoken";

        internal const string NgrokDomainsUrl = "https://dashboard.ngrok.com/cloud-edge/domains";

        internal const string NgrokTcpAddressesUrl = "https://dashboard.ngrok.com/cloud-edge/tcp-addresses";

        internal const string DevolutionsServerHelpLink = "https://redirection.devolutions.com/dgw-configuration-dvls";

        internal const string DevolutionsHubHelpLink = "https://redirection.devolutions.com/dgw-configuration-hub";
    }
}
