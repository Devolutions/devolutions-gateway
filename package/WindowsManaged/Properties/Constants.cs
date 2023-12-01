using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DevolutionsGateway.Properties
{
    internal class Constants
    {
        internal const string HttpProtocol = "http";

        internal const string HttpsProtocol = "https";

        internal const string TcpProtocol = "tcp";

        internal const string SetDGatewayHostnameCommandFormat = "Set-DGatewayHostname {0}";

        internal const string SetDGatewayListenersCommandFormat = "$httpListener = New-DGatewayListener '{0}' '{1}'; $tcpListener = New-DGatewayListener 'tcp://*:{2}' 'tcp://*:{3}'; $listeners = $httpListener, $tcpListener; Set-DGatewayListeners $listeners";

        internal const string ImportDGatewayCertificateWithPasswordCommandFormat = "Import-DGatewayCertificate -CertificateFile '{0}' -Password '{1}'";

        internal const string ImportDGatewayCertificateWithPrivateKeyCommandFormat = "Import-DGatewayCertificate -CertificateFile '{0} -PrivateKeyFile '{1}'";

        internal const string ImportDGatewayProvisionerKeyCommandFormat = "Import-DGatewayProvisionerKey -PublicKeyFile '{0}'";
    }
}
