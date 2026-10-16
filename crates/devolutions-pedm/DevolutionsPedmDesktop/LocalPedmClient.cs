using System.IO.Pipes;
using System.Net.Http;
using Devolutions.Pedm.Client.Api;

namespace DevolutionsPedmDesktop
{
    internal static class LocalPedmClient
    {
        public static DefaultApi Get()
        {
            var httpHandler = new StandardSocketsHttpHandler
            {
                ConnectCallback = async(ctx, ct) => {
                    // Request only the access the service grants to clients; ReadPermissions is needed by PedmServerVerifier.
                    // The verifier grants the impersonation level only to a server it verified.
                    return await PedmServerVerifier.ConnectAsync(
                        level => new NamedPipeClientStream(
                            ".",
                            "DevolutionsPEDM",
                            PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.ReadPermissions,
                            PipeOptions.None,
                            level,
                            HandleInheritability.None),
                        ct).ConfigureAwait(false);
                }
            };

            var client = new HttpClient(httpHandler)
            {
                BaseAddress = new Uri("http://localhost/")
            };

            return new DefaultApi(client);
        }
    }
}
