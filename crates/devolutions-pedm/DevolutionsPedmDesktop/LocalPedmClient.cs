using System.IO.Pipes;
using System.Net.Http;
using System.Security.Principal;
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
                    // The service impersonates the client to act on its behalf.
                    var pipe = new NamedPipeClientStream(
                        ".",
                        "DevolutionsPEDM",
                        PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.ReadPermissions,
                        PipeOptions.None,
                        TokenImpersonationLevel.Impersonation,
                        HandleInheritability.None);

                    try
                    {
                        await pipe.ConnectAsync(ct);
                        PedmServerVerifier.Verify(pipe);
                    }
                    catch
                    {
                        pipe.Dispose();
                        throw;
                    }

                    return pipe;
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
