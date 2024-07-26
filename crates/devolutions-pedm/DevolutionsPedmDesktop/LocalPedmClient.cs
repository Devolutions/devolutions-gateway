using System.IO.Pipes;
using System.Net.Http.Json;
using Devolutions.Pedm.Client;
using Devolutions.Pedm.Client.Api;

namespace DevolutionsPedmDesktop
{
    internal static class LocalPedmClient
    {
        public static DefaultApi Get()
        {
            var httpHandler = new SocketsHttpHandler
            {
                ConnectCallback = async(ctx, ct) => {
                    var pipe = new NamedPipeClientStream(".", "DevolutionsPEDM", PipeDirection.InOut);

                    await pipe.ConnectAsync(ct);

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
