using System.IO.Pipes;
using System.Net.Http;
using System.Security.AccessControl;
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
                    // Request only the access the service grants to clients; ReadPermissions is needed by VerifyServer.
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
                        VerifyServer(pipe);
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

        /// <summary>
        /// Ensures the pipe server is the PEDM service: the pipe must be owned by SYSTEM or Administrators, which a standard user cannot assign.
        /// </summary>
        private static void VerifyServer(NamedPipeClientStream pipe)
        {
            var owner = pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;

            if (owner is null
                || !(owner.IsWellKnown(WellKnownSidType.LocalSystemSid) || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)))
            {
                throw new UnauthorizedAccessException("The PEDM pipe server is not trusted because the pipe is not owned by SYSTEM or Administrators.");
            }
        }
    }
}
