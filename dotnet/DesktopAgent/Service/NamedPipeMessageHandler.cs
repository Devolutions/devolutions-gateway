using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Pipes;
using System.Net.Http;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Devolutions.Agent.Desktop.Service
{
    internal class NamedPipeMessageHandler(string pipeName) : HttpMessageHandler
    {
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            // Request only the access the service grants to clients; ReadPermissions is needed by VerifyServer.
            // The service impersonates the client to act on its behalf.
            using NamedPipeClientStream pipeClient = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.ReadPermissions,
                PipeOptions.Asynchronous,
                TokenImpersonationLevel.Impersonation,
                HandleInheritability.None);
            Task connectTask = pipeClient.ConnectAsync(cancellationToken);
            connectTask.GetAwaiter().GetResult();
            VerifyServer(pipeClient);

            string requestMessage = SerializeRequest(request);
            byte[] requestBytes = Encoding.UTF8.GetBytes(requestMessage);

            pipeClient.WriteAsync(requestBytes, 0, requestBytes.Length, cancellationToken).GetAwaiter().GetResult();
            pipeClient.FlushAsync(cancellationToken).GetAwaiter().GetResult();

            using MemoryStream memoryStream = new MemoryStream();
            pipeClient.CopyToAsync(memoryStream, 81920, cancellationToken).GetAwaiter().GetResult();
            string responseMessage = Encoding.UTF8.GetString(memoryStream.ToArray());

            return DeserializeResponse(responseMessage);
        }

        /// <summary>
        /// Ensures the pipe server is the PEDM service: the pipe must be owned by SYSTEM or Administrators, which a standard user cannot assign.
        /// </summary>
        private static void VerifyServer(NamedPipeClientStream pipe)
        {
            SecurityIdentifier owner = pipe.GetAccessControl().GetOwner(typeof(SecurityIdentifier)) as SecurityIdentifier;

            if (owner is null
                || !(owner.IsWellKnown(WellKnownSidType.LocalSystemSid) || owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid)))
            {
                throw new UnauthorizedAccessException("The PEDM pipe server is not trusted because the pipe is not owned by SYSTEM or Administrators.");
            }
        }

        private HttpResponseMessage DeserializeResponse(string responseMessage)
        {
            using StringReader reader = new StringReader(responseMessage);
            string statusLine = reader.ReadLine();
            string[] statusParts = statusLine.Split(' ');

            HttpResponseMessage response = new HttpResponseMessage((System.Net.HttpStatusCode)int.Parse(statusParts[1]))
            {
                Version = new Version(statusParts[0].Split('/')[1])
            };

            string line;

            while (!string.IsNullOrWhiteSpace(line = reader.ReadLine()))
            {
                string[] headerParts = line.Split([':'], 2);
                response.Headers.TryAddWithoutValidation(headerParts[0], headerParts[1].Trim());
            }

            string content = reader.ReadToEnd();
            response.Content = new StringContent(content);

            return response;
        }

        private string SerializeRequest(HttpRequestMessage request)
        {
            StringBuilder builder = new StringBuilder();
            builder.AppendLine($"{request.Method} {request.RequestUri} HTTP/{request.Version}");

            foreach (KeyValuePair<string, IEnumerable<string>> header in request.Headers)
            {
                builder.AppendLine($"{header.Key}: {string.Join(", ", header.Value)}");
            }

            if (request.Content != null)
            {
                foreach (KeyValuePair<string, IEnumerable<string>> header in request.Content.Headers)
                {
                    builder.AppendLine($"{header.Key}: {string.Join(", ", header.Value)}");
                }

                builder.AppendLine($"Content-Length: {request.Content.Headers.ContentLength}");
                builder.AppendLine();
                builder.Append(request.Content.ReadAsStringAsync().GetAwaiter().GetResult());
            }
            else
            {
                builder.AppendLine();
            }

            return builder.ToString();
        }
    }
}
