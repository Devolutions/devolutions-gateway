using Devolutions.Pedm.Client.Api;
using Devolutions.Pedm.Client.Model;
using System;
using System.IO;
using System.Linq;
using System.Net.Http;

namespace Devolutions.Agent.Desktop.Service
{
    internal class Client
    {
        internal static bool Available => Directory.GetFiles(@"\\.\pipe\").Contains(@"\\.\pipe\DevolutionsPEDM");

        internal static GetProfilesMeResponse CurrentProfiles()
        {
            return Instance().PolicyMeGet();
        }

        internal static Profile GetProfile(long id)
        {
            return Instance().PolicyProfilesIdGet(id);
        }

        internal static void SetCurrentProfile(long id)
        {
            Instance().PolicyMePut(new OptionalId(id));
        }

        private static DefaultApi Instance()
        {
            if (!Available)
            {
                throw new FileNotFoundException("DevolutionsPEDM");
            }

            NamedPipeMessageHandler handler = new NamedPipeMessageHandler("DevolutionsPEDM");

            HttpClient httpClient = new(handler)
            {
                BaseAddress = new Uri("http://localhost/"),
                Timeout = TimeSpan.FromSeconds(3)
            };

            return new DefaultApi(httpClient);
        }
    }
}
