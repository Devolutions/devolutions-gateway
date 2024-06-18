using System.Collections.Generic;

namespace DevolutionsGateway.Configuration
{
    public class Ngrok
    {
        public string AuthToken { get; set; }

        public int? HeartbeatInterval { get; set; }

        public int? HeartbeatTolerance { get; set; }

        public string Metadata { get; set; }

        public string ServerAddr { get; set; }

        public Dictionary<string, Tunnel> Tunnels { get; set; }
    }
}
