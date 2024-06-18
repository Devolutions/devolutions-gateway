namespace DevolutionsGateway.Configuration
{
    public class Tunnel
    {
        public string[] AllowCidrs { get; set; }

        public string[] DenyCidrs { get; set; }

        public string Metadata { get; set; }

        public string Proto { get; set; }

        // HTTP

        public string Domain { get; set; }
        
        public string CircuitBreaker { get; set; }

        public bool Compression { get; set; }

        // TCP

        public string RemoteAddr { get; set; }
    }
}
