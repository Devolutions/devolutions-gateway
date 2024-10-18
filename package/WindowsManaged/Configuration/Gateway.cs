using Newtonsoft.Json;
using System.Collections.Generic;
using System.ComponentModel;

namespace DevolutionsGateway.Configuration
{
    public class Gateway
    {
        public string Id { get; set; }

        public string Hostname { get; set; }

        public string ProvisionerPublicKeyFile { get; set; }

        public string ProvisionerPrivateKeyFile { get; set; }

        public SubProvisionerPublicKey SubProvisionerPublicKey { get; set; }

        public string DelegationPrivateKeyFile { get; set; }

        [DefaultValue("External")]
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Populate)]
        public string TlsCertificateSource { get; set; }

        public string TlsCertificateSubjectName { get; set; }

        public string TlsCertificateStoreName { get; set; }

        public string TlsCertificateStoreLocation { get; set; }

        public string TlsCertificateFile { get; set; }

        public string TlsPrivateKeyFile { get; set; }

        public string TlsPrivateKeyPassword { get; set; }

        public Listener[] Listeners { get; set; }

        public Subscriber Subscriber { get; set; }

        [DefaultValue("recordings")]
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Populate)]
        public string RecordingPath { get; set; }

        [DefaultValue("jrl.json")]
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Populate)]
        public string JrlFile { get; set; }

        public string LogFile { get; set; }

        public Ngrok Ngrok { get; set; }

        public WebApp WebApp { get; set; }

        public string VerbosityProfile { get; set; }
    }
}
