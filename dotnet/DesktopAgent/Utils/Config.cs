using System;
using System.IO;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace Devolutions.Agent.Desktop
{
    internal partial class Utils
    {
        internal static RootConfig LoadConfig()
        {
            try
            {
                string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
                string path = Path.Combine(programData, "Devolutions", "Agent", "agent.json");
                string json = File.ReadAllText(path);

                DataContractJsonSerializer serializer = new DataContractJsonSerializer(typeof(RootConfig));

                using (MemoryStream ms = new MemoryStream(Encoding.UTF8.GetBytes(json)))
                {
                    return (RootConfig)serializer.ReadObject(ms);
                }
            }
            catch
            {
                return null;
            }
        }
    }

    [DataContract]
    internal class RootConfig
    {
        [DataMember]
        public Feature Updater { get; set; }

        [DataMember]
        public Feature Session { get; set; }

        [DataMember]
        public Feature Pedm { get; set; }
    }

    [DataContract]
    internal class Feature
    {
        [DataMember]
        public bool Enabled { get; set; }
    }
}
