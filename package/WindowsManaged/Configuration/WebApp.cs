using System.ComponentModel;
using Newtonsoft.Json;

namespace DevolutionsGateway.Configuration
{
    public class WebApp
    {
        public bool Enabled { get; set; }

        public string Authentication { get; set; }

        public int AppTokenMaximumLifetime { get; set; }

        public int LoginLimitRate { get; set; }

        [DefaultValue(Actions.CustomActions.DefaultUsersFile)]
        [JsonProperty(DefaultValueHandling = DefaultValueHandling.Populate)]
        
        public string UsersFile { get; set; }

        public string StaticRootPath { get; set; }
    }
}
