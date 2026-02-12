using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Deployment.WindowsInstaller;
using WixSharp;

namespace DevolutionsAgent.Resources
{
    internal static class Features
    {
        internal const string FEATURE_ID_PREFIX = "F.";

        internal static IEnumerable<Feature> ExperimentalFeatures => [ ];

        internal static Feature AGENT_UPDATER_FEATURE = new("!(loc.FeatureAgentUpdaterName)", "!(loc.FeatureAgentUpdaterDescription)", isEnabled: true, allowChange: true)
        {
            Id = $"{FEATURE_ID_PREFIX}Updater"
        };

        internal static Feature AGENT_FEATURE = new("!(loc.FeatureAgentName)", isEnabled: true, allowChange: false)
        {
            Id = $"{FEATURE_ID_PREFIX}Agent", 
            Description = "!(loc.FeatureAgentDescription)",
            Children = [ AGENT_UPDATER_FEATURE ]
        };

        internal static Feature PEDM_FEATURE = new("!(loc.FeaturePedmName)", "!(loc.FeaturePedmDescription)", isEnabled: false)
        {
            Id = $"{FEATURE_ID_PREFIX}Pedm"
        };

        internal static Feature SESSION_FEATURE = new("!(loc.FeatureSessionName)", "!(loc.FeatureSessionDescription)", isEnabled: true)
        {
            Id = $"{FEATURE_ID_PREFIX}Session"
        };
    }

    internal class FeatureList
    {
        private readonly List<string> features;

        public FeatureList(string features)
        {
            this.features = features.Split([','], StringSplitOptions.RemoveEmptyEntries).ToList();
        }

        public FeatureList(IEnumerable<string> features)
        {
            this.features = features.ToList();
        }

        public FeatureList(IEnumerable<FeatureInstallation> features)
        {
            this.features = features.Select(x => x.FeatureName).ToList();
        }

        public void Add(string feature)
        {
            if (!this.features.Contains(feature))
            {
                this.features.Add(feature);
            }
        }

        public bool Contains(string feature) => this.features.Contains(feature);

        public void Remove(string feature)
        {
            this.features.RemoveAll(x => x.Equals(feature));
        }

        public override string ToString() => this.features.JoinBy(",");

        public string[] ToArray() => this.features.ToArray();
    }
}
