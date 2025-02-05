using System.Collections.Generic;
using WixSharp;

namespace DevolutionsAgent.Resources
{
    internal static class Features
    {
        internal static IEnumerable<Feature> ExperimentalFeatures => [ PEDM_FEATURE, SESSION_FEATURE ];

        internal static Feature AGENT_FEATURE = new("!(loc.FeatureAgentName)", true, false)
        {
            Id = "F.Agent", 
            Description = "!(loc.FeatureAgentDescription)"
        };

        internal static Feature PEDM_FEATURE = new("!(loc.FeaturePedmName)", "!(loc.FeaturePedmDescription)", false)
        {
            Id = "F.Pedm"
        };

        internal static Feature SESSION_FEATURE = new("!(loc.FeatureSessionName)", "!(loc.FeatureSessionDescription)", false)
        {
            Id = "F.Session"
        };
    }
}
