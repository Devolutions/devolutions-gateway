using DevolutionsAgent.Helpers;
using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;
using Microsoft.Deployment.WindowsInstaller;
using System;
using System.Collections.Generic;
using System.Linq;
using WixSharp;
using WixSharpSetup.Dialogs;

namespace DevolutionsAgent.Dialogs;

internal static class Wizard
{
    internal static Dictionary<string, string> Globals = new Dictionary<string, string>();

    private static readonly Type[] Sequence;

    static Wizard()
    {
        List<Type> dialogs = new()
        {
            typeof(WelcomeDialog),
            typeof(FeaturesDialog),
            typeof(AgentTunnelDialog),
            typeof(InstallDirDialog),
        };

        dialogs.Add(typeof(VerifyReadyDialog));

        Sequence = dialogs.ToArray();
    }

    internal static IEnumerable<Type> Dialogs => Sequence;

    internal static int Move(IManagedDialog current, bool forward)
    {
        Type t = current.GetType();
        int index = Dialogs.FindIndex(t);

        // Skip dialogs whose preconditions aren't met (e.g. feature unselected).
        // Iterating handles both forward and back traversal symmetrically.
        while (true)
        {
            index = forward ? index + 1 : index - 1;
            if (index < 0 || index >= Sequence.Length) break;
            if (!ShouldSkip(Sequence[index], current)) break;
        }
        return index;
    }

    private static bool ShouldSkip(Type dialogType, IManagedDialog current)
    {
        if (dialogType == typeof(AgentTunnelDialog))
        {
            string addlocal = (current as WixSharp.UI.Forms.ManagedForm)?.MsiRuntime?.Session?["ADDLOCAL"] ?? string.Empty;
            // ADDLOCAL=ALL installs every feature (Agent Tunnel included) without naming them, so a
            // literal feature-id match would miss it and wrongly skip the dialog. Tokens are matched
            // case-sensitively because Windows Installer treats the ALL keyword and feature names as
            // case-sensitive; matching the same way keeps this decision in lockstep with whether MSI
            // will actually install the feature (and therefore run EnrollAgentTunnel).
            bool installsTunnel = addlocal
                .Split(',')
                .Select(s => s.Trim())
                .Any(f => f == "ALL" || f == Features.AGENT_TUNNEL_FEATURE.Id);
            return !installsTunnel;
        }
        return false;
    }

    internal static int GetNext(IManagedDialog current) => Move(current, true);

    internal static int GetPrevious(IManagedDialog current) => Move(current, false);
}
