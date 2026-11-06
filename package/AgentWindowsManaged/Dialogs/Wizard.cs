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
            typeof(PsuDialog),
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
            return !addlocal.Split(',').Select(s => s.Trim()).Contains(Features.AGENT_TUNNEL_FEATURE.Id);
        }
        if (dialogType == typeof(PsuDialog))
        {
            string addlocal = (current as WixSharp.UI.Forms.ManagedForm)?.MsiRuntime?.Session?["ADDLOCAL"] ?? string.Empty;
            return !addlocal.Split(',').Select(s => s.Trim()).Contains(Features.PSU_FEATURE.Id);
        }
        return false;
    }

    internal static int GetNext(IManagedDialog current) => Move(current, true);

    internal static int GetPrevious(IManagedDialog current) => Move(current, false);
}
