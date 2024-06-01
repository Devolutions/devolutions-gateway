using DevolutionsAgent.Helpers;
using DevolutionsAgent.Properties;
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

        index = forward ? index + 1 : index - 1;
        return index;
    }

    internal static int GetNext(IManagedDialog current) => Move(current, true);

    internal static int GetPrevious(IManagedDialog current) => Move(current, false);
}
