using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;
using Microsoft.Deployment.WindowsInstaller;
using System;
using System.Collections.Generic;
using System.Linq;
using WixSharp;
using WixSharpSetup.Dialogs;

namespace DevolutionsGateway.Dialogs;

internal static class Wizard
{
    internal static Dictionary<string, string> Globals = new Dictionary<string, string>();

    private static readonly Type[] CustomizeSequence =
    {
        typeof(NgrokListenersDialog),
        typeof(ListenersDialog),
        typeof(AccessUriDialog),
        typeof(CertificateDialog),
        typeof(PublicKeyServerDialog),
        typeof(PublicKeyDialog),
        typeof(WebClientDialog),
        typeof(ServiceDialog),
        typeof(SummaryDialog),
    };

    private static readonly Type[] Sequence;

    static Wizard()
    {
        List<Type> dialogs = new()
        {
            typeof(WelcomeDialog),
            typeof(InstallDirDialog),
            typeof(CustomizeDialog),
        };

        dialogs.AddRange(CustomizeSequence);
        dialogs.Add(typeof(VerifyReadyDialog));

        Sequence = dialogs.ToArray();
    }
    
    internal static IEnumerable<Type> Dialogs => Sequence;

    private static bool Skip(Session session, Type dialog)
    {
        GatewayProperties properties = new(session);

        if (dialog == typeof(CustomizeDialog))
        {
            if (AppSearch.InstalledVersion is not null)
            {
                return true;
            }
        }

        if (dialog == typeof(NgrokListenersDialog))
        {
            if (!properties.ConfigureNgrok)
            {
                return true;
            }
        }

        if (dialog == typeof(ListenersDialog) || dialog == typeof(AccessUriDialog))
        {
            if (properties.ConfigureNgrok)
            {
                return true;
            }
        }

        if (dialog == typeof(CertificateDialog))
        {
            if (properties.HttpListenerScheme == Constants.HttpProtocol)
            {
                return true;
            }

            if (properties.ConfigureNgrok)
            {
                return true;
            }

            if (properties.ConfigureWebApp && properties.GenerateCertificate)
            {
                return true;
            }
        }

        if (dialog == typeof(PublicKeyServerDialog))
        {
            if (properties.ConfigureWebApp)
            {
                return true;
            }
        }

        if (dialog == typeof(PublicKeyDialog))
        {
            if (properties.ConfigureWebApp && properties.GenerateKeyPair)
            {
                return true;
            }

            if (!properties.ConfigureWebApp && !string.IsNullOrEmpty(properties.DevolutionsServerUrl))
            {
                return true;
            }
        }

        if (dialog == typeof(WebClientDialog))
        {
            if (!properties.ConfigureWebApp)
            {
                return true;
            }
        }

        if (dialog == typeof(ServiceDialog))
        {
            return true;
        }

        if (CustomizeSequence.Contains(dialog))
        {
            return !properties.ConfigureGateway;
        }

        return false;
    }

    internal static int Move(IManagedDialog current, bool forward)
    {
        Type t = current.GetType();
        int index = Dialogs.FindIndex(t);

        while (true)
        {
            index = forward ? index + 1 : index - 1;

            if (!Skip(current.Session(), Sequence[index]))
            {
                return index;
            }
        }
    }

    internal static int GetNext(IManagedDialog current) => Move(current, true);

    internal static int GetPrevious(IManagedDialog current) => Move(current, false);
}
