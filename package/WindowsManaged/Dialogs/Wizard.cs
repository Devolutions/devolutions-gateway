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
    private static readonly Type[] CustomizeSequence =
    {
        typeof(NgrokListenersDialog),
        typeof(ListenersDialog),
        typeof(AccessUriDialog),
        typeof(CertificateDialog),
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

    private static Type lastDialog;

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

        if (dialog == typeof(PublicKeyDialog))
        {
            if (properties.ConfigureWebApp && properties.GenerateKeyPair)
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

    internal static void DialogChanged(IManagedDialog dialog)
    {
        Type previousDialog = lastDialog;
        lastDialog = dialog.GetType();

        Type currentDialog = lastDialog;

        if (!Skip(dialog.Session(), currentDialog))
        {
            return;
        }

        int index = Dialogs.FindIndex(currentDialog);
        int prevIndex = Dialogs.FindIndex(previousDialog);

        bool backward = index < prevIndex;

        while (Skip(dialog.Session(), currentDialog))
        {
            index = backward ? index - 1 : index + 1;
            currentDialog = Sequence[index];
        }

        dialog.Shell.GoTo(index);
    }
}
