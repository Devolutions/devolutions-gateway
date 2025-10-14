using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;

using Microsoft.Win32;

using System;
using System.Windows.Forms;

using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class InstallDirDialog : GatewayDialog
{
    public InstallDirDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override bool ToProperties()
    {
        Runtime.Session[GatewayProperties.InstallDir] = installDir.Text;

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        string installDirProperty = Runtime.Session.Property("WixSharp_UI_INSTALLDIR");
        string installDirValue = Runtime.Session.Property(installDirProperty);

        if (string.IsNullOrEmpty(installDirValue))
        {
            try
            {
                RegistryKey localKey = RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, RegistryView.Registry64);
                RegistryKey gatewayKey = localKey.OpenSubKey($@"Software\{Includes.VENDOR_NAME}\{Includes.SHORT_NAME}");
                installDirValue = (string)gatewayKey?.GetValue("InstallDir");
            }
            catch
            {
            }

            if (string.IsNullOrEmpty(installDirValue))
            {
                //We are executed before any of the MSI actions are invoked so the INSTALLDIR (if set to absolute path)
                //is not resolved yet. So we need to do it manually
                this.installDir.Text = Runtime.Session.GetDirectoryPath(installDirProperty);

                if (this.installDir.Text == "ABSOLUTEPATH")
                    this.installDir.Text = Runtime.Session.Property("INSTALLDIR_ABSOLUTEPATH");
            }
            else
            {
                this.installDir.Text = installDirValue;
            }
        }
        else
        {
            //INSTALLDIR set either from the command line or by one of the early setup events (e.g. UILoaded)
            this.installDir.Text = installDirValue;
        }

        base.OnLoad(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);

    void Change_Click(object sender, EventArgs e)
    {
        using var dialog = new FolderBrowserDialog { SelectedPath = installDir.Text };

        if (dialog.ShowDialog(this) == DialogResult.OK)
        {
            installDir.Text = dialog.SelectedPath;
        }
    }
}
