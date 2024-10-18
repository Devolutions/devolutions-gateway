using System;
using DevolutionsGateway.Dialogs;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;
using DevolutionsGateway.Resources;

namespace WixSharpSetup.Dialogs;

public partial class ExitDialog : GatewayDialog
{
    private string warningsFile = null;

    public ExitDialog()
    {
        InitializeComponent();

        this.textPanel.BackColor = Color.FromArgb(233, 233, 233);
    }

    public override void OnLoad(object sender, System.EventArgs e)
    {
        image.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Dialog");

        if (Shell.UserInterrupted || Shell.Log.Contains("User cancelled installation."))
        {
            title.Text = "[UserExitTitle]";
            description.Text = "[UserExitDescription1]";
            this.Localize();
        }
        else if (Shell.ErrorDetected)
        {
            title.Text = "[FatalErrorTitle]";
            description.Text = Shell.CustomErrorDescription ?? "[FatalErrorDescription1]";
            this.Localize();
        }

        if (Guid.TryParse(Wizard.Globals["installId"], out Guid installId))
        {
            this.warningsFile = Path.Combine(Path.GetTempPath(), $"{installId}.{Includes.ERROR_REPORT_FILENAME}");

            if (File.Exists(this.warningsFile))
            {
                this.ViewErrorsButton.Visible = true;
            }
        }

        base.OnLoad(sender, e);
    }

    void finish_Click(object sender, System.EventArgs e)
    {
        if (!Shell.UserInterrupted && !Shell.ErrorDetected)
        {
            if (Wizard.Globals.TryGetValue("LaunchUrl", out string url))
            {
                try
                {
                    Process.Start(url.ToString());
                }
                catch
                {
                }
            }
        }

        Shell.Exit();
    }

    void viewLog_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
    {
        try
        {
            string wixSharpDir = Path.Combine(Path.GetTempPath(), @"WixSharp");
            if (!Directory.Exists(wixSharpDir))
                Directory.CreateDirectory(wixSharpDir);

            string logFile = Path.Combine(wixSharpDir, Runtime.ProductName + ".log");
            File.WriteAllText(logFile, Shell.Log);
            Process.Start(logFile);
        }
        catch
        {
            //Catch all, we don't want the installer to crash in an
            //attempt to view the log.
        }
    }

    private void ViewErrorsButton_LinkClicked(object sender, LinkLabelLinkClickedEventArgs e)
    {
        try
        {
            Process.Start(this.warningsFile);
        }
        catch
        {
        }
    }
}
