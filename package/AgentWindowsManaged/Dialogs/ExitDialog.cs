using System;
using DevolutionsAgent.Dialogs;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

namespace WixSharpSetup.Dialogs;

public partial class ExitDialog : AgentDialog
{
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

        base.OnLoad(sender, e);
    }

    void finish_Click(object sender, System.EventArgs e)
    {
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
}
