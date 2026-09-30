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

        this.BackColor = Color.FromArgb(241, 241, 241);
        this.imgPanel.BackColor = this.BackColor;
        this.textPanel.BackColor = this.BackColor;
        this.image.BackColor = this.BackColor;
        this.image.Width = 162;
    }

    public override void OnLoad(object sender, System.EventArgs e)
    {
        using Stream stream = GetType().Assembly.GetManifestResourceStream("DevolutionsAgent.Resources.AgentDialogSide.png")
            ?? throw new InvalidOperationException("the Agent exit-dialog illustration is missing");
        using Image illustration = Image.FromStream(stream);
        image.Image = new Bitmap(illustration);

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
