using DevolutionsGateway.Dialogs;
using Microsoft.Deployment.WindowsInstaller;
using System;
using System.Drawing;
using System.Runtime.InteropServices;
using System.Security.Principal;
using WixSharp;
using WixSharp.CommonTasks;

namespace WixSharpSetup.Dialogs;

public partial class ProgressDialog : GatewayDialog, IProgressDialog
{
    private static Icon shieldIcon;

    public static Icon ShieldLarge => shieldIcon ?? (shieldIcon = GetStockIcon(SIID_SHIELD, SHGSI_LARGEICON));

    private static Icon GetStockIcon(uint type, uint size)
    {
        var info = new SHSTOCKICONINFO();
        info.cbSize = (uint)Marshal.SizeOf(info);

        SHGetStockIconInfo(type, SHGSI_ICON | size, ref info);

        var icon = (Icon)Icon.FromHandle(info.hIcon).Clone(); // Get a copy that doesn't use the original handle
        DestroyIcon(info.hIcon); // Clean up native icon to prevent resource leak

        return icon;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct SHSTOCKICONINFO
    {
        public uint cbSize;
        public IntPtr hIcon;
        public int iSysIconIndex;
        public int iIcon;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szPath;
    }

    [DllImport("shell32.dll")]
    public static extern int SHGetStockIconInfo(uint siid, uint uFlags, ref SHSTOCKICONINFO psii);

    [DllImport("user32.dll")]
    public static extern bool DestroyIcon(IntPtr handle);

    private const uint SIID_SHIELD = 77;
    private const uint SHGSI_ICON = 0x100;
    private const uint SHGSI_LARGEICON = 0x0;
    private const uint SHGSI_SMALLICON = 0x1;

    public ProgressDialog()
    {
        InitializeComponent();
        dialogText.MakeTransparentOn(banner);

        pictureBox1.Image = ShieldLarge.ToBitmap();

        showWaitPromptTimer = new System.Windows.Forms.Timer() { Interval = 4000 };
        showWaitPromptTimer.Tick += (s, e) =>
        {
            this.waitPrompt.Visible = true;
            this.pictureBox1.Visible = true;
            showWaitPromptTimer.Stop();
        };
    }

    private System.Windows.Forms.Timer showWaitPromptTimer;

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        if (!WindowsIdentity.GetCurrent().IsAdmin() && Uac.IsEnabled())
        {
            showWaitPromptTimer.Start();
        }

        base.OnLoad(sender, e);

        Shell.StartExecute();
    }

    /// <summary>
    /// Called when Shell is changed. It is a good place to initialize the dialog to reflect the MSI session
    /// (e.g. localize the view).
    /// </summary>
    protected override void OnShellChanged()
    {
        if (Runtime.Session.IsUninstalling())
        {
            dialogText.Text =
                Text = "[ProgressDlgTitleRemoving]";
            description.Text = "[ProgressDlgTextRemoving]";
        }
        else if (Runtime.Session.IsRepairing())
        {
            dialogText.Text =
                Text = "[ProgressDlgTextRepairing]";
            description.Text = "[ProgressDlgTitleRepairing]";
        }
        else if (Runtime.Session.IsInstalling())
        {
            dialogText.Text =
                Text = "[ProgressDlgTitleInstalling]";
            description.Text = "[ProgressDlgTextInstalling]";
        }

        this.Localize();
    }

    /// <summary>
    /// Processes the message.
    /// </summary>
    /// <param name="messageType">Type of the message.</param>
    /// <param name="messageRecord">The message record.</param>
    /// <param name="buttons">The buttons.</param>
    /// <param name="icon">The icon.</param>
    /// <param name="defaultButton">The default button.</param>
    /// <returns></returns>
    public override MessageResult ProcessMessage(InstallMessage messageType, Record messageRecord, MessageButtons buttons, MessageIcon icon, MessageDefaultButton defaultButton)
    {
        switch (messageType)
        {
            case InstallMessage.InstallStart:
            case InstallMessage.InstallEnd:
                {
                    showWaitPromptTimer.Stop();
                    waitPrompt.Visible = false;
                    pictureBox1.Visible = false;
                }
                break;

            case InstallMessage.ActionStart:
                {
                    try
                    {
                        //messageRecord[0] - is reserved for FormatString value

                        string message = null;

                        bool simple = true;
                        if (simple)
                        {
                            /*
                            messageRecord[2] unconditionally contains the string to display

                            Examples:

                               messageRecord[0]    "Action 23:14:50: [1]. [2]"
                               messageRecord[1]    "InstallFiles"
                               messageRecord[2]    "Copying new files"
                               messageRecord[3]    "File: [1],  Directory: [9],  Size: [6]"

                               messageRecord[0]    "Action 23:15:21: [1]. [2]"
                               messageRecord[1]    "RegisterUser"
                               messageRecord[2]    "Registering user"
                               messageRecord[3]    "[1]"

                            */
                            if (messageRecord.FieldCount >= 3)
                            {
                                message = messageRecord[2].ToString();
                            }
                        }
                        else
                        {
                            message = messageRecord.FormatString;
                            if (message.IsNotEmpty())
                            {
                                for (int i = 1; i < messageRecord.FieldCount; i++)
                                {
                                    message = message.Replace("[" + i + "]", messageRecord[i].ToString());
                                }
                            }
                            else
                            {
                                message = messageRecord[messageRecord.FieldCount - 1].ToString();
                            }
                        }

                        if (message.IsNotEmpty())
                            currentAction.Text = "{0} {1}".FormatWith(currentActionLabel.Text, message);
                    }
                    catch
                    {
                        //Catch all, we don't want the installer to crash in an
                        //attempt to process message.
                    }
                }
                break;
        }
        return MessageResult.OK;
    }

    /// <summary>
    /// Called when MSI execution progress is changed.
    /// </summary>
    /// <param name="progressPercentage">The progress percentage.</param>
    public override void OnProgress(int progressPercentage)
    {
        progress.Value = progressPercentage;

        if (progressPercentage > 0)
        {
            waitPrompt.Visible = false;
        }
    }

    /// <summary>
    /// Called when MSI execution is complete.
    /// </summary>
    public override void OnExecuteComplete()
    {
        currentAction.Text = null;
        Shell.GoNext();
    }

    protected override void Cancel_Click(object sender, EventArgs e)
    {
        if (Shell.IsDemoMode)
        {
            Shell.GoNext();
        }
        else
        {
            Shell.Cancel();
        }
    }
}
