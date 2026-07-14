using DevolutionsAgent.Actions;
using DevolutionsAgent.Dialogs;
using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;

using System;
using System.Windows.Forms;

using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class PsuDialog : AgentDialog
{
    public PsuDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);
    }

    public override bool ToProperties()
    {
        _ = new AgentProperties(Runtime.Session)
        {
            PsuServerUrl = serverUrl.Text.Trim(),
            PsuAppToken = appToken.Text.Trim(),
            PsuAppTokenIsSecretReference = secretNameRadio.Checked,
            PsuAgentId = agentId.Text.Trim(),
            PsuDisplayName = displayName.Text.Trim(),
        };

        return true;
    }

    public override void FromProperties()
    {
        AgentProperties properties = new(Runtime.Session);

        serverUrl.Text = properties.PsuServerUrl;
        appToken.Text = properties.PsuAppToken;
        agentId.Text = properties.PsuAgentId;
        displayName.Text = properties.PsuDisplayName;

        bool isSecretReference = properties.PsuAppTokenIsSecretReference;
        secretNameRadio.Checked = isSecretReference;
        tokenValueRadio.Checked = !isSecretReference;

        UpdateAppTokenMask();
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        // A verbatim token is a credential and must stay masked; a secret *name* is not sensitive,
        // so unmask the field when "Secret name" is selected to make it easier to type/verify.
        secretNameRadio.CheckedChanged += (_, _) => UpdateAppTokenMask();

        // base.OnLoad calls FromProperties, restoring the dialog state (including the token mask)
        // when the user navigates back to this dialog.
        base.OnLoad(sender, e);
    }

    private void UpdateAppTokenMask()
    {
        appToken.UseSystemPasswordChar = !secretNameRadio.Checked;
    }

    public override bool DoValidate()
    {
        // The dialog is only reached when the PSU feature is selected (see Wizard.ShouldSkip),
        // so a server URL and an app token are both required here to produce a config the agent
        // can start with. The app token accepts either a verbatim value or a secret name; both
        // are non-empty strings, so we only check the token for presence and defer secret
        // resolution to the agent at runtime. The server URL is additionally validated for shape
        // and probed for reachability.
        if (string.IsNullOrWhiteSpace(serverUrl.Text))
        {
            ShowValidationErrorString(this.I18n(Strings.PsuDlgServerUrlRequired));
            return false;
        }

        string serverUrlText = serverUrl.Text.Trim();

        // Validate the URL shape here so the agent doesn't fail to parse it as a url::Url on its
        // first start after installation. The same check runs in the ConfigurePsuAgent custom action
        // for the silent-install path.
        if (!CustomActions.IsValidPsuServerUrl(serverUrlText))
        {
            ShowValidationErrorString(this.I18n(Strings.PsuDlgServerUrlInvalid));
            return false;
        }

        if (string.IsNullOrWhiteSpace(appToken.Text))
        {
            ShowValidationErrorString(this.I18n(Strings.PsuDlgAppTokenRequired));
            return false;
        }

        // Best-effort reachability probe for early diagnostics. A failure does not block installation
        // (the PowerShell Universal server may simply not be running yet), but warning here surfaces a
        // typo or wrong port before the configuration is committed.
        if (!CustomActions.TryReachPsuServer(serverUrlText, 3000, out string reachError))
        {
            if (MessageBox.Show(
                    string.Format(this.I18n(Strings.PsuDlgServerUnreachable), reachError),
                    this.Localize("[AgentDlg_Title]"),
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning) != DialogResult.Yes)
            {
                return false;
            }
        }

        return true;
    }

    // WixSharp's ManagedForm wires Back/Next/Cancel button clicks via reflection on the
    // *concrete* dialog type rather than the base class, so each leaf dialog must surface
    // these three overrides even when they only delegate to base. The ReSharper hint
    // suppresses the noise flag.

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);
}
