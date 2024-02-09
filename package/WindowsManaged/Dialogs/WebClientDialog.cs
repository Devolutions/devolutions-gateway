using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using System;
using DevolutionsGateway.Resources;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class WebClientDialog : GatewayDialog
{
    private bool CustomAuth => this.cmbAuthentication.SelectedIndex == (int)Constants.AuthenticationMode.Custom;

    public WebClientDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        this.cmbAuthentication.DataSource = Enum.GetValues(typeof(Constants.AuthenticationMode));
        this.cmbAuthentication.SelectedIndex = 0;
    }

    public override bool DoValidate()
    {
        if (!this.CustomAuth)
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(this.txtUsername.Text))
        {
            ShowValidationError(I18n(Strings.YouMustEnterAUsername));
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.txtPassword.Text))
        {
            ShowValidationError(I18n(Strings.YouMustEnterAPassword));
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.txtPassword2.Text))
        {
            ShowValidationError(I18n(Strings.YouMustConfirmThePassword));
            return false;
        }

        if (!string.Equals(this.txtPassword.Text, this.txtPassword2.Text))
        {
            ShowValidationError(I18n(Strings.PasswordsDoNotMatch));
            return false;
        }

        return true;
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);
        this.cmbAuthentication.SelectedIndex = (int) properties.AuthenticationMode;
        this.txtUsername.Text = properties.WebUsername;
        this.txtPassword.Text = properties.WebPassword;
        this.txtPassword2.Text = properties.WebPassword;

        this.SetControlStates();
    }

    public override bool ToProperties()
    {
        GatewayProperties _ = new(this.Runtime.Session)
        {
            AuthenticationMode = (Constants.AuthenticationMode)this.cmbAuthentication.SelectedIndex,
            WebUsername = this.txtUsername.Text,
            WebPassword = this.txtPassword.Text
        };

        return true;
    }

    public override void OnLoad(object sender, EventArgs e)
    {
        banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

        base.OnLoad(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);

    private void SetControlStates()
    {
        this.gbUser.Visible = this.CustomAuth;
    }

    private void cmbAuthentication_SelectedIndexChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }
}
