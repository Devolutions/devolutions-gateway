using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;

using System;

using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class ListenersDialog : GatewayDialog
{
    private static readonly string[] HttpProtocols = { Constants.HttpProtocol, Constants.HttpsProtocol };

    private static readonly string[] TcpProtocols = { Constants.TcpProtocol };

    public ListenersDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        this.cmbHttpProtocol.DataSource = HttpProtocols;
        this.cmbTcpProtocol.DataSource = TcpProtocols;
    }

    public override bool DoValidate()
    {
        if (string.IsNullOrWhiteSpace(this.txtHttpPort.Text) || !Validation.IsValidPort(this.txtHttpPort.Text, out _))
        {
            ShowValidationError("Error29999");
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.txtTcpPort.Text) || !Validation.IsValidPort(this.txtTcpPort.Text, out _))
        {
            ShowValidationError("Error29999");
            return false;
        }

        return true;
    }

    public override void FromProperties()
    {
        GatewayProperties properties = new(Runtime.Session);

        this.cmbHttpProtocol.SelectedIndex = HttpProtocols.FindIndex(properties.HttpListenerScheme);
        this.txtHttpHostname.Text = properties.HttpListenerHost;
        this.txtHttpPort.Text = properties.HttpListenerPort.ToString();

        // If the Access URI is http, so must the HTTP listener
        this.cmbHttpProtocol.Enabled = properties.AccessUriScheme != Constants.HttpProtocol;

        this.cmbTcpProtocol.SelectedIndex = TcpProtocols.FindIndex(properties.TcpListenerScheme);
        this.txtTcpHostname.Text = properties.TcpListenerHost;
        this.txtTcpPort.Text = properties.TcpListenerPort.ToString();
    }

    public override bool ToProperties()
    {
        GatewayProperties properties = new(Runtime.Session)
        {
            HttpListenerScheme = this.cmbHttpProtocol.SelectedValue.ToString(),
            HttpListenerHost = this.txtHttpHostname.Text.Trim(),
            HttpListenerPort = Convert.ToUInt32(this.txtHttpPort.Text.Trim()),
            TcpListenerScheme = this.cmbTcpProtocol.SelectedValue.ToString(),
            TcpListenerHost = this.txtTcpHostname.Text.Trim(),
            TcpListenerPort = Convert.ToUInt32(this.txtTcpPort.Text.Trim())
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
}
