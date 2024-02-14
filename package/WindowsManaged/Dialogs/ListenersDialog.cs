using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;

using System;
using System.Drawing;
using System.Net;
using System.Net.Sockets;
using System.Windows.Forms;
using DevolutionsGateway.Resources;
using WixSharp;
using Action = System.Action;

namespace WixSharpSetup.Dialogs;

public partial class ListenersDialog : GatewayDialog
{
    private static readonly string[] HttpProtocols = { Constants.HttpProtocol, Constants.HttpsProtocol };

    private static readonly string[] TcpProtocols = { Constants.TcpProtocol };

    private readonly Debouncer httpPortDebouncer;

    private readonly Debouncer tcpPortDebouncer;

    public ListenersDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        httpPortDebouncer = new Debouncer(TimeSpan.FromMilliseconds(500), PortCheck, this.txtHttpPort);
        tcpPortDebouncer = new Debouncer(TimeSpan.FromMilliseconds(500), PortCheck, this.txtTcpPort);

        this.cmbHttpProtocol.DataSource = HttpProtocols;
        this.cmbTcpProtocol.DataSource = TcpProtocols;
    }

    public override bool DoValidate()
    {
        if (string.IsNullOrWhiteSpace(this.txtHttpPort.Text) || !Validation.IsValidPort(this.txtHttpPort.Text, out _))
        {
            ShowValidationError(I18n(Strings.YouMustEnterAValidPort));
            return false;
        }

        if (string.IsNullOrWhiteSpace(this.txtTcpPort.Text) || !Validation.IsValidPort(this.txtTcpPort.Text, out _))
        {
            ShowValidationError(I18n(Strings.YouMustEnterAValidPort));
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
        
        this.cmbTcpProtocol.SelectedIndex = TcpProtocols.FindIndex(properties.TcpListenerScheme);
        this.txtTcpHostname.Text = properties.TcpListenerHost;
        this.txtTcpPort.Text = properties.TcpListenerPort.ToString();

        this.SetControlStates();
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

        // If the user hasn't customized the Access URI port, let's make it match
        // the HTTP listener
        if (properties.AccessUriPort == GatewayProperties.accessUriPort.Default)
        {
            properties.AccessUriPort = properties.HttpListenerPort;
        }

        // Generally they should match, so let's change that for the user
        // They can adjust this on the Access URI page if needed
        properties.AccessUriScheme = properties.HttpListenerScheme;

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

    private void cmbHttpProtocol_SelectedIndexChanged(object sender, EventArgs e)
    {
        this.SetControlStates();
    }

    private void SetControlStates()
    {
        GatewayProperties properties = new(Runtime.Session);

        if (this.cmbHttpProtocol.SelectedValue.ToString() == Constants.HttpProtocol)
        {
            this.lblHttpsDescription.Text = I18n(Strings.AnHttpListenerDoesNotRequireACert);
        }
        else if (properties.GenerateCertificate && properties.ConfigureWebApp)
        {
            this.lblHttpsDescription.Text = I18n(Strings.AnHttpsListenerRequiresACertSelfSigned);
        }
        else
        {
            this.lblHttpsDescription.Text = I18n(Strings.AnHttpsListenerRequiresACert);
        }
    }

    private void txtHttpPort_TextChanged(object sender, EventArgs e)
    {
        this.httpPortDebouncer.Invoke();
    }

    private void txtTcpPort_TextChanged(object sender, EventArgs e)
    {
        this.tcpPortDebouncer.Invoke();
    }

    private void PortCheck(object sender)
    {
        TextBox textBox = (TextBox)sender;

        if (textBox is null)
        {
            return;
        }
        
        Action result = () => {};

        string portString = this.Invoke(new Func<string>(() => textBox.Text)).ToString();

        if (string.IsNullOrEmpty(portString) || !Validation.IsValidPort(portString, out uint port))
        {
            result = () =>
            {
                this.ttPortCheck?.SetToolTip(textBox, I18n(Strings.InvalidPort));
                textBox.ForeColor = SystemColors.WindowText;
            };
        }
        else
        {
            TcpListener listener = null;

            try
            {
                listener = new TcpListener(IPAddress.Any, (int) port);
                listener.Start();

                result = () =>
                {
                    this.ttPortCheck?.SetToolTip(textBox, I18n(Strings.ChosenPortAvailable));
                    textBox.ForeColor = Color.Green;
                };
            }
            catch (SocketException se)
            {
                if (se.SocketErrorCode != SocketError.AddressAlreadyInUse)
                {
                    throw;
                }

                result = () =>
                {
                    this.ttPortCheck?.SetToolTip(textBox, I18n(Strings.ChosenPortNotAvailable));
                    textBox.ForeColor = Color.Red;
                };
            }
            catch
            {
                result = () =>
                {
                    this.ttPortCheck?.SetToolTip(textBox, I18n(Strings.ChosenPortCouldNotBeChecked));
                    textBox.ForeColor = SystemColors.WindowText;
                };
            }
            finally
            {
                listener?.Stop();
            }
        }
        
        this.Invoke(() =>
        {
            try
            { 
                result();
            }
            catch
            {
            }
        });
    }
}
