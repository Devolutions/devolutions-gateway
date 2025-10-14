using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;

using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Windows.Forms;
using DevolutionsGateway.Resources;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class ListenersDialog : GatewayDialog
{
    private static readonly string[] HttpProtocols = { Constants.HttpProtocol, Constants.HttpsProtocol };

    private static readonly string[] TcpProtocols = { Constants.TcpProtocol };

    private readonly Debouncer httpPortDebouncer;

    private readonly Debouncer tcpPortDebouncer;

    private readonly ErrorProvider errorProvider = new ErrorProvider();

    public ListenersDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        httpPortDebouncer = new Debouncer(TimeSpan.FromMilliseconds(500), PortCheck, this.txtHttpPort, SynchronizationContext.Current);
        tcpPortDebouncer = new Debouncer(TimeSpan.FromMilliseconds(500), PortCheck, this.txtTcpPort, SynchronizationContext.Current);

        this.errorProvider.BlinkStyle = ErrorBlinkStyle.NeverBlink;
        this.errorProvider.SetIconAlignment(this.txtHttpPort, ErrorIconAlignment.MiddleLeft);
        this.errorProvider.SetIconPadding(this.txtHttpPort, 6);
        this.errorProvider.SetIconAlignment(this.txtTcpPort, ErrorIconAlignment.MiddleLeft);
        this.errorProvider.SetIconPadding(this.txtTcpPort, 6);
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

        this.cmbHttpProtocol.DataSource = HttpProtocols;
        this.cmbTcpProtocol.DataSource = TcpProtocols;
        
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
        
        string portString = textBox.Text;

        if (string.IsNullOrEmpty(portString) || !Validation.IsValidPort(portString, out uint port))
        {
            errorProvider.SetError(textBox, I18n(Strings.InvalidPort));

        }
        else
        {
            TcpListener listener = null;

            try
            {
                listener = new TcpListener(Dns.GetHostEntry("localhost").AddressList.First(), (int)port);
                listener.Start();

                errorProvider.SetError(textBox, string.Empty);
            }
            catch (SocketException se)
            {
                errorProvider.SetError(textBox,
                    se.SocketErrorCode is SocketError.AddressAlreadyInUse or SocketError.AccessDenied
                        ? I18n(Strings.ChosenPortNotAvailable)
                        : I18n(Strings.ChosenPortCouldNotBeChecked));
            }
            catch
            {
                errorProvider.SetError(textBox, I18n(Strings.ChosenPortCouldNotBeChecked));
            }
            finally
            {
                listener?.Stop();
            }
        }
    }
}
