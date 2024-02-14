using System;
using System.Net;
using DevolutionsGateway.Actions;
using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using WixSharp;

namespace WixSharpSetup.Dialogs
{
    public partial class AccessUriDialog : GatewayDialog
    {
        private static readonly string MachineName = Dns.GetHostEntry(Environment.MachineName).HostName;

        private static readonly string[] Protocols = { Constants.HttpProtocol, Constants.HttpsProtocol };

        public AccessUriDialog()
        {
            InitializeComponent();

            label1.MakeTransparentOn(banner);
            label2.MakeTransparentOn(banner);

            this.pictureBox1.Image =
                StockIcon.GetStockIcon(StockIcon.SIID_WARNING, StockIcon.SHGSI_SMALLICON).ToBitmap();

            this.cmbProtocol.DataSource = Protocols;
        }

        public override void FromProperties()
        {
            GatewayProperties properties = new(this.Runtime.Session);
            this.cmbProtocol.SelectedIndex = Protocols.FindIndex(properties.AccessUriScheme);
            this.txtHostname.Text = properties.AccessUriHost;
            this.txtPort.Text = properties.AccessUriPort.ToString();
            
            if (string.IsNullOrEmpty(properties.AccessUriHost))
            {
                this.txtHostname.Text = 
                    this.cmbProtocol.SelectedValue.ToString() == Constants.HttpsProtocol ? 
                    MachineName : "localhost";
            }
        }

        public override bool ToProperties()
        {
            GatewayProperties _ = new(this.Runtime.Session)
            {
                AccessUriScheme = this.cmbProtocol.SelectedValue.ToString(),
                AccessUriHost = this.txtHostname.Text.Trim(),
                AccessUriPort = Convert.ToUInt32(this.txtPort.Text.Trim())
            };

            return true;
        }

        public override bool DoValidate()
        {
            if (string.IsNullOrWhiteSpace(this.txtHostname.Text))
            {
                ShowValidationError(I18n(Strings.YouMustProvideAValidHostname));
                return false;
            }

            if (string.IsNullOrWhiteSpace(this.txtPort.Text) || !Validation.IsValidPort(this.txtPort.Text, out uint _))
            {
                ShowValidationError(I18n(Strings.YouMustEnterAValidPort));
                return false;
            }

            if (!Uri.TryCreate(
                    $"{this.cmbProtocol.SelectedValue}://{this.txtHostname.Text.Trim()}:{this.txtPort.Text.Trim()}",
                    UriKind.Absolute, out _))
            {
                ShowValidationError();
                return false;
            }

            return true;
        }

        public override void OnLoad(object sender, EventArgs e)
        {
            banner.Image = Runtime.Session.GetResourceBitmap("WixUI_Bmp_Banner");

            WinAPI.SendMessage(this.txtHostname.Handle, WinAPI.EM_SETCUEBANNER, 0, "dev.devolutions.net");

            this.SetControlStates();

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
            this.pictureBox1.Visible = this.lblHttpWarn.Visible =
                this.cmbProtocol.SelectedValue.ToString() == Constants.HttpProtocol;
        }

        private void cmbProtocol_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (this.cmbProtocol.SelectedValue.ToString() == Constants.HttpsProtocol)
            {
                if (this.txtHostname.Text.Trim() == "localhost")
                {
                    this.txtHostname.Text = MachineName;
                }

                if (this.txtPort.Text.Trim() == "80")
                {
                    this.txtPort.Text = "443";
                }
            }
            else if (this.cmbProtocol.SelectedValue.ToString() == Constants.HttpProtocol)
            {
                if (this.txtHostname.Text.Trim() == MachineName)
                {
                    this.txtHostname.Text = "localhost";
                }

                if (this.txtPort.Text.Trim() == "443")
                {
                    this.txtPort.Text = "80";
                }
            }

            this.SetControlStates();
        }
    }
}
