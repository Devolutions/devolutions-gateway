using System;

using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Helpers;
using DevolutionsGateway.Properties;

using WixSharp;

namespace WixSharpSetup.Dialogs
{
    public partial class AccessUriDialog : GatewayDialog
    {
        private static readonly string[] Protocols = { Constants.HttpProtocol, Constants.HttpsProtocol };

        public AccessUriDialog()
        {
            InitializeComponent();

            label1.MakeTransparentOn(banner);
            label2.MakeTransparentOn(banner);

            this.cmbProtocol.DataSource = Protocols;
        }

        public override void FromProperties()
        {
            GatewayProperties properties = new(this.Runtime.Session);
            this.cmbProtocol.SelectedIndex = Protocols.FindIndex(properties.AccessUriScheme);
            this.txtHostname.Text = properties.AccessUriHost;
            this.txtPort.Text = properties.AccessUriPort.ToString();

            if (properties.ConfigureWebApp && properties.GenerateCertificate &&
                string.IsNullOrEmpty(properties.AccessUriHost))
            {
                this.txtHostname.Text = Environment.MachineName;
            }
        }

        public override bool ToProperties()
        {
            GatewayProperties properties = new(this.Runtime.Session)
            {
                AccessUriScheme = this.cmbProtocol.SelectedValue.ToString(),
                AccessUriHost = this.txtHostname.Text.Trim(),
                AccessUriPort = Convert.ToUInt32(this.txtPort.Text.Trim())
            };

            if (properties.AccessUriScheme == Constants.HttpProtocol)
            {
                properties.HttpListenerScheme = Constants.HttpProtocol;
            }

            return true;
        }

        public override bool DoValidate()
        {
            if (string.IsNullOrWhiteSpace(this.txtHostname.Text))
            {
                ShowValidationError("Error30000");
                return false;
            }

            if (string.IsNullOrWhiteSpace(this.txtPort.Text) || !Validation.IsValidPort(this.txtPort.Text, out uint _))
            {
                ShowValidationError("Error29999");
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

            base.OnLoad(sender, e);
        }

        // ReSharper disable once RedundantOverriddenMember
        protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

        // ReSharper disable once RedundantOverriddenMember
        protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

        // ReSharper disable once RedundantOverriddenMember
        protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);
    }
}
