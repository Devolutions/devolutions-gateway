using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using System;
using System.Linq;
using System.Text;
using WixSharp;

namespace WixSharpSetup.Dialogs;

public partial class SummaryDialog : GatewayDialog
{
    public SummaryDialog()
    {
        InitializeComponent();
        label1.MakeTransparentOn(banner);
        label2.MakeTransparentOn(banner);

        this.rchSummaryText.SelectionIndent = 10;
    }

    private class PropertyGroup
    {
        public string Name { get; set; }

        public Func<GatewayProperties, bool> If { get; set; } = Always;

        public IProperty[] Properties { get; set; }
    }

    private interface IProperty
    {
        Func<GatewayProperties, bool> If { get; }

        string Name { get; }

        string Value (ISession session);
    }

    private abstract class SummaryProperty : IProperty
    {
        public virtual Func<GatewayProperties, bool> If { get; set; } = Always;

        public abstract string Name { get; }

        public abstract string Value(ISession session);
    }

    private class InstallerProperty : SummaryProperty
    {
        private IWixProperty wixProperty;

        public override string Name => this.wixProperty.Summary;

        public override string Value(ISession session) => wixProperty.Hidden ? string.Concat(Enumerable.Repeat("*", session[this.wixProperty.Id].Length)) : session[this.wixProperty.Id];

        public InstallerProperty(IWixProperty wixProperty)
        {
            this.wixProperty = wixProperty;
        }
    }

    private class MetaProperty : SummaryProperty
    {
        private Func<ISession, string> fnValue;

        public override string Name { get; }

        public override string Value(ISession session) => this.fnValue(session);

        public MetaProperty(string name, Func<ISession, string> fnValue)
        {
            this.Name = name;
            this.fnValue = fnValue;
        }
    }

    private class StringProperty : SummaryProperty
    {
        private string value;

        public override string Name => throw new NotSupportedException();

        public override string Value(ISession session) => this.value;

        public StringProperty(string value)
        {
            this.value = value;
        }
    }

    private static Func<GatewayProperties, bool> Always = p => true;    

    private PropertyGroup[] Groups = new[]
    {
        new PropertyGroup()
        {
            Name = "Install Location",
            If = p => !p.ConfigureNgrok,
            Properties = new IProperty[]
            {
                new MetaProperty("Directory", session => session[GatewayProperties.InstallDir])
            }
        },

        new PropertyGroup()
        {
            Name = "Service",
            If = Always,
            Properties = new IProperty[]
            {
                new InstallerProperty(GatewayProperties.serviceStart)
            }
        },

        new PropertyGroup()
        {
            Name = "ngrok",
            If = p => p.ConfigureNgrok,
            Properties = new IProperty[]
            {
                new InstallerProperty(GatewayProperties.ngrokAuthToken),
                new InstallerProperty(GatewayProperties.ngrokHttpDomain),
                new InstallerProperty(GatewayProperties.ngrokEnableTcp),
                new InstallerProperty(GatewayProperties.ngrokRemoteAddress)
                {
                    If = p => p.NgrokEnableTcp
                },
            }
        },

        new PropertyGroup()
        {
            Name = "External Access",
            If = p => !p.ConfigureNgrok,
            Properties = new IProperty[]
            {
                new MetaProperty("Access URI", session => $"{session[GatewayProperties.accessUriScheme.Id]}://{session[GatewayProperties.accessUriHost.Id]}:{session[GatewayProperties.accessUriPort.Id]}")
            }
        },

        new PropertyGroup()
        {
            Name = "Listeners",
            If = p => !p.ConfigureNgrok,
            Properties = new IProperty[]
            {
                new MetaProperty("HTTP Listener", session => $"{session[GatewayProperties.httpListenerScheme.Id]}://*:{session[GatewayProperties.httpListenerPort.Id]}"),
                new MetaProperty("TCP Listener", session => $"{session[GatewayProperties.tcpListenerScheme.Id]}://*:{session[GatewayProperties.tcpListenerPort.Id]}"),
            }
        },

        new PropertyGroup()
        {
            Name = "Encryption Keys",
            If = Always,
            Properties = new IProperty[]
            {
                new StringProperty("A new key pair will be generated")
                {
                    If = p => p.ConfigureWebApp && p.GenerateKeyPair
                },
                new InstallerProperty(GatewayProperties.publicKeyFile)
                {
                    If = p => !p.GenerateKeyPair
                },
                new InstallerProperty(GatewayProperties.privateKeyFile)
                {
                    If = p => p.ConfigureWebApp && !p.GenerateKeyPair
                },
            }
        },

        new PropertyGroup()
        {
            Name = "Web App",
            If = p => p.ConfigureWebApp,
            Properties = new IProperty[]
            {
                new InstallerProperty(GatewayProperties.authenticationMode),
                new InstallerProperty(GatewayProperties.webUsername)
                {
                    If = p => p.AuthenticationMode == Constants.AuthenticationMode.Custom
                },
                new InstallerProperty(GatewayProperties.webPassword)
                {
                    If = p => p.AuthenticationMode == Constants.AuthenticationMode.Custom
                },
            }
        },

        new PropertyGroup()
        {
            Name = "Certificate",
            If = p => !p.ConfigureNgrok && p.HttpListenerScheme == Constants.HttpsProtocol,
            Properties = new IProperty[]
            {
                new InstallerProperty(GatewayProperties.certificateMode)
                {
                    If = p => !p.GenerateCertificate
                },
                new InstallerProperty(GatewayProperties.certificateFile)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.External
                },
                new InstallerProperty(GatewayProperties.certificatePrivateKeyFile)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.External && !string.IsNullOrEmpty(p.CertificatePrivateKeyFile)
                },
                new InstallerProperty(GatewayProperties.certificatePassword)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.External && !string.IsNullOrEmpty(p.CertificatePassword)
                },
                new InstallerProperty(GatewayProperties.certificateLocation)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.System
                },
                new InstallerProperty(GatewayProperties.certificateStore)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.System
                },
                new InstallerProperty(GatewayProperties.certificateName)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.System
                },
                new StringProperty("A new self-signed certificate will be generated")
                {
                    If = p => p.GenerateCertificate
                }
            }
        }
    };

    private string RtfEscape(string s) => s.Replace(@"\", @"\\");

    public override void FromProperties()
    {
        GatewayProperties properties = new(this.Runtime.Session);

        StringBuilder builder = new StringBuilder();
        builder.Append(@"{\rtf1\ansi");
        builder.Append(@" \line ");

        foreach (PropertyGroup group in Groups)
        {
            if (!group.If(properties))
            {
                continue;
            }

            builder.Append(@$" \ul {group.Name}\ul0");
            builder.Append(@" \line \line ");

            foreach (var property in group.Properties)
            {
                if (!property.If(properties))
                {
                    continue;
                }

                if (property is StringProperty)
                {
                    builder.AppendLine(@$" \tab {property.Value(Runtime.Session)}");
                }
                else
                {
                    builder.AppendLine(@$" \tab \b {property.Name}: \b0 {RtfEscape(property.Value(Runtime.Session))}");
                }
                builder.Append(@" \line ");
            }

            builder.Append(@" \line ");
        }

        builder.Append(@" }");
        
        this.rchSummaryText.Rtf = builder.ToString();
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
