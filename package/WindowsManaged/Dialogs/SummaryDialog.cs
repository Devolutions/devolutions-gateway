using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
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
        private readonly MsiRuntime runtime;

        private readonly IWixProperty wixProperty;

        public override string Name => $"Property_{this.wixProperty.Name}";

        public override string Value(ISession session)
        {
            if (this.wixProperty.Hidden)
            {
                return string.Concat(Enumerable.Repeat("*", session[this.wixProperty.Id].Length));
            }

            if (this.wixProperty.PropertyType.IsEnum)
            {
                return $"[{this.wixProperty.PropertyType.Name}_{session[this.wixProperty.Id]}]".LocalizeWith(runtime.Localize);
            }
            
            return session[this.wixProperty.Id];
        }

        public InstallerProperty(MsiRuntime runtime, IWixProperty wixProperty)
        {
            this.runtime = runtime;
            this.wixProperty = wixProperty;
        }
    }

    private class MetaProperty : SummaryProperty
    {
        private readonly Func<ISession, string> fnValue;

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
        private readonly string value;

        public override string Name => throw new NotSupportedException();

        public override string Value(ISession session) => this.value;

        public StringProperty(MsiRuntime runtime, string value)
        {
            this.value = $"[{value}]".LocalizeWith(runtime.Localize);
        }
    }

    private static readonly Func<GatewayProperties, bool> Always = p => true;    

    private PropertyGroup[] Groups;
        
    private void Init() => this.Groups = new[]
    {
        new PropertyGroup()
        {
            Name = Strings.Group_InstallLocation,
            If = p => !p.ConfigureNgrok,
            Properties = new IProperty[]
            {
                new MetaProperty(Strings.Property_Directory, session => session[GatewayProperties.InstallDir])
            }
        },

        new PropertyGroup()
        {
            Name = Strings.Group_Service,
            If = Always,
            Properties = new IProperty[]
            {
                new InstallerProperty(this.MsiRuntime, GatewayProperties.serviceStart)
            }
        },

        new PropertyGroup()
        {
            Name = Strings.Group_Ngrok,
            If = p => p.ConfigureNgrok,
            Properties = new IProperty[]
            {
                new InstallerProperty(this.MsiRuntime, GatewayProperties.ngrokAuthToken),
                new InstallerProperty(this.MsiRuntime, GatewayProperties.ngrokHttpDomain),
                new InstallerProperty(this.MsiRuntime, GatewayProperties.ngrokEnableTcp),
                new InstallerProperty(this.MsiRuntime, GatewayProperties.ngrokRemoteAddress)
                {
                    If = p => p.NgrokEnableTcp
                },
            }
        },

        new PropertyGroup()
        {
            Name = Strings.Group_ExternalAccess,
            If = p => !p.ConfigureNgrok,
            Properties = new IProperty[]
            {
                new MetaProperty(Strings.Property_AccessUri, session => $"{session[GatewayProperties.accessUriScheme.Id]}://{session[GatewayProperties.accessUriHost.Id]}:{session[GatewayProperties.accessUriPort.Id]}")
            }
        },

        new PropertyGroup()
        {
            Name = Strings.Group_Listeners,
            If = p => !p.ConfigureNgrok,
            Properties = new IProperty[]
            {
                new MetaProperty(Strings.Property_HttpListener, session => $"{session[GatewayProperties.httpListenerScheme.Id]}://*:{session[GatewayProperties.httpListenerPort.Id]}"),
                new MetaProperty(Strings.Property_TcpListener, session => $"{session[GatewayProperties.tcpListenerScheme.Id]}://*:{session[GatewayProperties.tcpListenerPort.Id]}"),
            }
        },

        new PropertyGroup()
        {
            Name = Strings.Group_EncryptionKeys,
            If = Always,
            Properties = new IProperty[]
            {
                new StringProperty(this.MsiRuntime, Strings.Property_NewKeyPair)
                {
                    If = p => p.ConfigureWebApp && p.GenerateKeyPair
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.publicKeyFile)
                {
                    If = p => !p.GenerateKeyPair && string.IsNullOrEmpty(p.DevolutionsServerUrl)
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.privateKeyFile)
                {
                    If = p => p.ConfigureWebApp && !p.GenerateKeyPair
                },
                new StringProperty(this.MsiRuntime, Strings.ThePublicKeyWillBeDownloaded)
                {
                    If = p => !string.IsNullOrEmpty(p.DevolutionsServerUrl)
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.devolutionsServerUrl)
                {
                    If = p => !string.IsNullOrEmpty(p.DevolutionsServerUrl)
                },
            }
        },

        new PropertyGroup()
        {
            Name = Strings.Group_WebApp,
            If = p => p.ConfigureWebApp,
            Properties = new IProperty[]
            {
                new InstallerProperty(this.MsiRuntime, GatewayProperties.authenticationMode),
                new InstallerProperty(this.MsiRuntime, GatewayProperties.webUsername)
                {
                    If = p => p.AuthenticationMode == Constants.AuthenticationMode.Custom
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.webPassword)
                {
                    If = p => p.AuthenticationMode == Constants.AuthenticationMode.Custom
                },
            }
        },

        new PropertyGroup()
        {
            Name = Strings.Group_Certificate,
            If = p => !p.ConfigureNgrok && p.HttpListenerScheme == Constants.HttpsProtocol,
            Properties = new IProperty[]
            {
                new InstallerProperty(this.MsiRuntime, GatewayProperties.certificateMode)
                {
                    If = p => !p.GenerateCertificate
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.certificateFile)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.External
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.certificatePrivateKeyFile)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.External && !string.IsNullOrEmpty(p.CertificatePrivateKeyFile)
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.certificatePassword)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.External && !string.IsNullOrEmpty(p.CertificatePassword)
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.certificateLocation)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.System
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.certificateStore)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.System
                },
                new InstallerProperty(this.MsiRuntime, GatewayProperties.certificateName)
                {
                    If = p => !p.GenerateCertificate && p.CertificateMode == Constants.CertificateMode.System
                },
                new StringProperty(this.MsiRuntime, Strings.Property_NewCertificate)
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

        StringBuilder builder = new();
        builder.Append(@"{\rtf1\ansi");
        builder.Append(@" \line ");

        foreach (PropertyGroup group in Groups)
        {
            if (!group.If(properties))
            {
                continue;
            }

            builder.Append(@$" \ul {I18n($"{group.Name}")}\ul0");
            builder.Append(@" \line \line ");

            foreach (IProperty property in group.Properties)
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
                    builder.AppendLine(@$" \tab \b {I18n($"{property.Name}")} \b0 {RtfEscape(property.Value(Runtime.Session))}");
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

        this.Init();

        base.OnLoad(sender, e);
    }

    // ReSharper disable once RedundantOverriddenMember
    protected override void Back_Click(object sender, EventArgs e) => base.Back_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Next_Click(object sender, EventArgs e) => base.Next_Click(sender, e);

    // ReSharper disable once RedundantOverriddenMember
    protected override void Cancel_Click(object sender, EventArgs e) => base.Cancel_Click(sender, e);
}
