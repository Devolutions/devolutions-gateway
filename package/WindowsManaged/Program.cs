using DevolutionsGateway.Actions;
using DevolutionsGateway.Dialogs;
using DevolutionsGateway.Properties;
using DevolutionsGateway.Resources;
using Microsoft.Deployment.WindowsInstaller;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using System.Xml;
using Newtonsoft.Json;
using WixSharp;
using WixSharp.CommonTasks;
using WixSharpSetup.Dialogs;
using Assembly = System.Reflection.Assembly;
using CompressionLevel = WixSharp.CompressionLevel;
using File = WixSharp.File;

namespace DevolutionsGateway;

internal class Program
{
    private const string PackageName = "DevolutionsGateway";

    private static string DevolutionsGatewayExePath
    {
        get
        {
            string path = Environment.GetEnvironmentVariable("DGATEWAY_EXECUTABLE");

            if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path))
            {
#if DEBUG
                path = "..\\..\\target\\x86_64-pc-windows-msvc\\release\\devolutionsgateway.exe";
#else
                throw new Exception("The environment variable DGATEWAY_EXECUTABLE is not specified or the file does not exist");
#endif
            }

            if (!System.IO.File.Exists(path))
            {
                throw new FileNotFoundException("The gateway executable was not found", path);
            }

            return path;
        }
    }

    private static string DevolutionsGatewayPsModulePath
    {
        get
        {
            string path = Environment.GetEnvironmentVariable("DGATEWAY_PSMODULE_PATH");

            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
#if DEBUG
                path = "..\\..\\powershell\\DevolutionsGateway";
#else
                throw new Exception("The environment variable DGATEWAY_PSMODULE_PATH is not specified or the directory does not exist");
#endif
            }

            if (!Directory.Exists(path))
            {
                throw new DirectoryNotFoundException("The powershell module was not found");
            }

            return path;
        }
    }

    private static string DevolutionsWebClientPath
    {
        get
        {
            string path = Environment.GetEnvironmentVariable("DGATEWAY_WEBCLIENT_PATH");

            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
#if DEBUG
                path = "..\\..\\webapp\\dist\\gateway-ui";
#else
                throw new Exception("The environment variable DGATEWAY_WEBCLIENT_PATH is not specified or the directory does not exist");
#endif
            }

            if (!Directory.Exists(path))
            {
                throw new DirectoryNotFoundException("The web client was not found");
            }

            return path;
        }
    }

    private static string DevolutionsWebPlayerPath
    {
        get
        {
            string path = Environment.GetEnvironmentVariable("DGATEWAY_WEBPLAYER_PATH");

            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
#if DEBUG
                path = "..\\..\\webapp\\dist\\recording-player";
#else
                throw new Exception("The environment variable DGATEWAY_WEBPLAYER_PATH is not specified or the directory does not exist");
#endif
            }

            if (!Directory.Exists(path))
            {
                throw new DirectoryNotFoundException("The web player was not found");
            }

            return path;
        }
    }

    private static string LibXmfPath
    {
        get
        {
            string path = Environment.GetEnvironmentVariable("DGATEWAY_LIB_XMF_PATH");

            if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path))
            {
#if DEBUG
                path = "..\\..\\native-libs\\xmf.dll";
#else
                throw new Exception("The environment variable DGATEWAY_LIB_XMF_PATH is not specified or the file does not exist");
#endif
            }

            if (!System.IO.File.Exists(path))
            {
                throw new FileNotFoundException("The XMF native library was not found");
            }

            return path;
        }
    }

    private static Version DevolutionsGatewayVersion
    {
        get
        {
            string versionString = Environment.GetEnvironmentVariable("DGATEWAY_VERSION");

            if (string.IsNullOrEmpty(versionString) || !Version.TryParse(versionString, out Version version))
            {
#if DEBUG
                versionString = FileVersionInfo.GetVersionInfo(DevolutionsGatewayExePath).FileVersion;

                if (versionString.StartsWith("20"))
                {
                    versionString = versionString.Substring(2);
                }

                version = Version.Parse(versionString);
#else
                throw new Exception("The environment variable DGATEWAY_VERSION is not specified or is invalid");
#endif
            }

            return version;
        }
    }

    private static bool SourceOnlyBuild => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("DGATEWAY_MSI_SOURCE_ONLY_BUILD"));

    private static string ProjectLangId
    {
        get
        {
            string langId = Environment.GetEnvironmentVariable("DGATEWAY_MSI_LANG_ID");

            if (string.IsNullOrWhiteSpace(langId))
            {
                return "en-US";
            }

            // ReSharper disable once SimplifyLinqExpressionUseAll
            if (!Languages.Any(x => x.Key == langId))
            {
                throw new Exception($"unrecognized language id: {langId}");
            }

            return langId;
        }
    }

    private static readonly Dictionary<string, string> Languages = new()
    {
        { "en-US", "DevolutionsGateway_en-us.wxl" },
        { "fr-FR", "DevolutionsGateway_fr-fr.wxl" },
    };

    private static KeyValuePair<string, string> enUS => Languages.First(x => x.Key == "en-US");

    private static KeyValuePair<string, string> frFR => Languages.First(x => x.Key == "fr-FR");

    static void Main()
    {
        ManagedProject project = new(Includes.PRODUCT_NAME)
        {
            UpgradeCode = Includes.UPGRADE_CODE,
            Version = DevolutionsGatewayVersion,
            Description = "!(loc.ProductDescription)",
            InstallerVersion = 500, // Windows Installer 5.0; Server 2008 R2 / Windows 7
            InstallScope = InstallScope.perMachine,
            InstallPrivileges = InstallPrivileges.elevated,
            Platform = Platform.x64,
#if DEBUG
            PreserveTempFiles = true,
            OutDir = "Debug",
#else
            OutDir = "Release",
#endif
            BannerImage = "Resources/WixUIBanner.jpg",
            BackgroundImage = "Resources/WixUIDialog.jpg",
            ValidateBackgroundImage = false,
            OutFileName = PackageName,
            MajorUpgrade = new MajorUpgrade
            {
                AllowDowngrades = false,
                AllowSameVersionUpgrades = true,
                DowngradeErrorMessage = "!(loc.NewerInstalled)",
                Schedule = UpgradeSchedule.afterInstallInitialize,
            },
            Media = new List<Media>
            {
                new()
                {
                    Cabinet = "dgateway.cab",
                    EmbedCab = true,
                    CompressionLevel = CompressionLevel.mszip,
                }
            },
            ControlPanelInfo = new ProductInfo
            {
                Manufacturer = Includes.VENDOR_NAME,
                NoModify = true,
                ProductIcon = "Resources/DevolutionsGateway.ico",
                UrlInfoAbout = Includes.INFO_URL,
            }
        };

        if (CryptoConfig.AllowOnlyFipsAlgorithms)
        {
            project.CandleOptions = "-fips";
        }

        project.Dirs = new Dir[]
        {
            new ("%ProgramFiles%", new Dir(Includes.VENDOR_NAME, new InstallDir(Includes.SHORT_NAME)
            {
                Files = new File[]
                {
                    new (DevolutionsGatewayExePath)
                    {
                        TargetFileName = Includes.EXECUTABLE_NAME,
                        FirewallExceptions = new FirewallException[]
                        {
                            new()
                            {
                                Name = Includes.SERVICE_DISPLAY_NAME,
                                Description = $"{Includes.SERVICE_DISPLAY_NAME} TCP",
                                Protocol = FirewallExceptionProtocol.tcp,
                                Profile = FirewallExceptionProfile.all,
                                Scope = FirewallExceptionScope.any,
                                IgnoreFailure = false
                            },
                            new()
                            {
                                Name = Includes.SERVICE_DISPLAY_NAME,
                                Description = $"{Includes.SERVICE_DISPLAY_NAME} UDP",
                                Protocol = FirewallExceptionProtocol.udp,
                                Profile = FirewallExceptionProfile.all,
                                Scope = FirewallExceptionScope.any,
                                IgnoreFailure = false
                            },
                        },
                        ServiceInstaller = new ServiceInstaller()
                        {
                            Type = SvcType.ownProcess,
                            Account = "NT AUTHORITY\\NetworkService",
                            Interactive = false,
                            Vital = true,
                            Name = Includes.SERVICE_NAME,
                            Arguments = "--service",
                            DisplayName = Includes.SERVICE_DISPLAY_NAME,
                            Description = Includes.SERVICE_DISPLAY_NAME,
                            FirstFailureActionType = FailureActionType.restart,
                            SecondFailureActionType = FailureActionType.restart,
                            ThirdFailureActionType = FailureActionType.restart,
                            RestartServiceDelayInSeconds = 900,
                            ResetPeriodInDays = 1,
                            RemoveOn = SvcEvent.Uninstall,
                            StopOn = SvcEvent.InstallUninstall,
                        },
                    },
                    new (LibXmfPath)
                    {
                        TargetFileName = "xmf.dll",
                    }
                },
                Dirs = new Dir[]
                {
                    new ("PowerShell", new Dir("Modules", new Dir("DevolutionsGateway")
                    {
                        Dirs = new Dir[]
                        {
                            new("bin", new Files($@"{DevolutionsGatewayPsModulePath}\bin\*.*", (path) => 
                                    (path.EndsWith(".dll") || path.EndsWith(".pdb") || path.EndsWith(".json")) &&
                                    !(path.Contains("-arm64") || path.Contains("linux-") || path.Contains("osx-")))),
                            new("Private", new Files($@"{DevolutionsGatewayPsModulePath}\Private\*.*")),
                            new("Public", new Files($@"{DevolutionsGatewayPsModulePath}\Public\*.*")),
                        },
                        Files = new File[]
                        {
                            new($@"{DevolutionsGatewayPsModulePath}\DevolutionsGateway.psm1"),
                            new($@"{DevolutionsGatewayPsModulePath}\DevolutionsGateway.psd1"),
                        }
                    })),
                    new ("webapp")
                    {
                        Dirs = new Dir[]
                        {
                            new("client", new Files($@"{DevolutionsWebClientPath}\*.*")),
                            new("player", new Files($@"{DevolutionsWebPlayerPath}\*.*")),
                        }
                    }
                }
            })),
        };
        project.ResolveWildCards(true);

        project.DefaultRefAssemblies.Add(typeof(ZipArchive).Assembly.Location);
        project.DefaultRefAssemblies.Add(typeof(JsonSerializer).Assembly.Location);
        project.Actions = GatewayActions.Actions;
        project.RegValues = new RegValue[]
        {
            new (RegistryHive.LocalMachine, $"Software\\{Includes.VENDOR_NAME}\\{Includes.SHORT_NAME}", "InstallDir", $"[{GatewayProperties.InstallDir}]")
            {
                AttributesDefinition = "Type=string; Component:Permanent=yes",
                Win64 = project.Platform == Platform.x64,
                RegistryKeyAction = RegistryKeyAction.create,
            },
            new (RegistryHive.LocalMachine, $"SYSTEM\\CurrentControlSet\\Services\\EventLog\\Application\\{Includes.PRODUCT_NAME}", "EventMessageFile", $"[{GatewayProperties.InstallDir}]{Includes.EXECUTABLE_NAME}")
            {
                AttributesDefinition = "Type=string",
                Win64 = project.Platform == Platform.x64,
                RegistryKeyAction = RegistryKeyAction.createAndRemoveOnUninstall,
            }
        };
        project.Properties = GatewayProperties.Properties.Select(x => x.ToWixSharpProperty()).ToArray();
        project.ManagedUI = new ManagedUI();
        project.ManagedUI.InstallDialogs.AddRange(Wizard.Dialogs);
        project.ManagedUI.InstallDialogs
            .Add<ProgressDialog>()
            .Add<ExitDialog>();
        project.ManagedUI.ModifyDialogs
            .Add<MaintenanceTypeDialog>()
            .Add<ProgressDialog>()
            .Add<ExitDialog>();

        project.UnhandledException += Project_UnhandledException;
        project.UIInitialized += Project_UIInitialized;
        
        if (SourceOnlyBuild)
        {
            project.Language = ProjectLangId;
            project.LocalizationFile = $"Resources/{Languages.First(x => x.Key == ProjectLangId).Value}";

            if (ProjectLangId != enUS.Key)
            {
                project.OutDir = Path.Combine(project.OutDir, ProjectLangId);
            }

            project.BuildMsiCmd();
        }
        else
        {
            // Build the multi-language MSI in the {Debug/Release} directory

            project.Language = enUS.Key;
            project.LocalizationFile = $"Resources/{enUS.Value}";

            string msi = project.BuildMsi();

            foreach (KeyValuePair<string, string> language in Languages.Where(x => x.Key != enUS.Key))
            {
                project.Language = language.Key;
                string mstFile = project.BuildLanguageTransform(msi, project.Language, $"Resources/{language.Value}");

                msi.EmbedTransform(mstFile);
            }
            
            msi.SetPackageLanguages(string.Join(",", Languages.Keys).ToLcidList());
        }
    }

    private static void Project_UnhandledException(ExceptionEventArgs e)
    {
        string errorMessage =
            $"An unhandled error has occurred. If this is recurring, please report the issue to {Includes.EMAIL_SUPPORT} or on {Includes.FORUM_SUPPORT}.";
        errorMessage += Environment.NewLine;
        errorMessage += Environment.NewLine;
        errorMessage += "Error details:";
        errorMessage += Environment.NewLine;
        errorMessage += e.Exception;

        MessageBox.Show(errorMessage, Includes.PRODUCT_NAME, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }

    private static void Project_UIInitialized(SetupEventArgs e)
    {
        e.Session.Set(GatewayProperties.userTempPath, Path.GetTempPath());

        Guid installId = Guid.NewGuid();
        e.Session.Set(GatewayProperties.installId, installId);
        Wizard.Globals["installId"] = installId.ToString();

        string lcid = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "fr" ? frFR.Key : enUS.Key;

        using Stream stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream($"DevolutionsGateway.Resources.{Languages[lcid]}");

        XmlDocument xml = new();
        xml.Load(stream);

        Dictionary<string, string> strings = new();

        foreach (XmlNode s in xml.GetElementsByTagName("String"))
        {
            strings.Add(s.Attributes["Id"].Value, s.InnerText);
        }

        string I18n(string key)
        {
            if (!strings.TryGetValue(key, out string result))
            {
                return key;
            }

            return Regex.Replace(result, @"\[(.*?)]", (match) =>
            {
                string property = match.Groups[1].Value;
                string value = e.Session[property];

                return string.IsNullOrEmpty(value) ? property : value;
            });
        }

        if (!Environment.Is64BitOperatingSystem)
        {
            MessageBox.Show(I18n(Strings.x86VersionRequired), I18n(Strings.GatewayDlg_Title));

            e.ManagedUI.Shell.ErrorDetected = true;
            e.Result = ActionResult.UserExit;
        }

        Version thisVersion = e.Session.QueryProductVersion();
        Version installedVersion = Helpers.AppSearch.InstalledVersion;

        if (installedVersion is null)
        {
            e.Session.Set(GatewayProperties.configureGateway, true);
        }

        if (thisVersion < installedVersion)
        {
            MessageBox.Show($"{I18n(Strings.NewerInstalled)} ({installedVersion})");

            e.ManagedUI.Shell.ErrorDetected = true;
            e.Result = ActionResult.UserExit;
        }

        if (!CustomActions.CheckPowerShellVersion())
        {
            MessageBox.Show(I18n(Strings.WindowsPowerShell51IsRequired), I18n(Strings.GatewayDlg_Title));

            e.ManagedUI.Shell.ErrorDetected = true;
            e.Result = ActionResult.UserExit;
        }
        
        if (!CustomActions.TryGetInstalledNetFx45Version(out uint netfx45Version) || netfx45Version < 394802)
        {
            if (MessageBox.Show(I18n(Strings.Dotnet462IsRequired), I18n(Strings.GatewayDlg_Title),
                    MessageBoxButtons.YesNo) == DialogResult.Yes)
            {
                Process.Start("https://go.microsoft.com/fwlink/?LinkId=2085155");
            }

            e.ManagedUI.Shell.ErrorDetected = true;
            e.Result = ActionResult.UserExit;
        }
        
        if (netfx45Version < 528040)
        {
            if (MessageBox.Show(I18n(Strings.DotNet48IsStrongRecommendedDownloadNow), I18n(Strings.GatewayDlg_Title),
                    MessageBoxButtons.YesNo) == DialogResult.Yes)
            {
                Process.Start("https://go.microsoft.com/fwlink/?LinkId=2085155");
            }
        }
    }
}
