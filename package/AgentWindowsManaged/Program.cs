using DevolutionsAgent.Actions;
using DevolutionsAgent.Dialogs;
using DevolutionsAgent.Properties;
using DevolutionsAgent.Resources;
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
using WixSharp;
using WixSharp.Bootstrapper;
using WixSharp.CommonTasks;
using WixSharpSetup.Dialogs;
using Action = WixSharp.Action;
using Assembly = System.Reflection.Assembly;
using CompressionLevel = WixSharp.CompressionLevel;
using File = WixSharp.File;

namespace DevolutionsAgent;

internal class Program
{
    private const string PackageName = "DevolutionsAgent";

    private static string DevolutionsAgentExePath
    {
        get
        {
            string path = Environment.GetEnvironmentVariable("DAGENT_EXECUTABLE");

            if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path))
            {
#if DEBUG
                path = "..\\..\\target\\x86_64-pc-windows-msvc\\release\\devolutionsagent.exe";
#else
                throw new Exception("The environment variable DAGENT_EXECUTABLE is not specified or the file does not exist");
#endif
            }

            if (!System.IO.File.Exists(path))
            {
                throw new FileNotFoundException("The agent executable was not found", path);
            }

            return path;
        }
    }

    private static string TargetOutputPath
    {
        get
        {
            string path = Environment.GetEnvironmentVariable("TARGET_OUTPUT_PATH");

            if (string.IsNullOrEmpty(path) || !Directory.Exists(path))
            {
#if DEBUG
                path = "..\\..\\target\\x86_64-pc-windows-msvc\\release\\";
#else
                throw new Exception("The environment variable TARGET_OUTPUT_PATH is not specified or the directory does not exist");
#endif
            }

            if (!Directory.Exists(path))
            {
                throw new FileNotFoundException("The target output path was not found", path);
            }

            return path;
        }
    }

    private static string DevolutionsAgentPedmDesktopExecutable
    {
        get
        {
            string path = Environment.GetEnvironmentVariable("DAGENT_PEDM_DESKTOP_EXECUTABLE");

            if (string.IsNullOrEmpty(path) || !System.IO.File.Exists(path))
            {
#if DEBUG
                path = "..\\..\\crates\\devolutions-pedm\\DevolutionsPedmDesktop\\bin\\Release\\net8.0-windows\\DevolutionsPedmDesktop.exe";
#else
                throw new Exception("The environment variable DAGENT_PEDM_DESKTOP_EXECUTABLE is not specified or the file does not exist");
#endif
            }

            if (!System.IO.File.Exists(path))
            {
                throw new FileNotFoundException("The agent PEDM desktop executable was not found", path);
            }

            return path;
        }
    }

    private static string ResolveArtifact(string varName, string error)
    {
        string path = Environment.GetEnvironmentVariable(varName);

        if (!System.IO.File.Exists(path))
        {
            throw new FileNotFoundException(error, path);
        }

        return path;
    }

    private static string DevolutionsPedmHook => ResolveArtifact("DAGENT_PEDM_HOOK", "The PEDM hook was not found");

    private static string DevolutionsPedmShellExtDll => ResolveArtifact("DAGENT_PEDM_SHELL_EXT_DLL", "The PEDM shell extension DLL was not found");

    private static string DevolutionsPedmShellExtMsix => ResolveArtifact("DAGENT_PEDM_SHELL_EXT_MSIX", "The PEDM shell extension MSIX was not found");

    private static string DevolutionsHost => ResolveArtifact("DAGENT_DEVOLUTIONS_HOST_EXECUTABLE", "The Devolutions Host executable was not found");

    private static Version DevolutionsAgentVersion
    {
        get
        {
            string versionString = Environment.GetEnvironmentVariable("DAGENT_VERSION");

            if (string.IsNullOrEmpty(versionString) || !Version.TryParse(versionString, out Version version))
            {
#if DEBUG
                versionString = FileVersionInfo.GetVersionInfo(DevolutionsAgentExePath).FileVersion;

                if (versionString.StartsWith("20"))
                {
                    versionString = versionString.Substring(2);
                }

                version = Version.Parse(versionString);
#else
                throw new Exception("The environment variable DAGENT_VERSION is not specified or is invalid");
#endif
            }

            return version;
        }
    }

    private static bool SourceOnlyBuild => !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("DAGENT_MSI_SOURCE_ONLY_BUILD"));

    private static string ProjectLangId
    {
        get
        {
            string langId = Environment.GetEnvironmentVariable("DAGENT_MSI_LANG_ID");

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
        { "en-US", "DevolutionsAgent_en-us.wxl" },
        { "fr-FR", "DevolutionsAgent_fr-fr.wxl" },
    };

    private static KeyValuePair<string, string> enUS => Languages.First(x => x.Key == "en-US");

    private static KeyValuePair<string, string> frFR => Languages.First(x => x.Key == "fr-FR");

    static void Main()
    {
        ManagedProject project = new(Includes.PRODUCT_NAME)
        {
            UpgradeCode = Includes.UPGRADE_CODE,
            Version = DevolutionsAgentVersion,
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
                    Cabinet = "dagent.cab",
                    EmbedCab = true,
                    CompressionLevel = CompressionLevel.mszip,
                }
            },
            ControlPanelInfo = new ProductInfo
            {
                Manufacturer = Includes.VENDOR_NAME,
                NoModify = true,
                ProductIcon = "Resources/DevolutionsAgent.ico",
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
                    new (DevolutionsAgentExePath)
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
                            // In contrast to Devolutions Gateway, Devolutions Agent uses LocalSystem
                            // accout to be able to perform administrative operations
                            // such as MSI installation (Updating, restarting DevolutionsGateway).
                            Interactive = false,
                            Vital = true,
                            Name = Includes.SERVICE_NAME,
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
                    new (Includes.PEDM_FEATURE, DevolutionsPedmHook),
                    new (Includes.PEDM_FEATURE, DevolutionsPedmShellExtDll),
                    new (Includes.PEDM_FEATURE, DevolutionsPedmShellExtMsix),
                    new (Includes.HOST_FEATURE, DevolutionsHost)
                },
                Dirs = new[]
                {
                    new Dir(Includes.PEDM_FEATURE, "desktop")
                    {
                        Files = new File[]
                        {
                            new (Includes.PEDM_FEATURE, DevolutionsAgentPedmDesktopExecutable),
                        }
                    }
                }
            })),
        };
        project.ResolveWildCards(true);

        project.DefaultRefAssemblies.Add(typeof(ZipArchive).Assembly.Location);
        project.DefaultRefAssemblies.Add(typeof(Newtonsoft.Json.JsonConvert).Assembly.Location);
        project.Actions = AgentActions.Actions;
        project.RegValues = new RegValue[]
        {
            new (RegistryHive.LocalMachine, $"Software\\{Includes.VENDOR_NAME}\\{Includes.SHORT_NAME}", "InstallDir", $"[{AgentProperties.InstallDir}]")
            {
                AttributesDefinition = "Type=string; Component:Permanent=yes",
                Win64 = project.Platform == Platform.x64,
                RegistryKeyAction = RegistryKeyAction.create,
            }
        };
        project.Properties = AgentProperties.Properties.Select(x => x.ToWixSharpProperty()).ToArray();
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
        string lcid = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "fr" ? frFR.Key : enUS.Key;

        using Stream stream = Assembly.GetExecutingAssembly()
            .GetManifestResourceStream($"DevolutionsAgent.Resources.{Languages[lcid]}");

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
            MessageBox.Show(I18n(Strings.x86VersionRequired), I18n(Strings.AgentDlg_Title));

            e.ManagedUI.Shell.ErrorDetected = true;
            e.Result = ActionResult.UserExit;
        }

        Version thisVersion = e.Session.QueryProductVersion();
        Version installedVersion = Helpers.AppSearch.InstalledVersion;


        if (thisVersion < installedVersion)
        {
            MessageBox.Show($"{I18n(Strings.NewerInstalled)} ({installedVersion})");

            e.ManagedUI.Shell.ErrorDetected = true;
            e.Result = ActionResult.UserExit;
        }

        if (!CustomActions.TryGetInstalledNetFx45Version(out uint netfx45Version) || netfx45Version < 394802)
        {
            if (MessageBox.Show(I18n(Strings.Dotnet462IsRequired), I18n(Strings.AgentDlg_Title),
                    MessageBoxButtons.YesNo) == DialogResult.Yes)
            {
                Process.Start("https://go.microsoft.com/fwlink/?LinkId=2085155");
            }

            e.ManagedUI.Shell.ErrorDetected = true;
            e.Result = ActionResult.UserExit;
        }

        if (netfx45Version < 528040)
        {
            if (MessageBox.Show(I18n(Strings.DotNet48IsStrongRecommendedDownloadNow), I18n(Strings.AgentDlg_Title),
                    MessageBoxButtons.YesNo) == DialogResult.Yes)
            {
                Process.Start("https://go.microsoft.com/fwlink/?LinkId=2085155");
            }
        }
    }
}
