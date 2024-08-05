using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Principal;
using System.Text;

namespace DevolutionsPedmDesktop
{
    internal static class Program
    {
        private static string GetDesktopName()
        {
            var desktop = WinAPI.GetThreadDesktop(WinAPI.GetCurrentThreadId());

            if (desktop == IntPtr.Zero)
            {
                throw new Win32Exception();
            }

            uint lengthNeeded = 0;
            WinAPI.GetUserObjectInformationW(desktop, WinAPI.UOI_NAME, null, 0, ref lengthNeeded);

            var buf = new byte[lengthNeeded];
            WinAPI.GetUserObjectInformationW(desktop, WinAPI.UOI_NAME, buf, (uint)buf.Length, ref lengthNeeded);

            var desktopName = Encoding.Unicode.GetString(buf);

            var nullByteIdx = desktopName.IndexOf('\0');

            if (nullByteIdx >= 0)
            {
                desktopName = desktopName.Substring(0, nullByteIdx);
            }

            return desktopName;
        }

        private static void SetupSecureDesktop(SecurityIdentifier sid, Form mainForm)
        {
            if (!GetDesktopName().Equals("Winlogon", StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

            var wallpaper = ScreenshotHelper.Wallpaper(sid) ?? new Bitmap(512, 512);

            ScreenshotHelper.DimBitmap(wallpaper);

            mainForm.Load += (object sender, EventArgs args) =>
            {
                var currentProcess = Process.GetCurrentProcess();
                int ouat = WinAPI.WmsgSendMessage(currentProcess.SessionId, 0x502, currentProcess.Id, out int status);

                var screens = Screen.AllScreens;
                foreach (var screen in screens)
                {
                    var backgroundForm = new FrmBackground(screen)
                    {
                        Background = new Bitmap(wallpaper, screen.Bounds.Size)
                    };

                    backgroundForm.GotFocus += (sender, args) =>
                    {
                        mainForm.Focus();
                    };

                    backgroundForm.Show();

                    _backgrounds.Add(backgroundForm);
                }

                ouat = WinAPI.WmsgSendMessage(currentProcess.SessionId, 0x500, currentProcess.Id, out status);
            };

            mainForm.FormClosed += (object sender, FormClosedEventArgs e) =>
            {
                foreach (var bg in _backgrounds)
                {
                    bg.Close();
                }
            };
            
            Application.ApplicationExit += (object sender, EventArgs e) =>
            {
                var currentProcess = Process.GetCurrentProcess();
                int ouat = WinAPI.WmsgSendMessage(currentProcess.SessionId, 0x501, currentProcess.Id, out int status);
            };
        }

        private static readonly List<FrmBackground> _backgrounds = new();

        /// <summary>
        ///  The main entry point for the application.
        /// </summary>
        [STAThread]
        public static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            WinAPI.SetProcessDpiAwareness(WinAPI.ProcessDPIAwareness.ProcessPerMonitorDPIAware);

            AppDomain.CurrentDomain.UnhandledException += (sender, eventArgs) =>
            {
                MessageBox.Show(eventArgs.ExceptionObject.ToString());
            };

            if (args.Length < 2)
            {
                return;
            }

            var sid = new SecurityIdentifier(args[0]);
            var verb = args[1];
            var cmdArgs = args.Skip(2).ToArray();

            Form mainForm = null;
            switch (verb)
            {
                case "consent" when cmdArgs.Length >= 2:
                {
                    var pipe = new AnonymousPipeClientStream(PipeDirection.Out, cmdArgs[0]);
                    mainForm = new FrmConsent(pipe, cmdArgs[1]);
                    break;
                }
                case "error" when cmdArgs.Length >= 1:
                {
                    mainForm = new FrmError(new Win32Exception(int.Parse(cmdArgs[0])));
                    break;
                }
            }

            if (mainForm == null)
            {
                return;
            }

            SetupSecureDesktop(sid, mainForm);
            Application.Run(mainForm);
        }
    }
}