using Microsoft.Win32;
using System;
using System.Runtime.InteropServices;

namespace Devolutions.Agent.Desktop
{
    internal partial class Utils
    {
        internal enum ThemeMode
        {
            Dark = 0,
            Light = 1,
            Unknown,
        }

        [DllImport("dwmapi.dll")]
        private static extern int DwmSetWindowAttribute(IntPtr hwnd, int attr, ref int attrValue, int attrSize);

        private const int DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1 = 19;

        private const int DWMWA_USE_IMMERSIVE_DARK_MODE = 20;

        internal static bool UseImmersiveDarkMode(IntPtr handle, bool enabled)
        {
            if (Environment.OSVersion.Version.Major >= 10 && Environment.OSVersion.Version.Build >= 17763)
            {
                int attribute = Environment.OSVersion.Version.Build >= 18985 ? DWMWA_USE_IMMERSIVE_DARK_MODE : DWMWA_USE_IMMERSIVE_DARK_MODE_BEFORE_20H1;
                int useImmersiveDarkMode = enabled ? 1 : 0;

                try
                {
                    return DwmSetWindowAttribute(handle, attribute, ref useImmersiveDarkMode, sizeof(int)) == 0;
                }
                catch
                {
                    return false;
                }
            }

            return false;
        }

        public static ThemeMode Theme()
        {
            string keyName = @"HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize";

            try
            {
                int raw = (int)Registry.GetValue(keyName, "AppsUseLightTheme", -1);

                return raw switch
                {
                    0 => ThemeMode.Dark,
                    1 => ThemeMode.Light,
                    _ => ThemeMode.Unknown
                };
            }
            catch 
            { 
                return ThemeMode.Unknown; 
            }
        }
    }
}
