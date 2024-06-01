using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Windows.Forms;

namespace DevolutionsAgent.Controls
{
    public class ElevatedButton : Button
    {
        /// <summary>
        /// The constructor to create the button with a UAC shield if necessary.
        /// </summary>
        public ElevatedButton()
        {
            FlatStyle = FlatStyle.System;

            if (LicenseManager.UsageMode != LicenseUsageMode.Designtime)
            {
                if (!IsElevated()) ShowShield();
            }
        }


        [DllImport("user32.dll")]
        private static extern IntPtr SendMessage(HandleRef hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        private uint BCM_SETSHIELD = 0x0000160C;

        private bool IsElevated()
        {
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        private void ShowShield()
        {
            IntPtr wParam = new IntPtr(0);
            IntPtr lParam = new IntPtr(1);
            SendMessage(new HandleRef(this, Handle), BCM_SETSHIELD, wParam, lParam);
        }
    }
}
