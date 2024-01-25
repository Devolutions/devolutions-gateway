using System;
using System.Drawing;
using System.Runtime.InteropServices;

namespace DevolutionsGateway.Helpers
{
    internal class StockIcon
    {
        internal static Icon GetStockIcon(uint type, uint size)
        {
            var info = new SHSTOCKICONINFO();
            info.cbSize = (uint)Marshal.SizeOf(info);

            SHGetStockIconInfo(type, SHGSI_ICON | size, ref info);

            var icon = (Icon)Icon.FromHandle(info.hIcon).Clone(); // Get a copy that doesn't use the original handle
            DestroyIcon(info.hIcon); // Clean up native icon to prevent resource leak

            return icon;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct SHSTOCKICONINFO
        {
            public uint cbSize;
            public IntPtr hIcon;
            public int iSysIconIndex;
            public int iIcon;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szPath;
        }

        [DllImport("shell32.dll")]
        private static extern int SHGetStockIconInfo(uint siid, uint uFlags, ref SHSTOCKICONINFO psii);

        [DllImport("user32.dll")]
        private static extern bool DestroyIcon(IntPtr handle);

        internal const uint SIID_HELP = 23;
        internal const uint SIID_SHIELD = 77;
        internal const uint SIID_WARNING = 78;
        internal const uint SIID_INFO = 79;
        internal const uint SHGSI_ICON = 0x100;
        internal const uint SHGSI_LARGEICON = 0x0;
        internal const uint SHGSI_SMALLICON = 0x1;
    }
}
