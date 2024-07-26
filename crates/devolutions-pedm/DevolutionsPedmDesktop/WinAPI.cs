using System.Runtime.InteropServices;

namespace DevolutionsPedmDesktop
{
    internal static class WinAPI
    {
        public const int UOI_NAME = 2;

        [DllImport("kernel32.dll")]
        public static extern uint GetCurrentThreadId();

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr GetThreadDesktop(uint dwThreadId);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool GetUserObjectInformationW(IntPtr hObj, int nIndex, [Out] byte[] pvInfo, uint nLength, ref uint lpnLengthNeeded);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern bool CloseDesktop(IntPtr hDesktop);

        [DllImport("user32.dll", SetLastError = true)]
        public static extern IntPtr SwitchDesktop(IntPtr hDesktop);

        [DllImport("wmsgapi.dll")]
        public static extern int WmsgSendMessage(int sessionId, uint commandId, int arg, out int status);

        public enum ProcessDPIAwareness
        {
            ProcessDPIUnaware = 0,
            ProcessSystemDPIAware = 1,
            ProcessPerMonitorDPIAware = 2
        }

        [DllImport("shcore.dll")]
        public static extern int SetProcessDpiAwareness(ProcessDPIAwareness value);

        [DllImport("user32.dll")]
        public static extern bool PaintDesktop(IntPtr hdc);

        [DllImport("shell32.dll", CharSet = CharSet.Auto)]
        static extern uint ExtractIconEx(string szFileName, int nIconIndex, IntPtr[] phiconLarge, IntPtr[] phiconSmall, uint nIcons);
    }
}
