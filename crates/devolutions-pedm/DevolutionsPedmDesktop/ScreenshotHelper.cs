using Microsoft.Win32;
using System.Security.Principal;

namespace DevolutionsPedmDesktop
{
    internal static class ScreenshotHelper
    {
        public static Bitmap Wallpaper(SecurityIdentifier sid)
        {
            var wallpaperPath = Registry.Users.OpenSubKey(sid.Value)?.OpenSubKey("Control Panel")?.OpenSubKey("Desktop")?.GetValue("WallPaper") as string;

            if (string.IsNullOrWhiteSpace(wallpaperPath)) {
                return null;
            }

            using var stream = File.Open(wallpaperPath, FileMode.Open, FileAccess.Read);
            
            var image = Image.FromStream(stream);

            return new Bitmap(image);
        }

        public static void DimBitmap(Bitmap bitmap)
        {
            using var graphics = Graphics.FromImage(bitmap);

            var brush = new SolidBrush(Color.FromArgb(192, Color.Black));
            graphics.FillRectangle(brush, 0, 0, bitmap.Width, bitmap.Height);
        }
    }
}
