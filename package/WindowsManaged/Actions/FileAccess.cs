using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DevolutionsGateway.Actions
{
    internal enum FileAccess
    {
        None,
        Read,
        Write,
        Modify,
    }

    internal static class FileAccessExtensions
    {
        internal static string AsString(this FileAccess access)
        {
            switch (access)
            {
                case FileAccess.Read: return "read";
                case FileAccess.Write: return "write";
                case FileAccess.Modify: return "modify";
                default: return "unknown";
            }
        }
    }
}
