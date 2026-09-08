using System;
using System.Security.Principal;
namespace DevolutionsGateway.Resources
{
    internal static class Includes
    {
        internal static string VENDOR_NAME = "Devolutions";

        internal static string PRODUCT_NAME = "Devolutions Gateway";

        internal static string SHORT_NAME = "Gateway";

        internal static string SERVICE_NAME = "DevolutionsGateway";

        internal static string SERVICE_DISPLAY_NAME = "Devolutions Gateway Service";

        internal static string SERVICE_DESCRIPTION = "Devolutions Gateway Service";

        internal static string EXECUTABLE_NAME = "DevolutionsGateway.exe";

        internal static string EMAIL_SUPPORT = "support@devolutions.net";

        internal static string FORUM_SUPPORT = "forum.devolutions.net";

        internal static Guid UPGRADE_CODE = new("db3903d6-c451-4393-bd80-eb9f45b90214");

        internal static string INFO_URL = "https://server.devolutions.net";

        /// <summary>
        /// SDDL template for the desired %programdata%\devolutions\gateway ACL. `{0}` is the SID of the service account.
        /// Easiest way to generate an SDDL is to configure the required access, and then query the path with PowerShell: `Get-Acl | Format-List`
        /// </summary>
        /// <remarks>
            /// Local System (SY)	Full Access (FA)
            /// Local Service (LS)	Read, Execute
            /// Service account	Read, Execute, Write, Delete Subfolders and Files
            /// Administrators (BA)	Full Access (FA)
            /// Users (BU)	Read, Execute
        /// </remarks>
        private const string PROGRAM_DATA_SDDL_TEMPLATE = "O:SYG:SYD:PAI(A;OICI;FA;;;SY)(A;OICI;0x1201bf;;;LS)(A;OICI;0x1301ff;;;{0})(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";

        /// <summary>
        /// SDDL template for the desired %programdata%\devolutions\gateway\users.txt ACL. `{0}` is the SID of the service account.
        /// </summary>
        /// <remarks>
        /// Owner  : NT AUTHORITY\SYSTEM
        /// Group  : NT AUTHORITY\SYSTEM
        /// Access :
            /// Local System (SY)	Full Access (FA)
            /// Local Service (LS)	Read, Execute, Modify (Write)
            /// Service account	Read, Execute, Modify (Write)
            /// Administrators (BA)	Full Access (FA)
        /// </remarks>
        private const string USERS_FILE_SDDL_TEMPLATE = "O:SYG:SYD:PAI(A;;FA;;;SY)(A;;0x1201bf;;;LS)(A;;0x1201bf;;;{0})(A;;FA;;;BA)";

        internal static string ProgramDataSddl(SecurityIdentifier serviceAccount) => string.Format(PROGRAM_DATA_SDDL_TEMPLATE, serviceAccount.Value);

        internal static string UsersFileSddl(SecurityIdentifier serviceAccount) => string.Format(USERS_FILE_SDDL_TEMPLATE, serviceAccount.Value);
    }
}
