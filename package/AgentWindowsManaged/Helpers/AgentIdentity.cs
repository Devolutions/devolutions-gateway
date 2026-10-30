using System.IO;
using System.Linq;
using DevolutionsAgent.Resources;

namespace DevolutionsAgent.Helpers
{
    /// <summary>
    /// How the installer hands an Agent Identity enrollment token to the agent, and which device keys a full uninstall
    /// deletes.
    /// </summary>
    internal static class AgentIdentity
    {
        /// <summary>
        /// The device-key prefix Agent Identity owns (crates/agent-identity/INTENT.md, "Stored identities").
        /// </summary>
        internal const string KeyNamePrefix = "devolutions-agent-identity";

        /// <summary>
        /// The <c>identity enroll -</c> invocation, which reads the token from the first line of standard input so that
        /// it never appears in a process listing.
        /// </summary>
        internal static (string FileName, string Arguments, string Input) EnrollCommand(string installDir, string token) =>
            (Path.Combine(installDir, Includes.EXECUTABLE_NAME), "identity enroll -", token + "\n");

        /// <summary>
        /// Whether <paramref name="name"/> is a device key of Agent Identity, by the device-key listing rule: a
        /// well-formed name whose part before the first <c>_</c> equals the prefix.
        /// </summary>
        internal static bool IsKeyName(string name)
        {
            int separator = name.IndexOf('_');

            if (separator < 0 || name.Substring(0, separator) != KeyNamePrefix)
            {
                return false;
            }

            string part = name.Substring(separator + 1);

            return part.Length is >= 1 and <= 128
                && part.All(c => c is >= 'a' and <= 'z' or >= '0' and <= '9' or '-' or '_');
        }
    }
}
