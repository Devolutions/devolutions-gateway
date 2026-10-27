using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Xml;

namespace DevolutionsGateway.Actions;

/// <summary>
/// The installer strings, for custom actions, which the managed UI's localization isn't available to.
/// </summary>
internal static class InstallerStrings
{
    private const string English = "1033";

    /// <summary>
    /// The installer string <paramref name="id"/> in the language whose LCID is <paramref name="productLanguage"/>, or
    /// in English when the installer doesn't have that language.
    /// </summary>
    /// <remarks>
    /// Custom actions pass the <c>ProductLanguage</c> property, which the language transform Windows Installer applied
    /// sets, so that their messages match the rest of the installer.
    /// </remarks>
    /// <returns>The string, or <paramref name="id"/> when no localization file has it.</returns>
    internal static string Localize(string productLanguage, string id)
    {
        XmlDocument strings = Load(productLanguage) ?? Load(English);
        XmlNode node = strings?.GetElementsByTagName("String")
            .Cast<XmlNode>()
            .FirstOrDefault(s => s.Attributes["Id"]?.Value == id);

        return node?.InnerText ?? id;
    }

    /// <summary>
    /// The localization file embedded in this assembly whose language is the LCID <paramref name="language"/>, or
    /// <c>null</c> when there is none.
    /// </summary>
    private static XmlDocument Load(string language)
    {
        Assembly assembly = Assembly.GetExecutingAssembly();

        foreach (string name in assembly.GetManifestResourceNames()
                     .Where(n => n.EndsWith(".wxl", StringComparison.OrdinalIgnoreCase)))
        {
            using Stream stream = assembly.GetManifestResourceStream(name);
            XmlDocument xml = new();
            xml.Load(stream);

            if (xml.DocumentElement?.GetAttribute("Language") == language)
            {
                return xml;
            }
        }

        return null;
    }
}
