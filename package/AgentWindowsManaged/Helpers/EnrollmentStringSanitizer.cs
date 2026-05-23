using System.Text.RegularExpressions;

namespace DevolutionsAgent.Helpers;

/// <summary>
/// Strip every whitespace character from an enrollment string (typically a JWT).
/// Pasted JWTs often arrive wrapped onto multiple lines or padded with spaces;
/// the dialog validation, the property persisted into the MSI session, and the
/// argument handed to <c>agent.exe up --enrollment-string</c> must all refer to
/// the exact same byte sequence. <c>Trim()</c> alone is insufficient because it
/// only removes leading/trailing whitespace.
/// </summary>
internal static class EnrollmentStringSanitizer
{
    public static string StripAllWhitespace(string value) =>
        value is null ? string.Empty : Regex.Replace(value, @"\s+", "");
}
