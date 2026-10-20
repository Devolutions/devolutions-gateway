namespace Devolutions.AgentIdentity;

/// <summary>
/// Helpers for the lines of an HTTP field, which a request can split a field value across.
/// </summary>
internal static class FieldLines
{
    /// <summary>
    /// Copies the field lines that a caller passed, rejecting a null line.
    /// </summary>
    public static string[] Copy(IReadOnlyList<string> fieldLines, string parameterName)
    {
        ArgumentNullException.ThrowIfNull(fieldLines, parameterName);

        string[] copy = [.. fieldLines];
        if (Array.IndexOf(copy, null) >= 0)
        {
            throw new ArgumentException("A field line is null.", parameterName);
        }

        return copy;
    }

    /// <summary>
    /// Combines field lines into one field value, as RFC 9421 §2.1 does for a covered field.
    /// </summary>
    /// <remarks>
    /// Each line loses its leading and trailing white space,
    /// and the lines are joined in order with a comma and a space.
    /// RFC 9110 §5.3 combines lines the same way, so one combined value serves both parsing and the signature base.
    /// </remarks>
    public static string Combine(IReadOnlyList<string> fieldLines)
    {
        return string.Join(", ", fieldLines.Select(line => line.Trim(' ', '\t')));
    }
}
