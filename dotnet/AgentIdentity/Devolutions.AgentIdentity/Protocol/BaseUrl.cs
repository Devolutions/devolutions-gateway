namespace Devolutions.AgentIdentity;

/// <summary>
/// Checks a base URL to which the agent appends a path, and writes it in one form.
/// </summary>
internal static class BaseUrl
{
    /// <summary>
    /// Returns the URL in normalized absolute form without trailing slashes,
    /// so that the path the agent appends follows exactly one slash.
    /// </summary>
    /// <param name="url">The URL text.</param>
    /// <param name="name">What the URL is, as error messages start, such as <c>The product base URL</c>.</param>
    /// <param name="paramName">The parameter that holds the URL.</param>
    /// <exception cref="ArgumentException">
    /// The URL is not an absolute <c>https</c> URL,
    /// or has user information or any other <c>@</c>, a query or a fragment.
    /// </exception>
    public static string Normalize(string url, string name, string paramName)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? parsed))
        {
            throw new ArgumentException($"{name} is not an absolute URL.", paramName);
        }

        if (parsed.Scheme != Uri.UriSchemeHttps)
        {
            throw new ArgumentException($"{name} does not use the https scheme.", paramName);
        }

        // CONTRACT.agent-identity.md §2 reads the URL as text, where any '@' counts as a user name,
        // because URL parsers disagree on forms such as https://@host.
        if (url.Contains('@'))
        {
            throw new ArgumentException($"{name} contains an '@', which counts as user information.", paramName);
        }

        // Query and Fragment include their delimiter, so an empty query or fragment still makes them non-empty.
        if (parsed.Query.Length != 0)
        {
            throw new ArgumentException($"{name} has a query.", paramName);
        }

        if (parsed.Fragment.Length != 0)
        {
            throw new ArgumentException($"{name} has a fragment.", paramName);
        }

        return parsed.AbsoluteUri.TrimEnd('/');
    }
}
