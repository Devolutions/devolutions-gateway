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
    /// The URL is not an absolute <c>https</c> URL, or has user information, a query or a fragment.
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

        // UserInfo is empty for https://@host, so only the component with its delimiter shows the '@'.
        if (parsed.GetComponents(UriComponents.UserInfo | UriComponents.KeepDelimiter, UriFormat.UriEscaped).Length != 0)
        {
            throw new ArgumentException($"{name} has user information.", paramName);
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
