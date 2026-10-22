namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// URLs that are not an absolute <c>https</c> URL without user information, a query or a fragment,
/// the form that a token's <c>u</c> and a config's <c>agent_channel_url</c> both take.
/// </summary>
public static class UnacceptableUrls
{
    // CONTRACT.agent-identity.md §2 makes `u` and §5.2 makes `agent_channel_url` an absolute `https` URL
    // without a query or fragment.
    // RFC 9110 §4.2.4 deprecates user information in an `https` URI and tells a recipient to treat it as an error.
    public static string[] All { get; } =
    [
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "/dvls",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "host/dvls",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "http://host/dvls",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "wss://host/dvls",
        // oracle: spec RFC 9110 §4.2.2
        "https:///dvls",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "https://host/dvls?tenant=1",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        // oracle: spec RFC 3986 §3.4
        "https://host/dvls?",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "https://host/dvls#top",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        // oracle: spec RFC 3986 §3.5
        "https://host/dvls#",
        // oracle: spec RFC 9110 §4.2.4
        "https://admin@host/dvls",
        // oracle: spec RFC 9110 §4.2.4
        "https://@host/dvls",
    ];

    public static TheoryData<string> Rows => new(All);
}
