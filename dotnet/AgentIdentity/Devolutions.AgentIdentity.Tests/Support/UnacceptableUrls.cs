namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// URLs that are not an absolute <c>https</c> URL without an <c>@</c>, a query or a fragment,
/// the form that a token's <c>u</c> and a config's <c>agent_channel_url</c> both take.
/// </summary>
public static class UnacceptableUrls
{
    // CONTRACT.agent-identity.md §2 makes `u`, and §5.2 makes `agent_channel_url`, an absolute `https` URL
    // without a user name or password, a query or a fragment, read as text:
    // it begins with `https://` and contains no '@', since any '@' counts as a user name.
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
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "https://admin@host/dvls",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "https://admin:secret@host/dvls",
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "https://:secret@host/dvls",
        // Any '@' counts as a user name, even with nothing before it.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "https://@host/dvls",
        // Read as text, a URL contains no '@' anywhere, even after the authority.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "https://host/dvls/a@b",
        // Read as text, a URL begins with `https://`.
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enrollment-token
        // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §enroll
        "https:@host/dvls",
    ];

    public static TheoryData<string> Rows => new(All);
}
