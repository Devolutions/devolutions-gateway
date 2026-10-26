namespace Devolutions.Agent.Identity.Authority.Tests;

/// <summary>
/// Checks that a text reveals no part of an enrollment token,
/// since tokens never appear in logs, not even partially (INTENT.agent-identity.md, security invariant 9).
/// </summary>
internal static class EnrollmentTokenAssert
{
    // Any six consecutive characters of a bag or a secret count as a part of the token.
    // The prefix is public, so a fixed message may name it.
    private const int PartLength = 6;

    public static void RevealsNoPart(string text, params ReadOnlySpan<string> segments)
    {
        foreach (string segment in segments)
        {
            for (int start = 0; start + PartLength <= segment.Length; start++)
            {
                Assert.DoesNotContain(segment.Substring(start, PartLength), text, StringComparison.Ordinal);
            }
        }
    }
}
