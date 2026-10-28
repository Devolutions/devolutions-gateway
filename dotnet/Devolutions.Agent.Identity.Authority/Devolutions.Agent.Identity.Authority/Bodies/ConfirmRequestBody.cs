namespace Devolutions.Agent.Identity.Authority;

/// <summary>
/// The body of a <c>confirm</c> request, which is empty.
/// </summary>
public sealed class ConfirmRequestBody
{
    private ConfirmRequestBody()
    {
    }

    /// <summary>
    /// Checks that the body of a <c>confirm</c> request is empty.
    /// </summary>
    /// <remarks>
    /// Any byte, white space included, makes the body invalid.
    /// Authenticate the request first and act on it only once the body is valid,
    /// so that an authentication error wins over an invalid body and an invalid body changes no state.
    /// </remarks>
    /// <param name="body">The request body.</param>
    public static RequestBodyParseResult<ConfirmRequestBody> Parse(ReadOnlySpan<byte> body)
    {
        if (!body.IsEmpty)
        {
            return RequestBodyParseResult<ConfirmRequestBody>.Failure("The body is not empty.");
        }

        return RequestBodyParseResult<ConfirmRequestBody>.Success(new ConfirmRequestBody());
    }
}
