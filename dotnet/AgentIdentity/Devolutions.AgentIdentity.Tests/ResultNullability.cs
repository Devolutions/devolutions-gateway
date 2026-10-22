namespace Devolutions.AgentIdentity.Tests;

// Never runs: it compiles only while each result's Succeeded tells the compiler which members are not null,
// so a lost [MemberNotNullWhen] fails the build under TreatWarningsAsErrors.
// It is not a test, because no document decides the annotations and the build alone checks them.
internal static class ResultNullability
{
    internal static void Authentication(AuthenticationResult result)
    {
        if (result.Succeeded)
        {
            Consume(result.Identity);
        }

        if (!result.Succeeded)
        {
            Consume(result.Error, result.FailureDetail);
        }
    }

    internal static void MetadataValidation(MetadataValidationResult result)
    {
        if (result.Succeeded)
        {
            Consume(result.Metadata);
        }

        if (!result.Succeeded)
        {
            Consume(result.Error, result.FailureDetail);
        }
    }

    internal static void RequestBodyParse(RequestBodyParseResult<EnrollRequestBody> result)
    {
        if (result.Succeeded)
        {
            Consume(result.Body);
        }

        if (!result.Succeeded)
        {
            Consume(result.Error, result.FailureDetail);
        }
    }

    internal static void CsrValidation(CsrValidationResult result)
    {
        if (result.Succeeded)
        {
            Consume(result.Csr);
        }

        if (!result.Succeeded)
        {
            Consume(result.Error, result.FailureDetail);
        }
    }

    internal static void EnrollmentAuthorization(EnrollmentAuthorizationResult result)
    {
        if (!result.Succeeded)
        {
            Consume(result.Error, result.FailureDetail);
        }
    }

    internal static void ChannelOpening(ChannelOpeningResult result)
    {
        if (result.Succeeded)
        {
            Consume(result.Opening);
        }

        if (!result.Succeeded)
        {
            Consume(result.Error, result.FailureDetail);
        }
    }

    internal static void ChannelHandshake(ChannelHandshakeResult result)
    {
        if (result.Succeeded)
        {
            Consume(result.Identity, result.Metadata, result.Welcome);
        }

        if (!result.Succeeded)
        {
            Consume(result.Error, result.FailureDetail);
        }
    }

    private static void Consume(params object[] values)
    {
        _ = values;
    }
}
