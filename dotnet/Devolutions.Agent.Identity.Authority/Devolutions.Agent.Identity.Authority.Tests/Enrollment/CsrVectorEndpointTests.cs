namespace Devolutions.Agent.Identity.Authority.Tests;

// test-vectors.json csr.<name>.expected_at gives each CSR's outcome at each endpoint:
// `enroll` with a valid token whose `u` is the entry's `enrollment_url`, or any valid token when it has none,
// and `renew` signed by an identity that holds no certificate for the CSR's key.
public class CsrVectorEndpointTests
{
    private static readonly DateTimeOffset Now = new(2026, 9, 24, 12, 0, 0, TimeSpan.Zero);

    // Any valid token, for an entry that names no enrollment URL.
    private const string AnyTokenUrl = "https://example.test/dvls";

    public static TheoryData<string, string> CsrEndpoints
    {
        get
        {
            TheoryData<string, string> rows = [];
            foreach ((string name, CsrVector vector) in TestVectors.Instance.Csr)
            {
                foreach (string endpoint in vector.ExpectedAt.Keys)
                {
                    rows.Add(name, endpoint);
                }
            }

            return rows;
        }
    }

    // oracle: reference docs/agent-identity/test-vectors.json csr
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §certificates
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §token-rules
    [Theory]
    [MemberData(nameof(CsrEndpoints))]
    public async Task CsrVectorHasItsExpectedOutcomeAtEachEndpoint(string name, string endpoint)
    {
        CsrVector vector = TestVectors.Instance.Csr[name];

        string outcome = await Endpoints[endpoint](vector);

        Assert.Equal(vector.ExpectedAt[endpoint], outcome);
    }

    // The outcome of a CSR at each endpoint, through the public API: `ok` or the wire value of the error code.
    private static Dictionary<string, Func<CsrVector, Task<string>>> Endpoints => new()
    {
        ["enroll"] = vector => Task.FromResult(Enroll(vector)),
        ["renew"] = Renew,
    };

    private static string Enroll(CsrVector vector)
    {
        CsrValidationResult result = CertificateSigningRequest.Validate(vector.Csr);
        if (!result.Succeeded)
        {
            return result.Error.Code.ToWireValue();
        }

        EnrollmentTokenState token =
            new(false, vector.EnrollmentUrl ?? AnyTokenUrl, Now.AddDays(1), maxUses: 10, identitiesCreated: 0);
        EnrollmentDecision decision = EnrollmentRules.Decide(token, result.Csr, null, Now);

        return decision.Outcome == EnrollmentOutcome.CreateIdentity ? "ok" : decision.Error!.Code.ToWireValue();
    }

    private static async Task<string> Renew(CsrVector vector)
    {
        CsrValidationResult result = CertificateSigningRequest.Validate(vector.Csr);
        if (!result.Succeeded)
        {
            return result.Error.Code.ToWireValue();
        }

        AuthenticatedIdentity renewing = await TestIdentity.AuthenticateAsync(AgentOperation.Renew);
        RenewalDecision decision = RenewalRules.Decide(renewing, result.Csr, null);

        return decision.Outcome == RenewalOutcome.IssuePendingCertificate ? "ok" : decision.Error!.Code.ToWireValue();
    }
}
