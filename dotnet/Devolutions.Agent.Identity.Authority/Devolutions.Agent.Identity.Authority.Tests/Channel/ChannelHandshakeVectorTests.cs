namespace Devolutions.Agent.Identity.Authority.Tests;

/// <summary>
/// The shared channel proof vectors, run through the public API:
/// the vector's opening request, then a <c>Hello</c> carrying each case's proof.
/// </summary>
public class ChannelHandshakeVectorTests
{
    private static ChannelProofVectors Vectors => TestVectors.Instance.ChannelProof;

    // Step 4: a proof that does not verify closes the stream with signature_invalid.
    // Each failing case changes the key, one part of the signed bytes, or the encoding of the proof.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: reference docs/agent-identity/test-vectors.json channel_proof
    [Theory]
    [MemberData(nameof(VectorData.ChannelProofCaseNames), MemberType = typeof(VectorData))]
    public async Task CaseMatchesItsExpectedValidity(string name)
    {
        ChannelProofCaseVector vector = Vectors.Case(name);
        ChannelOpening opening = await VectorChannel.OpenAsync();

        ChannelHandshakeResult result =
            await opening.VerifyHelloAsync(VectorChannel.HelloMessage(opening, vector.Proof));

        string outcome = result.Succeeded ? "ok" : result.Error.Code.ToWireValue();
        Assert.Equal(vector.ExpectedValid ? "ok" : "signature_invalid", outcome);
    }

    // Step 3: the proof signs the domain, a zero byte, the challenge and the connect nonce.
    // A proof input that differs from the vector's in any byte fails every agent's proof.
    // oracle: contract docs/agent-identity/CONTRACT.agent-identity.md §channel-sequence
    // oracle: reference docs/agent-identity/test-vectors.json channel_proof.message_hex
    [Fact]
    public void ProofInputIsTheVectorMessage()
    {
        byte[] input = ChannelProof.BuildInput(Vectors.Challenge, Vectors.ConnectNonce);

        Assert.Equal(Convert.ToHexStringLower(Vectors.Message), Convert.ToHexStringLower(input));
    }
}
