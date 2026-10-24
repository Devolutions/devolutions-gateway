namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// Theory data that yields one row per vector name, so that each vector runs and reports as its own test.
/// </summary>
public static class VectorData
{
    public static TheoryData<string> CsrNames =>
        new(TestVectors.Instance.Csr.Keys);

    public static TheoryData<string> HttpSignatureCaseNames =>
        new(TestVectors.Instance.HttpSignature.Cases.Select(c => c.Name));

    public static TheoryData<string> HttpSignatureSequenceNames =>
        new(TestVectors.Instance.HttpSignature.Sequences.Select(sequence => sequence.Name));

    public static TheoryData<string> ChannelProofCaseNames =>
        new(TestVectors.Instance.ChannelProof.Cases.Select(c => c.Name));
}
