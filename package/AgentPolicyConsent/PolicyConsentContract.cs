namespace DevolutionsAgentPolicyConsent
{
    internal static class PolicyConsentContract
    {
        internal const string ProtocolVersion = "2.0";
        internal const string ExecutableName = "DevolutionsAgentPolicyConsent.exe";
        internal const string ProductName = "Devolutions Agent Policy Consent";
        internal const string DefaultBrokerPipeName = @"\\.\pipe\Devolutions.Now.PackageBroker.v1";

        // Supported UniGetUI hosts are version 2026.2.7 or newer and must carry this signer:
        // subject CN=Devolutions Inc, O=Devolutions Inc, C=CA;
        // issuer CN=GlobalSign GCC R45 EV CodeSigning CA 2020, O=GlobalSign nv-sa, C=BE;
        // serial 73D3C33603FF8BB44224F25E, SHA-1 8DB5A43BB8AFE4D2FFB92DA9007D8997A4CC4E13,
        // valid 2023-10-30T17:51:18Z through 2026-10-30T17:51:18Z.
        internal const string CurrentUiSignerSpkiSha256 =
            "e43ed3368eaabff61abc79eb338cba9da88a80d93b751735ff417f26afa579a8";

        // Keep synchronized with devolutions-agent-shared/src/windows/code_signing.rs.
        internal static readonly string[] DevolutionsSignerSha1Thumbprints =
        [
            "3f5202a9432d54293bdfe6f7e46adb0a6f8b3ba6",
            "8db5a43bb8afe4d2ffb92da9007d8997a4cc4e13",
            "50f753333811ff11f1920274afde3ffd4468b210",
        ];
    }
}
