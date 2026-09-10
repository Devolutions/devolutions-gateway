namespace DevolutionsAgentPolicyConsent
{
    internal static class PolicyConsentContract
    {
        internal const string ProtocolVersion = "2.0";
        internal const string ExecutableName = "DevolutionsAgentPolicyConsent.exe";
        internal const string ProductName = "Devolutions Agent Policy Consent";

        // UniGetUI 2026.2.7: subject CN=Devolutions Inc, O=Devolutions Inc, C=CA;
        // issuer CN=GlobalSign GCC R45 EV CodeSigning CA 2020, O=GlobalSign nv-sa, C=BE;
        // serial 73D3C33603FF8BB44224F25E, SHA-1 8DB5A43BB8AFE4D2FFB92DA9007D8997A4CC4E13,
        // valid 2023-10-30T17:51:18Z through 2026-10-30T17:51:18Z.
        internal const string CurrentUiSignerSpkiSha256 =
            "e43ed3368eaabff61abc79eb338cba9da88a80d93b751735ff417f26afa579a8";

        // UniGetUI 3.3.7: subject CN="Open Source Developer, Martí Climent López",
        // O=Open Source Developer, C=ES; issuer CN=Certum Code Signing 2021 CA,
        // O=Asseco Data Systems S.A., C=PL;
        // serial 1AC2CAA58AF100E402D9812002C08B30, SHA-1 28949703053434989162B12C101497DE35FE4E8E,
        // valid 2025-06-24T18:02:38Z through 2026-06-24T18:02:37Z.
        // Remove this transition pin when the minimum supported UniGetUI version postdates its last signed release.
        internal const string TransitionUiSignerSpkiSha256 =
            "99e7adb5894e242d87d32b8ad6cb5a1e0d2dd791a447bd7192c30189ef083fab";

        // Keep synchronized with devolutions-agent-shared/src/windows/code_signing.rs.
        internal static readonly string[] DevolutionsSignerSha1Thumbprints =
        [
            "3f5202a9432d54293bdfe6f7e46adb0a6f8b3ba6",
            "8db5a43bb8afe4d2ffb92da9007d8997a4cc4e13",
            "50f753333811ff11f1920274afde3ffd4468b210",
        ];
    }
}
