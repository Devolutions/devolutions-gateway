using System.Buffers.Binary;
using System.Text.Json;
using DevolutionsAgentPolicyConsent;
using Microsoft.Win32.SafeHandles;
using Xunit;

namespace DevolutionsAgentPolicyConsent.Tests;

public sealed class ProtocolTests
{
    private const string RequestId = "0123456789abcdef0123456789abcdef";

    [Fact]
    public void ArgumentsRequireExactBoundIdentity()
    {
        Arguments parsed = Protocol.ParseArguments(
        [
            "--protocol", "2.0",
            "--pipe", $"UniGetUI.PolicyElevation.{RequestId}",
            "--parent-pid", "42",
            "--parent-created", "638900000000000000",
            "--session", "1",
        ]);

        Assert.Equal(42, parsed.ParentProcessId);
        Assert.Equal((uint)1, parsed.SessionId);
    }

    public sealed class TrustPolicyTests
    {
        [Fact]
        public void CurrentAndTransitionSignersAreAccepted()
        {
            Assert.True(PeerLease.IsAllowedSigner(PeerLease.CurrentUiSignerSpkiSha256));
            Assert.True(PeerLease.IsAllowedSigner(PeerLease.TransitionUiSignerSpkiSha256));
        }

        [Fact]
        public void LookalikeSignerIsRejected()
        {
            Assert.False(PeerLease.IsAllowedSigner(new string('0', 64)));
        }

        [Fact]
        public void SignerMatchingIsCaseSensitive()
        {
            Assert.False(PeerLease.IsAllowedSigner(PeerLease.CurrentUiSignerSpkiSha256.ToUpperInvariant()));
        }

        [Theory]
        [InlineData("3.3.7")]
        [InlineData("2026.2.7")]
        public void ProductBindingSupportsProtocolEraAndCurrentInstallModes(string version)
        {
            Assert.True(PeerLease.IsSupportedUiIdentity("UniGetUI", "UniGetUI.dll", version));
        }

        [Theory]
        [InlineData("Lookalike", "UniGetUI.dll", "2026.2.7")]
        [InlineData("UniGetUI", "malware.exe", "2026.2.7")]
        [InlineData("UniGetUI", "UniGetUI.dll", "3.3.6")]
        public void ProductBindingRejectsLookalikes(string product, string originalFilename, string version)
        {
            Assert.False(PeerLease.IsSupportedUiIdentity(product, originalFilename, version));
        }

        [Theory]
        [InlineData(41, 638900000000000000, 1)]
        [InlineData(42, 638900000000000001, 1)]
        [InlineData(42, 638900000000000000, 2)]
        public void ProcessIdentityRejectsPidReuseAndSessionMismatch(int pid, long created, uint session)
        {
            Arguments expected = new("pipe", 42, 638900000000000000, 1);
            Assert.False(PeerLease.MatchesProcessIdentity(expected, pid, created, session));
        }

        [Fact]
        public void ProcessIdentityAcceptsExactRetainedInstance()
        {
            Arguments expected = new("pipe", 42, 638900000000000000, 1);
            Assert.True(PeerLease.MatchesProcessIdentity(expected, 42, 638900000000000000, 1));
        }

        [Fact]
        public void BrokerServerRequiresExactAgentSiblingPath()
        {
            Assert.True(BrokerServerLease.IsExpectedPath(
                @"C:\Program Files\Devolutions\Agent\DevolutionsAgent.exe",
                @"c:\PROGRAM FILES\Devolutions\Agent\DevolutionsAgent.exe"));
            Assert.False(BrokerServerLease.IsExpectedPath(
                @"C:\Users\Alice\DevolutionsAgent.exe",
                @"C:\Program Files\Devolutions\Agent\DevolutionsAgent.exe"));
        }

        [Fact]
        public void AuthenticodeSignerComesFromRetainedImageHandle()
        {
            string path = Path.Combine(AppContext.BaseDirectory, "testhost.exe");
            using SafeFileHandle image = OpenImage(path);
            using var certificate = PeerLease.VerifyAuthenticodeSigner(path, image, "test host");
            Assert.NotEmpty(certificate.RawData);
        }

        [Fact]
        public void AuthenticodeRequiresFreshWholeChainRevocation()
        {
            Native.WinTrustData data = new(IntPtr.Zero);

            Assert.Equal(Native.WtdRevokeWholeChain, data.RevocationChecks);
            Assert.Equal(
                Native.WtdRevocationCheckChain | Native.WtdDisableMd2Md4,
                data.ProviderFlags);
            Assert.Equal(0u, data.ProviderFlags & Native.WtdCacheOnlyUrlRetrieval);
        }

        [Theory]
        [InlineData(0, true)]
        [InlineData(unchecked((int)0x800B010C), false)]
        [InlineData(unchecked((int)0x80092012), false)]
        [InlineData(unchecked((int)0x80092013), false)]
        [InlineData(unchecked((int)0x800B010E), false)]
        public void AuthenticodeFailsClosedForIndeterminateStatus(int status, bool accepted)
        {
            Assert.Equal(accepted, PeerLease.IsAuthenticodeStatusAccepted(status));
        }

        [Fact]
        public void ProcessImageMappingAcceptsOnlyCurrentMappedImage()
        {
            using SafeProcessHandle process = Native.OpenProcess(
                PeerLease.ProcessQueryInformation |
                    PeerLease.ProcessQueryLimitedInformation |
                    PeerLease.Synchronize,
                false,
                Environment.ProcessId);
            Assert.False(process.IsInvalid);

            string processPath = PeerLease.ImagePath(process);
            using SafeFileHandle processImage = OpenImage(processPath);
            PeerLease.VerifyImageMapping(process, processImage);

            using SafeFileHandle differentImage =
                OpenImage(Path.Combine(AppContext.BaseDirectory, "DevolutionsAgentPolicyConsent.exe"));
            Assert.Throws<InvalidOperationException>(() => PeerLease.VerifyImageMapping(process, differentImage));
        }

        [Fact]
        public void BrokerServerRejectsNonSystemProcessToken()
        {
            using SafeProcessHandle process = Native.OpenProcess(
                PeerLease.ProcessQueryLimitedInformation,
                false,
                Environment.ProcessId);
            Assert.False(process.IsInvalid);
            Assert.False(PeerLease.IsLocalSystemProcess(process));
        }

        [Fact]
        public void FileIdentityRejectsDifferentImage()
        {
            using SafeFileHandle first = OpenImage(Path.Combine(AppContext.BaseDirectory, "testhost.exe"));
            using SafeFileHandle same = OpenImage(Path.Combine(AppContext.BaseDirectory, "testhost.exe"));
            using SafeFileHandle different =
                OpenImage(Path.Combine(AppContext.BaseDirectory, "DevolutionsAgentPolicyConsent.exe"));

            Assert.True(PeerLease.SameFile(first, same));
            Assert.False(PeerLease.SameFile(first, different));
        }

        private static SafeFileHandle OpenImage(string path)
        {
            SafeFileHandle image = Native.CreateFile(
                path,
                PeerLease.GenericRead | PeerLease.FileExecute | PeerLease.Synchronize,
                PeerLease.FileShareRead,
                IntPtr.Zero,
                PeerLease.OpenExisting,
                0,
                IntPtr.Zero);
            Assert.False(image.IsInvalid);
            return image;
        }
    }

    [Theory]
    [InlineData("--extra")]
    [InlineData("--pipe")]
    public void ArgumentsRejectUnknownOrDuplicateNames(string name)
    {
        string[] args =
        [
            "--protocol", "2.0",
            "--pipe", $"UniGetUI.PolicyElevation.{RequestId}",
            "--parent-pid", "42",
            "--parent-created", "638900000000000000",
            name, "1",
        ];

        Assert.Throws<ProtocolException>(() => Protocol.ParseArguments(args));
    }

    [Fact]
    public async Task FrameUsesBigEndianLengthAndRoundTrips()
    {
        byte[] body = [1, 2, 3, 4];
        using MemoryStream stream = new();
        await Protocol.WriteFrameAsync(stream, body, body.Length, CancellationToken.None);
        Assert.Equal((uint)body.Length, BinaryPrimitives.ReadUInt32BigEndian(stream.GetBuffer()));
        stream.Position = 0;
        Assert.Equal(body, await Protocol.ReadFrameAsync(stream, body.Length, CancellationToken.None));
    }

    [Fact]
    public async Task OversizedFrameIsRejectedBeforeBodyRead()
    {
        byte[] header = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(header, 128);
        using MemoryStream stream = new(header);
        await Assert.ThrowsAsync<ProtocolException>(
            () => Protocol.ReadFrameAsync(stream, 127, CancellationToken.None));
    }

    [Fact]
    public async Task ZeroLengthAndTruncatedFramesAreRejected()
    {
        using MemoryStream empty = new(new byte[4]);
        await Assert.ThrowsAsync<ProtocolException>(
            () => Protocol.ReadFrameAsync(empty, 128, CancellationToken.None));

        using MemoryStream truncated = new([0, 0, 0, 2, 1]);
        await Assert.ThrowsAsync<EndOfStreamException>(
            () => Protocol.ReadFrameAsync(truncated, 128, CancellationToken.None));
    }

    [Fact]
    public async Task FrameReadHonorsCancellation()
    {
        using CancellationTokenSource cancellation = new(TimeSpan.FromMilliseconds(25));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(
            () => Protocol.ReadFrameAsync(new BlockingStream(), 128, cancellation.Token));
    }

    [Fact]
    public void RequestRejectsUnknownJsonMembers()
    {
        string json =
            $$"""{"protocolVersion":"2.0","requestId":"{{RequestId}}","operation":"Update","conflictHandling":"Reject","expectedStoreToken":"a","validationReceipt":"b","warningsAcknowledged":false,"draft":{},"command":"cmd.exe"}""";

        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize(json, ProtocolJsonContext.Default.ElevationRequest));
    }

    [Fact]
    public void OfficialRequestContainsOnlyPolicyReplacementFields()
    {
        using JsonDocument draft = JsonDocument.Parse("""{"Metadata":{"Id":"tests.policy"}}""");
        ElevationRequest request = new(
            "2.0",
            RequestId,
            "Update",
            "ConfirmOverwrite",
            "token",
            "receipt",
            true,
            draft.RootElement.Clone());

        using JsonDocument official = JsonDocument.Parse(BrokerClient.CreateOfficialRequest(request));
        string[] names = official.RootElement.EnumerateObject().Select(property => property.Name).ToArray();
        Assert.Equal(
        [
            "RequestKind",
            "RequestVersion",
            "ExpectedStoreToken",
            "Operation",
            "ConflictHandling",
            "WarningsAcknowledged",
            "Draft",
            "ValidationReceipt",
        ], names);
    }

    [Fact]
    public void RequestRequiresEveryMemberAndObjectDraft()
    {
        string missingAcknowledgement =
            $$$"""{"protocolVersion":"2.0","requestId":"{{{RequestId}}}","operation":"Update","conflictHandling":"Reject","expectedStoreToken":"a","validationReceipt":"b","draft":{}}""";
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize(missingAcknowledgement, ProtocolJsonContext.Default.ElevationRequest));

        using JsonDocument draft = JsonDocument.Parse("[]");
        ElevationRequest request = new("2.0", RequestId, "Update", "Reject", "a", "b", false, draft.RootElement);
        Assert.Throws<ProtocolException>(() => Protocol.ValidateRequest(request));
    }

    [Theory]
    [InlineData("Delete", "Reject")]
    [InlineData("Update", "Overwrite")]
    public void RequestRejectsUnknownOperations(string operation, string conflictHandling)
    {
        using JsonDocument draft = JsonDocument.Parse("{}");
        ElevationRequest request = new(
            "2.0",
            RequestId,
            operation,
            conflictHandling,
            "a",
            "b",
            false,
            draft.RootElement);

        Assert.Throws<ProtocolException>(() => Protocol.ValidateRequest(request));
    }

    [Fact]
    public void CommittedResponseContainsOnlyStoreToken()
    {
        ElevationResponse response = new(
            "2.0",
            RequestId,
            "Committed",
            null,
            null,
            "new-token",
            null,
            null,
            null);

        Protocol.ValidateResponse(response);
        string json = JsonSerializer.Serialize(response, ProtocolJsonContext.Default.ElevationResponse);
        Assert.DoesNotContain("payload", json, StringComparison.OrdinalIgnoreCase);
        Assert.DoesNotContain("message", json, StringComparison.OrdinalIgnoreCase);
    }

    [Theory]
    [InlineData("Active", "policy.id")]
    [InlineData("Missing", null)]
    [InlineData("Invalid", null)]
    public void StaleRejectionCarriesBoundedConflictContext(string state, string? policyId)
    {
        ElevationResponse response = new(
            "2.0",
            RequestId,
            "Rejected",
            409,
            "StalePolicyStoreToken",
            null,
            "current-token",
            state,
            policyId);

        Protocol.ValidateResponse(response);
    }

    [Fact]
    public void UnknownResponseCannotClaimCommitOrConflict()
    {
        ElevationResponse response = new(
            "2.0",
            RequestId,
            "Unknown",
            null,
            "Timeout",
            "claimed-token",
            null,
            null,
            null);

        Assert.Throws<ProtocolException>(() => Protocol.ValidateResponse(response));
    }

    [Fact]
    public void ResponseRequiresExplicitNullableMembers()
    {
        string missingConflictFields =
            $$$"""{"protocolVersion":"2.0","requestId":"{{{RequestId}}}","disposition":"Unknown","brokerStatusCode":null,"brokerErrorCode":"Timeout","committedStoreToken":null}""";

        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize(missingConflictFields, ProtocolJsonContext.Default.ElevationResponse));
    }

    [Fact]
    public void MaximumStaleResponseFitsExactWireBudget()
    {
        ElevationResponse response = new(
            "2.0",
            RequestId,
            "Rejected",
            409,
            "StalePolicyStoreToken",
            null,
            "T" + new string('"', 511),
            "Active",
            "P" + new string('"', 2047));

        Protocol.ValidateResponse(response);
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(
            response,
            ProtocolJsonContext.Default.ElevationResponse);
        Assert.InRange(body.Length, 1, Protocol.MaxResponseBodyBytes);
    }

    [Fact]
    public void BrokerSuccessMapsToCompactCommittedAcknowledgement()
    {
        ElevationResponse response = BrokerClient.ParseResponse(
            RequestId,
            HttpResponse(
                200,
                """{"ResponseKind":"PolicyReplacementResponse","ResponseVersion":"1.0","Management":{"StoreToken":"new-token"}}"""));

        Assert.Equal("Committed", response.Disposition);
        Assert.Equal("new-token", response.CommittedStoreToken);
        Assert.Null(response.BrokerStatusCode);
    }

    [Fact]
    public void BrokerStaleErrorMapsExactConflictContext()
    {
        ElevationResponse response = BrokerClient.ParseResponse(
            RequestId,
            HttpResponse(
                409,
                """{"ResponseKind":"ErrorResponse","ResponseVersion":"1.0","Code":"StalePolicyStoreToken","Management":{"StoreToken":"current-token","State":"Active","Policy":{"Metadata":{"Id":"policy.id"}}}}"""));

        Assert.Equal("Rejected", response.Disposition);
        Assert.Equal(409, response.BrokerStatusCode);
        Assert.Equal("current-token", response.ConflictStoreToken);
        Assert.Equal("Active", response.ConflictState);
        Assert.Equal("policy.id", response.ConflictPolicyId);
    }

    [Fact]
    public void EmptyBrokerResponseMapsToUnknown()
    {
        ElevationResponse response = BrokerClient.ParseResponse(
            RequestId,
            HttpResponse(503, string.Empty));

        Assert.Equal("Unknown", response.Disposition);
        Assert.Equal(503, response.BrokerStatusCode);
        Assert.Equal("EmptyResponse", response.BrokerErrorCode);
    }

    private static byte[] HttpResponse(int status, string body) =>
        System.Text.Encoding.UTF8.GetBytes(
            $"HTTP/1.1 {status} Test\r\nContent-Length: {System.Text.Encoding.UTF8.GetByteCount(body)}\r\n\r\n{body}");

    private sealed class BlockingStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
        public override void Flush() => throw new NotSupportedException();
        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
        public override async ValueTask<int> ReadAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            return 0;
        }
    }
}
