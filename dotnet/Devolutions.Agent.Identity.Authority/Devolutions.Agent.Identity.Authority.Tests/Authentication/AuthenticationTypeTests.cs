using System.Reflection;

namespace Devolutions.Agent.Identity.Authority.Tests;

/// <summary>
/// The types that only request authentication, the channel handshake and the enrollment rules create.
/// </summary>
/// <remarks>
/// INTENT.md: code that acts for an identity takes it as a type only the signature check can create,
/// so that an identity is never taken from a value the agent or a caller sent.
/// </remarks>
public class AuthenticationTypeTests
{
    private static readonly Type[] AuthenticationTypes =
    [
        // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Authenticated identity
        typeof(AuthenticatedIdentity),
        // The handshake turns an opening into an identity,
        // so an opening built by a caller would yield an identity that no signature check produced.
        // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Authenticated identity
        typeof(ChannelOpening),
        // A new identity's certificate is issued from the decision that creates it,
        // so a decision built by a caller would certify a key for an identity that no enrollment created.
        // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Authenticated identity
        typeof(EnrollmentDecision),
        // oracle: mutant a public AuthenticationResult constructor
        typeof(AuthenticationResult),
        // oracle: mutant a public ChannelOpeningResult constructor
        typeof(ChannelOpeningResult),
        // oracle: mutant a public ChannelHandshakeResult constructor
        typeof(ChannelHandshakeResult),
    ];

    public static TheoryData<Type> AuthenticationTypeData => new(AuthenticationTypes);

    // Code that acts for an identity takes it as a type only the signature check can create.
    // A public or protected constructor would let a caller build an identity from any values,
    // or a subclass of one with its own constructor.
    // The other types carry an identity, the opening that becomes one, or the decision that creates one,
    // out of a check.
    // Each row's marker names what decides it.
    // oracle: intent dotnet/Devolutions.Agent.Identity.Authority/INTENT.md §Authenticated identity
    [Theory]
    [MemberData(nameof(AuthenticationTypeData))]
    public void TypeHasNoPublicOrProtectedConstructor(Type type)
    {
        IEnumerable<ConstructorInfo> reachable = type
            .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
            .Where(IsReachableFromAnotherAssembly);

        Assert.Empty(reachable);
    }

    // A new public member producing one of these types could be a factory that bypasses the check that creates it.
    // The intent forbids creating an identity outside that check but not forwarding one that it created,
    // so the list of members allowed to produce one is the library's own.
    // oracle: mutant a public member that builds an AuthenticatedIdentity outside the signature check,
    // or an EnrollmentDecision outside the enrollment rules
    [Fact]
    public void NoOtherPublicMemberProducesTheseTypes()
    {
        const BindingFlags declared = BindingFlags.Public | BindingFlags.NonPublic
            | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly;

        IEnumerable<string> producers = typeof(RequestAuthenticator).Assembly
            .GetExportedTypes()
            .SelectMany(type => type.GetMethods(declared)
                .Where(IsReachableFromAnotherAssembly)
                .Where(method => Produces(method.ReturnType))
                .Select(method => $"{type.Name}.{method.Name}")
                .Concat(type.GetFields(declared)
                    .Where(field => field.IsPublic || field.IsFamily || field.IsFamilyOrAssembly)
                    .Where(field => Produces(field.FieldType))
                    .Select(field => $"{type.Name}.{field.Name}")));

        Assert.Equal(
            [
                "AuthenticationResult.get_Identity",
                "ChannelHandshakeResult.get_Identity",
                "ChannelOpening.FirstMessageUnreadableAsync",
                "ChannelOpening.HelloTimedOutAsync",
                "ChannelOpening.VerifyHelloAsync",
                "ChannelOpeningResult.get_Opening",
                "EnrollmentRules.Decide",
                "RequestAuthenticator.AuthenticateAsync",
                "RequestAuthenticator.AuthenticateChannelOpeningAsync",
            ],
            producers.Order(StringComparer.Ordinal));
    }

    private static bool IsReachableFromAnotherAssembly(MethodBase method)
    {
        return method.IsPublic || method.IsFamily || method.IsFamilyOrAssembly;
    }

    private static bool Produces(Type type)
    {
        Type? definition = type.IsGenericType ? type.GetGenericTypeDefinition() : null;
        Type produced = definition == typeof(ValueTask<>) || definition == typeof(Task<>)
            ? type.GetGenericArguments()[0]
            : type;

        return AuthenticationTypes.Contains(produced);
    }
}
