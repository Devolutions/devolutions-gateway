using System.Reflection;

namespace Devolutions.AgentIdentity.Tests;

/// <summary>
/// The types that only request authentication and the channel handshake create.
/// </summary>
/// <remarks>
/// INTENT.md: code that acts for an identity takes it as a type only the signature check can create,
/// so that an identity is never taken from a value the agent or a caller sent.
/// </remarks>
public class AuthenticationTypeTests
{
    private static readonly Type[] AuthenticationTypes =
    [
        typeof(AuthenticatedIdentity),
        typeof(ChannelOpening),
        typeof(AuthenticationResult),
        typeof(ChannelOpeningResult),
        typeof(ChannelHandshakeResult),
    ];

    public static TheoryData<Type> AuthenticationTypeData => new(AuthenticationTypes);

    // A public or protected constructor would let a caller build an identity from any values,
    // or a subclass of one with its own constructor.
    [Theory]
    [MemberData(nameof(AuthenticationTypeData))]
    public void TypeHasNoPublicOrProtectedConstructor(Type type)
    {
        IEnumerable<ConstructorInfo> reachable = type
            .GetConstructors(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)
            .Where(IsReachableFromAnotherAssembly);

        Assert.Empty(reachable);
    }

    // Any other public member producing one of these types would be a factory that bypasses the signature check.
    [Fact]
    public void OnlyAuthenticationProducesTheseTypes()
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
                "ChannelOpening.HelloTimedOut",
                "ChannelOpening.VerifyHello",
                "ChannelOpeningResult.get_Opening",
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
