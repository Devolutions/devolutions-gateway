using System.Reflection;

namespace Devolutions.Agent.Identity.Authority.Tests;

// An instance of each type below vouches that its value passed validation,
// so nothing but validation may create one: otherwise a host could pass an unchecked value in its place.
public class ConstructionTests
{
    private static readonly Type[] Validated =
    [
        typeof(AgentMetadata),
        typeof(CertificateSigningRequest),
        typeof(EnrollRequestBody),
        typeof(RenewRequestBody),
        typeof(CheckInRequestBody),
        typeof(ConfirmRequestBody),
    ];

    public static TheoryData<Type> ValidatedTypes => new(Validated);

    // IdentityConfig.Create and KeyStoragePolicy.Create check the host's values and return the instance itself rather
    // than a result.
    public static TheoryData<Type> CheckedTypes => new([.. Validated, typeof(IdentityConfig), typeof(KeyStoragePolicy)]);

    // oracle: mutant a public IdentityConfig constructor that takes already-serialized JSON
    [Theory]
    [MemberData(nameof(CheckedTypes))]
    public void HasNoPublicOrProtectedConstructor(Type type)
    {
        IEnumerable<ConstructorInfo> reachable = type
            .GetConstructors(BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic)
            .Where(constructor => constructor.IsPublic || constructor.IsFamily || constructor.IsFamilyOrAssembly);

        Assert.Empty(reachable);
        Assert.True(type.IsSealed);
    }

    // Validation returns a result that holds the instance,
    // so a public static member returning the type itself would be another factory.
    // oracle: mutant a public AgentMetadata factory that skips validation
    [Theory]
    [MemberData(nameof(ValidatedTypes))]
    public void NoPublicStaticMemberReturnsTheType(Type type)
    {
        IEnumerable<MemberInfo> factories = typeof(AgentMetadata).Assembly
            .GetExportedTypes()
            .SelectMany(exported => exported.GetMembers(BindingFlags.Public | BindingFlags.Static))
            .Where(member => member switch
            {
                MethodInfo method => method.ReturnType == type,
                PropertyInfo property => property.PropertyType == type,
                FieldInfo field => field.FieldType == type,
                _ => false,
            });

        Assert.Empty(factories);
    }
}
