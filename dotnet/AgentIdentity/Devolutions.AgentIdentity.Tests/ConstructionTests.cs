using System.Reflection;

namespace Devolutions.AgentIdentity.Tests;

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
    ];

    public static TheoryData<Type> ValidatedTypes => new(Validated);

    // IdentityConfig.Create checks the host's values and returns the config itself rather than a result.
    public static TheoryData<Type> CheckedTypes => new([.. Validated, typeof(IdentityConfig)]);

    // oracle: self-derived; sole guard for a public IdentityConfig constructor that takes already-serialized JSON.
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
    // oracle: self-derived; sole guard for a public AgentMetadata factory that skips validation.
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
