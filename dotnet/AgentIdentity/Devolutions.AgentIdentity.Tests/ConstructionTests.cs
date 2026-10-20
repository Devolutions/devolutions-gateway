using System.Reflection;

namespace Devolutions.AgentIdentity.Tests;

// An instance of each type below vouches that its value passed validation,
// so nothing but validation may create one: otherwise a host could pass unvalidated agent input in its place.
public class ConstructionTests
{
    public static TheoryData<Type> ValidatedTypes => new(
        typeof(AgentMetadata),
        typeof(CertificateSigningRequest),
        typeof(EnrollRequestBody),
        typeof(RenewRequestBody),
        typeof(CheckInRequestBody));

    [Theory]
    [MemberData(nameof(ValidatedTypes))]
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
