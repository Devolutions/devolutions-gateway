using System;
using System.Diagnostics;
using WixSharp;

namespace DevolutionsGateway.Properties
{
    internal static class WixProperties
    {
        public static T Get<T>(this Microsoft.Deployment.WindowsInstaller.Session session, WixProperty<T> prop)
        {
            Debug.Assert(session is not null);

            string propertyValue = session.Property(prop.Id);

            return GetPropertyValue<T>(propertyValue);
        }

        public static T Get<T>(this ISession session, WixProperty<T> prop)
        {
            Debug.Assert(session is not null);

            string propertyValue = session.Property(prop.Id);

            return GetPropertyValue<T>(propertyValue);
        }

        public static void Set<T>(this Microsoft.Deployment.WindowsInstaller.Session session, WixProperty<T> prop, T value)
        {
            session[prop.Id] = value.ToString();
        }

        public static void Set<T>(this ISession session, WixProperty<T> prop, T value)
        {
            session[prop.Id] = value.ToString();
        }

        public static Property ToWixSharpProperty(this IWixProperty property)
        {
            return new(property.Id)
            {
                Value = property.DefaultValue,
                Hidden = property.Hidden,
                Secure = property.Secure,
            };
        }

        internal static T GetPropertyValue<T>(string propertyValue)
        {
            if (string.IsNullOrWhiteSpace(propertyValue))
            {
                return default;
            }

            var type = Nullable.GetUnderlyingType(typeof(T)) ?? typeof(T);
            return (T)Convert.ChangeType(propertyValue, type);
        }
    }

    internal interface IWixProperty
    {
        public string DefaultValue { get; }

        public bool Hidden { get; }

        public string Id { get; }

        public bool Secure { get; }
    }

    internal class WixProperty<T> : IWixProperty
    {
        public T Default { get; set; }

        public string DefaultValue => Default.ToString();

        public bool Hidden { get; set; }

        public string Id { get; set; }

        public bool Secure { get; set; } = false;
    }
}
