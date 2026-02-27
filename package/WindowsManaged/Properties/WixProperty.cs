using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Text;
using WixSharp;

namespace DevolutionsGateway.Properties
{
    internal static class WixProperties
    {
        public static string Decode(this Microsoft.Deployment.WindowsInstaller.Session session, WixProperty<string> prop)
        {
            if (!prop.Encode)
            {
                return session.Property(prop.Id);
            }

            if (string.IsNullOrEmpty(session.Property(prop.EncodedId())))
            {
                return string.Empty;
            }

            byte[] value = Convert.FromBase64String(session.Property(prop.EncodedId()));
            return Encoding.UTF8.GetString(value);
        }

        public static void Encode(this Microsoft.Deployment.WindowsInstaller.Session session, WixProperty<string> prop)
        {
            if (!prop.Encode)
            {
                return;
            }

            string value = session.Property(prop.Id);

            if (string.IsNullOrEmpty(value))
            {
                session[prop.EncodedId()] = string.Empty;
                return;
            }

            session[prop.EncodedId()] = Convert.ToBase64String(Encoding.UTF8.GetBytes(value), Base64FormattingOptions.None);
        }

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
            session[prop.Id] = value?.ToString();
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

            if (typeof(T).IsEnum)
            {
                return (T) Enum.Parse(typeof(T), propertyValue);
            }

            return (T)TypeDescriptor.GetConverter(typeof(T)).ConvertFromInvariantString(propertyValue);
        }
    }

    internal static class WixPropertyExtensions
    {
        // https://www.firegiant.com/docs/wix/v3/tutorial/com-expression-syntax-miscellanea/expression-syntax/

        internal static Condition Equal<T>(this WixProperty<T> property, T value)
        {
            return new Condition($"{property.Id}=\"{value}\"");
        }

        internal static Condition NotEqual<T>(this WixProperty<T> property, T value)
        {
            return new Condition($"{property.Id}<>\"{value}\"");
        }

        internal static string EncodedId(this IWixProperty property)
        {
            return property.Encode ? $"{property.Id}_ENCODED" : property.Id;
        }
    }

    internal interface IWixProperty
    {
        public string DefaultValue { get; }

        public bool Encode { get; }

        public bool Hidden { get; }

        public string Id { get; }

        public string Name { get; }

        public bool Secure { get; }

        public bool Public { get; }

        public Type PropertyType { get; }
    }

    internal class WixProperty<T> : IWixProperty
    {
        public T Default { get; set; }

        public string DefaultValue => Default.ToString();

        public bool Encode { get; set; } = false;

        public bool Hidden { get; set; }

        public string Id { get; set; }

        public string Name { get; set; }

        public bool Secure { get; set; } = false;

        public bool Public { get; set; }
        
        public Type PropertyType => typeof(T);
    }
}
