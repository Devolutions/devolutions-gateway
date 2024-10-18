using System;
using System.Collections.Generic;
using WixSharp;

namespace DevolutionsAgent.Helpers
{
    internal class NamedItem<T>
    {
        public NamedItem(string name, T value)
        {
            this.Name = name;
            this.Value = value;
        }

        public string Name { get; }

        public T Value { get; }

        public override string ToString()
        {
            return this.Name;
        }
    }

    internal class DisplayEnum<T> where T : Enum
    {
        private readonly MsiRuntime runtime;

        private IEnumerable<T> Values => (T[])Enum.GetValues(typeof(T));

        internal IEnumerable<NamedItem<T>> Items
        {
            get
            {
                Func<string, string> fnLocalize = this.runtime.Localize;
                string enumName = typeof(T).Name;

                foreach (T value in this.Values)
                {
                    string key = $"{enumName}_{value}";
                    string name = $"[{key}]".LocalizeWith(fnLocalize);

                    if (name.Equals(key))
                    {
                        name = Enum.GetName(typeof(T), value);
                    }

                    yield return new NamedItem<T>(name, value);
                }
            }
        }

        public DisplayEnum(MsiRuntime runtime)
        {
            this.runtime = runtime;
        }
    }
}
