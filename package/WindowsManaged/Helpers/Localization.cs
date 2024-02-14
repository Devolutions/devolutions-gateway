using System;
using System.Linq;
using System.Windows.Forms;
using WixSharp;
using static System.Windows.Forms.LinkLabel;

namespace DevolutionsGateway.Helpers
{
    internal static class LocalizationExtensions
    {
        internal static void Source<T>(this ComboBox comboBox, MsiRuntime runtime) where T : Enum
        {
            comboBox.DisplayMember = nameof(NamedItem<T>.Name);
            comboBox.ValueMember = nameof(NamedItem<T>.Value);
            comboBox.DataSource = new DisplayEnum<T>(runtime).Items.ToArray();
        }

        internal static T Selected<T>(this ComboBox comboBox) where T : Enum => ((NamedItem<T>)comboBox.SelectedItem).Value;

        internal static void SetSelected<T>(this ComboBox comboBox, T value) where T : Enum => comboBox.SelectedValue = value;

        internal static void SetLink(this LinkLabel label, MsiRuntime runtime, string labelFormat, params string[] linkText)
        {
            string linkFormat = $"[{labelFormat}]".LocalizeWith(runtime.Localize);

            object[] localizedLinkText = new object[linkText.Length];

            for (int i = 0; i < linkText.Length; i++)
            {
                localizedLinkText[i] = $"[{linkText[i]}]".LocalizeWith(runtime.Localize);
            }
            
            label.Text = string.Format(linkFormat, localizedLinkText);

            for (int i = 0; i < localizedLinkText.Length; i++)
            {
                string localizedLink = localizedLinkText[i].ToString();
                Link link = new Link(label.Text.IndexOf(localizedLink, StringComparison.CurrentCulture),
                    localizedLink.Length);
                link.Tag = linkText[i];
                label.Links.Add(link);
            }
        }
    }
}
