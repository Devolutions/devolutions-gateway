using System;
using System.Linq;
using System.Windows.Forms;
using WixSharp;

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

        internal static void SetLink(this LinkLabel label, MsiRuntime runtime, string labelFormat, string linkText)
        {
            string linkFormat = $"[{labelFormat}]".LocalizeWith(runtime.Localize);
            string link = $"[{linkText}]".LocalizeWith(runtime.Localize);

            label.Text = string.Format(linkFormat, link);
            label.LinkArea = new LinkArea(label.Text.IndexOf(link, StringComparison.CurrentCulture), link.Length);

        }
    }
}
