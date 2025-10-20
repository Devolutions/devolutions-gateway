using System.ComponentModel;
using System.Windows.Forms;
using DevolutionsGateway.Helpers;

namespace DevolutionsGateway.Controls
{
    public class FileBrowseButton : Button
    {
        public FileBrowseButton()
        {
            if (base.Enabled)
            {
                base.Enabled = !SystemInfo.IsServerCore;
            }
        }

        [Browsable(false)]
        [EditorBrowsable(EditorBrowsableState.Never)]
        public new bool Enabled
        {
            get
            {
                if (SystemInfo.IsServerCore)
                {
                    return false;
                }

                return base.Enabled;
            }
            set
            {
                if (!SystemInfo.IsServerCore)
                {
                    base.Enabled = value;
                }
            }
        }
    }
}
