using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement;

namespace DevolutionsPedmDesktop
{

    public partial class AppView : UserControl
    {
        public string ExePath
        {
            get => lblPath.Text;
            set
            {
                lblPath.Text = value;

                if (value.Length <= 0) return;

                imgIcon.Image = Icon.ExtractAssociatedIcon(value)?.ToBitmap();

                var info = FileVersionInfo.GetVersionInfo(value);
                lblApplication.Text = info.FileDescription;
            }
        }

        public AppView()
        {
            InitializeComponent();
        }
    }
}
