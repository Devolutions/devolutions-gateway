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

namespace DevolutionsPedmDesktop
{
    public partial class CtrlHeader : UserControl
    {
        public string Subtitle
        {
            get => lblSubtitle.Text;
            set => lblSubtitle.Text = value;
        }

        public CtrlHeader()
        {
            InitializeComponent();
        }
    }
}
