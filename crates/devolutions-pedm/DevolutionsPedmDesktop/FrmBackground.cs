using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TrayNotify;

namespace DevolutionsPedmDesktop
{
    public partial class FrmBackground : Form
    {
        public FrmBackground(Screen screen, Bitmap background)
        {
            InitializeComponent();

            this.imageFill.Image = background;

            this.Location = screen.WorkingArea.Location;
        }
    }
}
