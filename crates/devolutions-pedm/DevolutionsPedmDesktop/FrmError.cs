using System.ComponentModel;

namespace DevolutionsPedmDesktop
{
    public partial class FrmError : Form
    {
        public FrmError(Win32Exception ex)
        {
            InitializeComponent();

            this.ctrlHeader1.Subtitle = ex.Message;
        }

        private void BtnOk_Click(object sender, EventArgs e)
        {
            Close();
        }
    }
}
