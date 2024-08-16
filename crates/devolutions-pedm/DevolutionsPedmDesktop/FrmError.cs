using System.ComponentModel;

namespace DevolutionsPedmDesktop
{
    public partial class FrmError : Form
    {
        public FrmError(Win32Exception ex)
        {
            InitializeComponent();
            uint cornerPreference = 2;
            WinAPI.DwmSetWindowAttribute(this.Handle, 33, ref cornerPreference, 4);

            this.picError.Image = SystemIcons.Error.ToBitmap();
            this.lblError.Text = $"{ex.Message} (0x{ex.NativeErrorCode.ToString("X8")})";
        }

        private void BtnOk_Click(object sender, EventArgs e)
        {
            Close();
        }
    }
}
