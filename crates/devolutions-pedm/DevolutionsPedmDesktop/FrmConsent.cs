using System.IO.Pipes;

namespace DevolutionsPedmDesktop
{
    public partial class FrmConsent : Form
    {
        private readonly PipeStream _pipe;

        public FrmConsent(PipeStream pipe, string path)
        {
            InitializeComponent();

            appView.ExePath = path;
            _pipe = pipe;
        }

        private void BtnDeny_Click(object sender, EventArgs e)
        {
            _pipe.WriteByte(0);
            _pipe.Flush();
            Close();
        }

        private void BtnApprove_Click(object sender, EventArgs e)
        {
            _pipe.WriteByte(1);
            _pipe.Flush();
            Close();
        }

        protected override void OnClosed(EventArgs e)
        {
            base.OnClosed(e);

            _pipe?.Dispose();
        }

        private void FrmConsent_FormClosed(object sender, FormClosedEventArgs e)
        {
            _pipe.WriteByte(0);
            _pipe.Flush();
            Close();
        }
    }
}
