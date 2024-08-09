namespace DevolutionsPedmDesktop
{
    public partial class FrmBackground : Form
    {
        private Bitmap _background;
        public Bitmap Background
        {
            get => _background;
            set
            {
                _background = value;
                SetupBackground();
            }
        }

        public FrmBackground(Screen screen)
        {
            InitializeComponent();

            Location = screen.WorkingArea.Location;
        }


        private void FrmBackground_Resize(object sender, EventArgs e)
        {
            SetupBackground();
        }

        private void FrmBackground_Load(object sender, EventArgs e)
        {
            SetupBackground();
        }

        private void SetupBackground()
        {
            if (_background == null)
            {
                return;
            }

            var width = Math.Min(Width, _background.Width);
            var height = Math.Min(Height, _background.Height);

            var ratio = Math.Max(width / (float)_background.Width, height / (float)_background.Height);

            var fittedSize = new Size((int)Math.Round(_background.Width * ratio), (int)Math.Round(_background.Height * ratio));

            var fitted = new Bitmap(_background, fittedSize);

            BackgroundImage = fitted.Clone(new Rectangle((fitted.Width - Width) / 2, (fitted.Height - Height) / 2, Width, Height), fitted.PixelFormat);
        }
    }
}
