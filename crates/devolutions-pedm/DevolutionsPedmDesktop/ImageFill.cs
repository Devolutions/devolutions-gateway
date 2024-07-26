using System.Numerics;

namespace DevolutionsPedmDesktop
{
    public partial class ImageFill : Control
    {
        public ImageFill()
        {
            SetStyle(ControlStyles.Selectable | ControlStyles.SupportsTransparentBackColor, false);
            SetStyle(ControlStyles.AllPaintingInWmPaint | ControlStyles.OptimizedDoubleBuffer | ControlStyles.Opaque | ControlStyles.UserPaint | ControlStyles.ResizeRedraw, true);
        }

        private Image? _image;
        public Image? Image
        {
            get => _image;
            set
            {
                if (_image == value)
                {
                    return;
                }

                _image = value;
                Invalidate();
            }
        }

        private Vector2 _offset = new Vector2();
        public Vector2 Offset
        {
            get => _offset;
            set
            {
                if (_offset == value)
                {
                    return;
                }

                _offset = value;
                Invalidate();
            }
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);
            if (_image == null)
            {
                e.Graphics.Clear(BackColor);
            }
            else
            {
                Size sourceSize = _image.Size, targetSize = ClientSize;
                float scale = Math.Max((float)targetSize.Width / sourceSize.Width, (float)targetSize.Height / sourceSize.Height);
                var rect = new RectangleF();
                rect.Width = scale * sourceSize.Width;
                rect.Height = scale * sourceSize.Height;
                rect.X = (targetSize.Width - rect.Width) / 2;
                rect.Y = (targetSize.Height - rect.Height) / 2;
                e.Graphics.DrawImage(_image, rect);
            }
        }
    }
}
