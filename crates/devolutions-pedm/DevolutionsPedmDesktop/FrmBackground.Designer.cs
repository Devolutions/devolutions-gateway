namespace DevolutionsPedmDesktop
{
    partial class FrmBackground
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            imageFill = new ImageFill();
            SuspendLayout();
            // 
            // imageFill
            // 
            imageFill.Dock = DockStyle.Fill;
            imageFill.Image = null;
            imageFill.Location = new Point(0, 0);
            imageFill.Name = "imageFill";
            imageFill.Size = new Size(460, 375);
            imageFill.TabIndex = 0;
            imageFill.Text = "imageFill1";
            // 
            // FrmBackground
            // 
            AutoScaleMode = AutoScaleMode.None;
            BackColor = SystemColors.Desktop;
            BackgroundImageLayout = ImageLayout.None;
            ClientSize = new Size(460, 375);
            ControlBox = false;
            Controls.Add(imageFill);
            DoubleBuffered = true;
            Enabled = false;
            FormBorderStyle = FormBorderStyle.None;
            MinimizeBox = false;
            Name = "FrmBackground";
            ShowIcon = false;
            ShowInTaskbar = false;
            StartPosition = FormStartPosition.CenterScreen;
            Text = "FrmBackground";
            WindowState = FormWindowState.Maximized;
            ResumeLayout(false);
        }

        #endregion

        private ImageFill imageFill;
    }
}