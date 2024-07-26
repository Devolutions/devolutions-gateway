namespace DevolutionsPedmDesktop
{
    partial class AppView
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

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            lblApplication = new Label();
            lblPath = new Label();
            imgIcon = new PictureBox();
            ((System.ComponentModel.ISupportInitialize)imgIcon).BeginInit();
            SuspendLayout();
            // 
            // lblApplication
            // 
            lblApplication.AutoSize = true;
            lblApplication.Font = new Font("Segoe UI", 12F);
            lblApplication.Location = new Point(115, 20);
            lblApplication.Name = "lblApplication";
            lblApplication.Size = new Size(52, 21);
            lblApplication.TabIndex = 0;
            lblApplication.Text = "label1";
            // 
            // lblPath
            // 
            lblPath.AutoSize = true;
            lblPath.Location = new Point(115, 41);
            lblPath.Name = "lblPath";
            lblPath.Size = new Size(38, 15);
            lblPath.TabIndex = 1;
            lblPath.Text = "label1";
            // 
            // imgIcon
            // 
            imgIcon.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left;
            imgIcon.Location = new Point(20, 20);
            imgIcon.Name = "imgIcon";
            imgIcon.Size = new Size(80, 80);
            imgIcon.SizeMode = PictureBoxSizeMode.Zoom;
            imgIcon.TabIndex = 2;
            imgIcon.TabStop = false;
            // 
            // AppView
            // 
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            Controls.Add(imgIcon);
            Controls.Add(lblPath);
            Controls.Add(lblApplication);
            Name = "AppView";
            Size = new Size(400, 120);
            ((System.ComponentModel.ISupportInitialize)imgIcon).EndInit();
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Label lblApplication;
        private Label lblPath;
        private PictureBox imgIcon;
    }
}
