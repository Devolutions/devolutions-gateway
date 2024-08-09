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
            this.lblApplication = new System.Windows.Forms.Label();
            this.lblPath = new System.Windows.Forms.Label();
            this.imgIcon = new System.Windows.Forms.PictureBox();
            ((System.ComponentModel.ISupportInitialize)(this.imgIcon)).BeginInit();
            this.SuspendLayout();
            // 
            // lblApplication
            // 
            this.lblApplication.AutoSize = true;
            this.lblApplication.Font = new System.Drawing.Font("Segoe UI", 12F);
            this.lblApplication.Location = new System.Drawing.Point(131, 21);
            this.lblApplication.Name = "lblApplication";
            this.lblApplication.Size = new System.Drawing.Size(52, 21);
            this.lblApplication.TabIndex = 0;
            this.lblApplication.Text = "label1";
            // 
            // lblPath
            // 
            this.lblPath.AutoSize = true;
            this.lblPath.Font = new System.Drawing.Font("Segoe UI", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblPath.Location = new System.Drawing.Point(131, 44);
            this.lblPath.Name = "lblPath";
            this.lblPath.Size = new System.Drawing.Size(43, 17);
            this.lblPath.TabIndex = 1;
            this.lblPath.Text = "label1";
            // 
            // imgIcon
            // 
            this.imgIcon.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left)));
            this.imgIcon.Location = new System.Drawing.Point(23, 21);
            this.imgIcon.Name = "imgIcon";
            this.imgIcon.Size = new System.Drawing.Size(91, 85);
            this.imgIcon.SizeMode = System.Windows.Forms.PictureBoxSizeMode.Zoom;
            this.imgIcon.TabIndex = 2;
            this.imgIcon.TabStop = false;
            // 
            // AppView
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.imgIcon);
            this.Controls.Add(this.lblPath);
            this.Controls.Add(this.lblApplication);
            this.Name = "AppView";
            this.Size = new System.Drawing.Size(457, 128);
            ((System.ComponentModel.ISupportInitialize)(this.imgIcon)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private Label lblApplication;
        private Label lblPath;
        private PictureBox imgIcon;
    }
}
