namespace DevolutionsPedmDesktop
{
    partial class FrmError
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
            btnOk = new Button();
            ctrlHeader1 = new CtrlHeader();
            SuspendLayout();
            // 
            // btnOk
            // 
            btnOk.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            btnOk.Location = new Point(278, 94);
            btnOk.Name = "btnOk";
            btnOk.Size = new Size(110, 25);
            btnOk.TabIndex = 2;
            btnOk.Text = "Ok";
            btnOk.UseVisualStyleBackColor = true;
            btnOk.Click += BtnOk_Click;
            // 
            // ctrlHeader1
            // 
            ctrlHeader1.BackColor = Color.RosyBrown;
            ctrlHeader1.Dock = DockStyle.Top;
            ctrlHeader1.Location = new Point(0, 0);
            ctrlHeader1.Margin = new Padding(3, 4, 3, 4);
            ctrlHeader1.Name = "ctrlHeader1";
            ctrlHeader1.Size = new Size(400, 80);
            ctrlHeader1.Subtitle = "Error";
            ctrlHeader1.TabIndex = 5;
            // 
            // FrmError
            // 
            AutoScaleDimensions = new SizeF(8F, 20F);
            AutoScaleMode = AutoScaleMode.Font;
            AutoSize = true;
            ClientSize = new Size(400, 131);
            Controls.Add(ctrlHeader1);
            Controls.Add(btnOk);
            FormBorderStyle = FormBorderStyle.None;
            MaximizeBox = false;
            MinimizeBox = false;
            Name = "FrmError";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "Devolutions PEDM";
            ResumeLayout(false);
        }

        #endregion
        private Button btnOk;
        private CtrlHeader ctrlHeader1;
    }
}