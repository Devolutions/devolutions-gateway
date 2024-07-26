namespace DevolutionsPedmDesktop
{
    partial class FrmConsent
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
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
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            btnApprove = new Button();
            btnDeny = new Button();
            appView = new AppView();
            header = new CtrlHeader();
            tableLayoutPanel1 = new TableLayoutPanel();
            tableLayoutPanel1.SuspendLayout();
            SuspendLayout();
            // 
            // btnApprove
            // 
            btnApprove.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
            btnApprove.FlatStyle = FlatStyle.System;
            btnApprove.Font = new Font("Segoe UI", 9F);
            btnApprove.Location = new Point(3, 3);
            btnApprove.Name = "btnApprove";
            btnApprove.Size = new Size(182, 36);
            btnApprove.TabIndex = 1;
            btnApprove.Text = "Approve";
            btnApprove.UseVisualStyleBackColor = true;
            btnApprove.Click += BtnApprove_Click;
            // 
            // btnDeny
            // 
            btnDeny.Anchor = AnchorStyles.Bottom | AnchorStyles.Right;
            btnDeny.FlatStyle = FlatStyle.System;
            btnDeny.Font = new Font("Segoe UI", 9F);
            btnDeny.Location = new Point(191, 3);
            btnDeny.Name = "btnDeny";
            btnDeny.Size = new Size(182, 36);
            btnDeny.TabIndex = 0;
            btnDeny.Text = "Deny";
            btnDeny.UseVisualStyleBackColor = true;
            btnDeny.Click += BtnDeny_Click;
            // 
            // appView
            // 
            appView.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
            appView.ExePath = "C:\\Windows\\System32\\cmd.exe";
            appView.Location = new Point(42, 90);
            appView.Name = "appView";
            appView.Size = new Size(316, 120);
            appView.TabIndex = 2;
            // 
            // header
            // 
            header.BackColor = SystemColors.ActiveCaption;
            header.Dock = DockStyle.Top;
            header.Location = new Point(0, 0);
            header.Name = "header";
            header.Size = new Size(400, 80);
            header.Subtitle = "Do you want to allow this application to make changes to your computer?";
            header.TabIndex = 3;
            // 
            // tableLayoutPanel1
            // 
            tableLayoutPanel1.Anchor = AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
            tableLayoutPanel1.ColumnCount = 2;
            tableLayoutPanel1.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            tableLayoutPanel1.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50F));
            tableLayoutPanel1.Controls.Add(btnApprove, 0, 0);
            tableLayoutPanel1.Controls.Add(btnDeny, 1, 0);
            tableLayoutPanel1.Location = new Point(12, 246);
            tableLayoutPanel1.Name = "tableLayoutPanel1";
            tableLayoutPanel1.RowCount = 1;
            tableLayoutPanel1.RowStyles.Add(new RowStyle(SizeType.Percent, 50F));
            tableLayoutPanel1.Size = new Size(376, 42);
            tableLayoutPanel1.TabIndex = 4;
            // 
            // FrmConsent
            // 
            AcceptButton = btnDeny;
            AutoScaleDimensions = new SizeF(7F, 15F);
            AutoScaleMode = AutoScaleMode.Font;
            CancelButton = btnDeny;
            ClientSize = new Size(400, 300);
            Controls.Add(tableLayoutPanel1);
            Controls.Add(header);
            Controls.Add(appView);
            FormBorderStyle = FormBorderStyle.None;
            MaximizeBox = false;
            MinimizeBox = false;
            Name = "FrmConsent";
            StartPosition = FormStartPosition.CenterScreen;
            Text = "ConsentForm";
            TopMost = true;
            tableLayoutPanel1.ResumeLayout(false);
            ResumeLayout(false);
        }

        #endregion
        private Button btnApprove;
        private Button btnDeny;
        private AppView appView;
        private CtrlHeader header;
        private TableLayoutPanel tableLayoutPanel1;
    }
}
