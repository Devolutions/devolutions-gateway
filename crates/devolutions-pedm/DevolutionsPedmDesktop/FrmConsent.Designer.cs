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
            this.btnApprove = new System.Windows.Forms.Button();
            this.btnDeny = new System.Windows.Forms.Button();
            this.tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            this.header = new DevolutionsPedmDesktop.CtrlHeader();
            this.appView = new DevolutionsPedmDesktop.AppView();
            this.tableLayoutPanel1.SuspendLayout();
            this.SuspendLayout();
            // 
            // btnApprove
            // 
            this.btnApprove.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.btnApprove.FlatStyle = System.Windows.Forms.FlatStyle.System;
            this.btnApprove.Font = new System.Drawing.Font("Segoe UI", 9F);
            this.btnApprove.Location = new System.Drawing.Point(3, 4);
            this.btnApprove.Name = "btnApprove";
            this.btnApprove.Size = new System.Drawing.Size(208, 38);
            this.btnApprove.TabIndex = 1;
            this.btnApprove.Text = "Approve";
            this.btnApprove.UseVisualStyleBackColor = true;
            this.btnApprove.Click += new System.EventHandler(this.BtnApprove_Click);
            // 
            // btnDeny
            // 
            this.btnDeny.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.btnDeny.DialogResult = System.Windows.Forms.DialogResult.Cancel;
            this.btnDeny.FlatStyle = System.Windows.Forms.FlatStyle.System;
            this.btnDeny.Font = new System.Drawing.Font("Segoe UI", 9F);
            this.btnDeny.Location = new System.Drawing.Point(219, 4);
            this.btnDeny.Name = "btnDeny";
            this.btnDeny.Size = new System.Drawing.Size(208, 38);
            this.btnDeny.TabIndex = 0;
            this.btnDeny.Text = "Deny";
            this.btnDeny.UseVisualStyleBackColor = true;
            this.btnDeny.Click += new System.EventHandler(this.BtnDeny_Click);
            // 
            // tableLayoutPanel1
            // 
            this.tableLayoutPanel1.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.tableLayoutPanel1.ColumnCount = 2;
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 50F));
            this.tableLayoutPanel1.Controls.Add(this.btnApprove, 0, 0);
            this.tableLayoutPanel1.Controls.Add(this.btnDeny, 1, 0);
            this.tableLayoutPanel1.Location = new System.Drawing.Point(14, 262);
            this.tableLayoutPanel1.Name = "tableLayoutPanel1";
            this.tableLayoutPanel1.RowCount = 1;
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 50F));
            this.tableLayoutPanel1.Size = new System.Drawing.Size(430, 45);
            this.tableLayoutPanel1.TabIndex = 4;
            // 
            // header
            // 
            this.header.AutoSize = true;
            this.header.BackColor = System.Drawing.SystemColors.ActiveCaption;
            this.header.Dock = System.Windows.Forms.DockStyle.Top;
            this.header.Location = new System.Drawing.Point(0, 0);
            this.header.Name = "header";
            this.header.Size = new System.Drawing.Size(457, 63);
            this.header.Subtitle = "Do you want to allow this application to make changes to your computer?";
            this.header.TabIndex = 3;
            // 
            // appView
            // 
            this.appView.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.appView.ExePath = "C:\\Windows\\System32\\cmd.exe";
            this.appView.Location = new System.Drawing.Point(48, 96);
            this.appView.Name = "appView";
            this.appView.Size = new System.Drawing.Size(361, 128);
            this.appView.TabIndex = 2;
            // 
            // FrmConsent
            // 
            this.AcceptButton = this.btnDeny;
            this.AutoScaleDimensions = new System.Drawing.SizeF(8F, 16F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.CancelButton = this.btnDeny;
            this.ClientSize = new System.Drawing.Size(457, 320);
            this.Controls.Add(this.tableLayoutPanel1);
            this.Controls.Add(this.header);
            this.Controls.Add(this.appView);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.Name = "FrmConsent";
            this.ShowIcon = false;
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Devolutions PEDM";
            this.TopMost = true;
            this.FormClosed += new System.Windows.Forms.FormClosedEventHandler(this.FrmConsent_FormClosed);
            this.tableLayoutPanel1.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private Button btnApprove;
        private Button btnDeny;
        private AppView appView;
        private CtrlHeader header;
        private TableLayoutPanel tableLayoutPanel1;
    }
}
