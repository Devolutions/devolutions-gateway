using WixSharp;
using WixSharp.UI.Forms;

namespace WixSharpSetup.Dialogs
{
    partial class WebClientDialog
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
            this.components = new System.ComponentModel.Container();
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.copyToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.middlePanel = new System.Windows.Forms.Panel();
            this.tableLayoutPanel2 = new System.Windows.Forms.TableLayoutPanel();
            this.lblPassword2 = new System.Windows.Forms.Label();
            this.lblPassword = new System.Windows.Forms.Label();
            this.txtUsername = new System.Windows.Forms.TextBox();
            this.lblUsername = new System.Windows.Forms.Label();
            this.lblDefaultUserDescription = new System.Windows.Forms.Label();
            this.lblPublicKeyDescription = new System.Windows.Forms.Label();
            this.lblAuthentication = new System.Windows.Forms.Label();
            this.cmbAuthentication = new System.Windows.Forms.ComboBox();
            this.txtPassword = new System.Windows.Forms.TextBox();
            this.txtPassword2 = new System.Windows.Forms.TextBox();
            this.topBorder = new System.Windows.Forms.Panel();
            this.topPanel = new System.Windows.Forms.Panel();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.banner = new System.Windows.Forms.PictureBox();
            this.bottomPanel = new System.Windows.Forms.Panel();
            this.tableLayoutPanel1 = new System.Windows.Forms.TableLayoutPanel();
            this.back = new System.Windows.Forms.Button();
            this.next = new System.Windows.Forms.Button();
            this.cancel = new System.Windows.Forms.Button();
            this.border1 = new System.Windows.Forms.Panel();
            this.contextMenuStrip1.SuspendLayout();
            this.middlePanel.SuspendLayout();
            this.tableLayoutPanel2.SuspendLayout();
            this.topPanel.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.banner)).BeginInit();
            this.bottomPanel.SuspendLayout();
            this.tableLayoutPanel1.SuspendLayout();
            this.SuspendLayout();
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.copyToolStripMenuItem});
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(103, 26);
            // 
            // copyToolStripMenuItem
            // 
            this.copyToolStripMenuItem.Name = "copyToolStripMenuItem";
            this.copyToolStripMenuItem.Size = new System.Drawing.Size(102, 22);
            this.copyToolStripMenuItem.Text = "Copy";
            // 
            // middlePanel
            // 
            this.middlePanel.Controls.Add(this.tableLayoutPanel2);
            this.middlePanel.Location = new System.Drawing.Point(0, 58);
            this.middlePanel.Name = "middlePanel";
            this.middlePanel.Size = new System.Drawing.Size(494, 261);
            this.middlePanel.TabIndex = 16;
            // 
            // tableLayoutPanel2
            // 
            this.tableLayoutPanel2.ColumnCount = 3;
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Absolute, 150F));
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel2.Controls.Add(this.lblPassword2, 0, 5);
            this.tableLayoutPanel2.Controls.Add(this.lblPassword, 0, 4);
            this.tableLayoutPanel2.Controls.Add(this.txtUsername, 1, 3);
            this.tableLayoutPanel2.Controls.Add(this.lblUsername, 0, 3);
            this.tableLayoutPanel2.Controls.Add(this.lblDefaultUserDescription, 0, 2);
            this.tableLayoutPanel2.Controls.Add(this.lblPublicKeyDescription, 0, 0);
            this.tableLayoutPanel2.Controls.Add(this.lblAuthentication, 0, 1);
            this.tableLayoutPanel2.Controls.Add(this.cmbAuthentication, 1, 1);
            this.tableLayoutPanel2.Controls.Add(this.txtPassword, 1, 4);
            this.tableLayoutPanel2.Controls.Add(this.txtPassword2, 1, 5);
            this.tableLayoutPanel2.Location = new System.Drawing.Point(22, 17);
            this.tableLayoutPanel2.Name = "tableLayoutPanel2";
            this.tableLayoutPanel2.RowCount = 7;
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.Size = new System.Drawing.Size(449, 216);
            this.tableLayoutPanel2.TabIndex = 2;
            // 
            // lblPassword2
            // 
            this.lblPassword2.AutoSize = true;
            this.lblPassword2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPassword2.Location = new System.Drawing.Point(3, 131);
            this.lblPassword2.Margin = new System.Windows.Forms.Padding(3, 0, 3, 5);
            this.lblPassword2.Name = "lblPassword2";
            this.lblPassword2.Size = new System.Drawing.Size(144, 23);
            this.lblPassword2.TabIndex = 8;
            this.lblPassword2.Text = "Confirm Password";
            this.lblPassword2.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // lblPassword
            // 
            this.lblPassword.AutoSize = true;
            this.lblPassword.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPassword.Location = new System.Drawing.Point(3, 103);
            this.lblPassword.Margin = new System.Windows.Forms.Padding(3, 0, 3, 5);
            this.lblPassword.Name = "lblPassword";
            this.lblPassword.Size = new System.Drawing.Size(144, 23);
            this.lblPassword.TabIndex = 6;
            this.lblPassword.Text = "Password";
            this.lblPassword.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // txtUsername
            // 
            this.txtUsername.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtUsername.Location = new System.Drawing.Point(153, 78);
            this.txtUsername.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.txtUsername.MaxLength = 256;
            this.txtUsername.Name = "txtUsername";
            this.txtUsername.Size = new System.Drawing.Size(293, 20);
            this.txtUsername.TabIndex = 4;
            // 
            // lblUsername
            // 
            this.lblUsername.AutoSize = true;
            this.lblUsername.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblUsername.Location = new System.Drawing.Point(3, 75);
            this.lblUsername.Margin = new System.Windows.Forms.Padding(3, 0, 3, 5);
            this.lblUsername.Name = "lblUsername";
            this.lblUsername.Size = new System.Drawing.Size(144, 23);
            this.lblUsername.TabIndex = 3;
            this.lblUsername.Text = "Username";
            this.lblUsername.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // lblDefaultUserDescription
            // 
            this.lblDefaultUserDescription.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.lblDefaultUserDescription, 3);
            this.lblDefaultUserDescription.Location = new System.Drawing.Point(3, 57);
            this.lblDefaultUserDescription.Margin = new System.Windows.Forms.Padding(3, 10, 3, 5);
            this.lblDefaultUserDescription.Name = "lblDefaultUserDescription";
            this.lblDefaultUserDescription.Size = new System.Drawing.Size(249, 13);
            this.lblDefaultUserDescription.TabIndex = 2;
            this.lblDefaultUserDescription.Text = "Create a default user to access the web application";
            // 
            // lblPublicKeyDescription
            // 
            this.lblPublicKeyDescription.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.lblPublicKeyDescription, 3);
            this.lblPublicKeyDescription.Location = new System.Drawing.Point(3, 0);
            this.lblPublicKeyDescription.Margin = new System.Windows.Forms.Padding(3, 0, 3, 5);
            this.lblPublicKeyDescription.Name = "lblPublicKeyDescription";
            this.lblPublicKeyDescription.Size = new System.Drawing.Size(370, 13);
            this.lblPublicKeyDescription.TabIndex = 0;
            this.lblPublicKeyDescription.Text = "Choose the authentication method used when accessing the web application";
            // 
            // lblAuthentication
            // 
            this.lblAuthentication.AutoSize = true;
            this.lblAuthentication.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblAuthentication.Location = new System.Drawing.Point(3, 18);
            this.lblAuthentication.Margin = new System.Windows.Forms.Padding(3, 0, 3, 5);
            this.lblAuthentication.Name = "lblAuthentication";
            this.lblAuthentication.Size = new System.Drawing.Size(144, 24);
            this.lblAuthentication.TabIndex = 1;
            this.lblAuthentication.Text = "Authentication";
            this.lblAuthentication.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // cmbAuthentication
            // 
            this.cmbAuthentication.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cmbAuthentication.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbAuthentication.FormattingEnabled = true;
            this.cmbAuthentication.Location = new System.Drawing.Point(153, 21);
            this.cmbAuthentication.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.cmbAuthentication.Name = "cmbAuthentication";
            this.cmbAuthentication.Size = new System.Drawing.Size(293, 21);
            this.cmbAuthentication.TabIndex = 5;
            this.cmbAuthentication.SelectedIndexChanged += new System.EventHandler(this.cmbAuthentication_SelectedIndexChanged);
            // 
            // txtPassword
            // 
            this.txtPassword.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtPassword.Location = new System.Drawing.Point(153, 106);
            this.txtPassword.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.txtPassword.MaxLength = 256;
            this.txtPassword.Name = "txtPassword";
            this.txtPassword.Size = new System.Drawing.Size(293, 20);
            this.txtPassword.TabIndex = 7;
            this.txtPassword.UseSystemPasswordChar = true;
            // 
            // txtPassword2
            // 
            this.txtPassword2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtPassword2.Location = new System.Drawing.Point(153, 134);
            this.txtPassword2.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.txtPassword2.MaxLength = 256;
            this.txtPassword2.Name = "txtPassword2";
            this.txtPassword2.Size = new System.Drawing.Size(293, 20);
            this.txtPassword2.TabIndex = 9;
            this.txtPassword2.UseSystemPasswordChar = true;
            // 
            // topBorder
            // 
            this.topBorder.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.topBorder.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.topBorder.Location = new System.Drawing.Point(0, 58);
            this.topBorder.Name = "topBorder";
            this.topBorder.Size = new System.Drawing.Size(494, 1);
            this.topBorder.TabIndex = 15;
            // 
            // topPanel
            // 
            this.topPanel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.topPanel.BackColor = System.Drawing.SystemColors.Control;
            this.topPanel.Controls.Add(this.label2);
            this.topPanel.Controls.Add(this.label1);
            this.topPanel.Controls.Add(this.banner);
            this.topPanel.Location = new System.Drawing.Point(0, 0);
            this.topPanel.Name = "topPanel";
            this.topPanel.Size = new System.Drawing.Size(494, 58);
            this.topPanel.TabIndex = 10;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.BackColor = System.Drawing.Color.Transparent;
            this.label2.ForeColor = System.Drawing.SystemColors.HighlightText;
            this.label2.Location = new System.Drawing.Point(18, 31);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(205, 13);
            this.label2.TabIndex = 1;
            this.label2.Text = "Configure the standalone web application.";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.ForeColor = System.Drawing.SystemColors.HighlightText;
            this.label1.Location = new System.Drawing.Point(11, 8);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(107, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "[WebAppDlgTitle]";
            // 
            // banner
            // 
            this.banner.BackColor = System.Drawing.Color.White;
            this.banner.Location = new System.Drawing.Point(0, 0);
            this.banner.Name = "banner";
            this.banner.Size = new System.Drawing.Size(494, 58);
            this.banner.SizeMode = System.Windows.Forms.PictureBoxSizeMode.StretchImage;
            this.banner.TabIndex = 0;
            this.banner.TabStop = false;
            // 
            // bottomPanel
            // 
            this.bottomPanel.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.bottomPanel.BackColor = System.Drawing.SystemColors.Control;
            this.bottomPanel.Controls.Add(this.tableLayoutPanel1);
            this.bottomPanel.Controls.Add(this.border1);
            this.bottomPanel.Location = new System.Drawing.Point(0, 312);
            this.bottomPanel.Name = "bottomPanel";
            this.bottomPanel.Size = new System.Drawing.Size(494, 49);
            this.bottomPanel.TabIndex = 9;
            // 
            // tableLayoutPanel1
            // 
            this.tableLayoutPanel1.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right)));
            this.tableLayoutPanel1.ColumnCount = 5;
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Absolute, 14F));
            this.tableLayoutPanel1.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel1.Controls.Add(this.back, 1, 0);
            this.tableLayoutPanel1.Controls.Add(this.next, 2, 0);
            this.tableLayoutPanel1.Controls.Add(this.cancel, 4, 0);
            this.tableLayoutPanel1.Location = new System.Drawing.Point(0, 3);
            this.tableLayoutPanel1.Name = "tableLayoutPanel1";
            this.tableLayoutPanel1.RowCount = 1;
            this.tableLayoutPanel1.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel1.Size = new System.Drawing.Size(493, 43);
            this.tableLayoutPanel1.TabIndex = 8;
            // 
            // back
            // 
            this.back.Anchor = System.Windows.Forms.AnchorStyles.Right;
            this.back.AutoSize = true;
            this.back.Location = new System.Drawing.Point(224, 10);
            this.back.MinimumSize = new System.Drawing.Size(75, 0);
            this.back.Name = "back";
            this.back.Size = new System.Drawing.Size(77, 23);
            this.back.TabIndex = 0;
            this.back.Text = "[WixUIBack]";
            this.back.UseVisualStyleBackColor = true;
            this.back.Click += new System.EventHandler(this.Back_Click);
            // 
            // next
            // 
            this.next.Anchor = System.Windows.Forms.AnchorStyles.Right;
            this.next.AutoSize = true;
            this.next.Location = new System.Drawing.Point(307, 10);
            this.next.MinimumSize = new System.Drawing.Size(75, 0);
            this.next.Name = "next";
            this.next.Size = new System.Drawing.Size(77, 23);
            this.next.TabIndex = 1;
            this.next.Text = "[WixUINext]";
            this.next.UseVisualStyleBackColor = true;
            this.next.Click += new System.EventHandler(this.Next_Click);
            // 
            // cancel
            // 
            this.cancel.Anchor = System.Windows.Forms.AnchorStyles.Right;
            this.cancel.AutoSize = true;
            this.cancel.Location = new System.Drawing.Point(404, 10);
            this.cancel.MinimumSize = new System.Drawing.Size(75, 0);
            this.cancel.Name = "cancel";
            this.cancel.Size = new System.Drawing.Size(86, 23);
            this.cancel.TabIndex = 2;
            this.cancel.Text = "[WixUICancel]";
            this.cancel.UseVisualStyleBackColor = true;
            this.cancel.Click += new System.EventHandler(this.Cancel_Click);
            // 
            // border1
            // 
            this.border1.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.border1.Dock = System.Windows.Forms.DockStyle.Top;
            this.border1.Location = new System.Drawing.Point(0, 0);
            this.border1.Name = "border1";
            this.border1.Size = new System.Drawing.Size(494, 1);
            this.border1.TabIndex = 14;
            // 
            // WebClientDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.ClientSize = new System.Drawing.Size(494, 361);
            this.Controls.Add(this.middlePanel);
            this.Controls.Add(this.topBorder);
            this.Controls.Add(this.topPanel);
            this.Controls.Add(this.bottomPanel);
            this.Name = "WebClientDialog";
            this.Text = "[WebAppDlg_Title]";
            this.Load += new System.EventHandler(this.OnLoad);
            this.contextMenuStrip1.ResumeLayout(false);
            this.middlePanel.ResumeLayout(false);
            this.tableLayoutPanel2.ResumeLayout(false);
            this.tableLayoutPanel2.PerformLayout();
            this.topPanel.ResumeLayout(false);
            this.topPanel.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.banner)).EndInit();
            this.bottomPanel.ResumeLayout(false);
            this.tableLayoutPanel1.ResumeLayout(false);
            this.tableLayoutPanel1.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.PictureBox banner;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ToolStripMenuItem copyToolStripMenuItem;
        private System.Windows.Forms.Panel topPanel;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Panel bottomPanel;
        private System.Windows.Forms.Panel border1;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel1;
        private System.Windows.Forms.Button back;
        private System.Windows.Forms.Button next;
        private System.Windows.Forms.Button cancel;
        private System.Windows.Forms.Panel topBorder;
        private System.Windows.Forms.Panel middlePanel;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel2;
        private System.Windows.Forms.TextBox txtUsername;
        private System.Windows.Forms.Label lblUsername;
        private System.Windows.Forms.Label lblDefaultUserDescription;
        private System.Windows.Forms.Label lblPublicKeyDescription;
        private System.Windows.Forms.Label lblAuthentication;
        private System.Windows.Forms.ComboBox cmbAuthentication;
        private System.Windows.Forms.Label lblPassword;
        private System.Windows.Forms.TextBox txtPassword;
        private System.Windows.Forms.Label lblPassword2;
        private System.Windows.Forms.TextBox txtPassword2;
    }
}
