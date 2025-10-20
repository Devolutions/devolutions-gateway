using WixSharp;
using WixSharp.UI.Forms;

namespace WixSharpSetup.Dialogs
{
    partial class CustomizeDialog
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
            this.gbConfigure = new System.Windows.Forms.GroupBox();
            this.tableLayoutPanel3 = new System.Windows.Forms.TableLayoutPanel();
            this.chkWebApp = new System.Windows.Forms.CheckBox();
            this.chkGenerateCertificate = new System.Windows.Forms.CheckBox();
            this.chkGenerateKeyPair = new System.Windows.Forms.CheckBox();
            this.chkConfigureNgrok = new System.Windows.Forms.CheckBox();
            this.lnkNgrok = new System.Windows.Forms.LinkLabel();
            this.cmbConfigure = new System.Windows.Forms.ComboBox();
            this.label3 = new System.Windows.Forms.Label();
            this.lblConfigureDescription = new System.Windows.Forms.Label();
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
            this.gbConfigure.SuspendLayout();
            this.tableLayoutPanel3.SuspendLayout();
            this.topPanel.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.banner)).BeginInit();
            this.bottomPanel.SuspendLayout();
            this.tableLayoutPanel1.SuspendLayout();
            this.SuspendLayout();
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.ImageScalingSize = new System.Drawing.Size(32, 32);
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
            this.middlePanel.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.middlePanel.Controls.Add(this.tableLayoutPanel2);
            this.middlePanel.Location = new System.Drawing.Point(0, 58);
            this.middlePanel.Name = "middlePanel";
            this.middlePanel.Size = new System.Drawing.Size(494, 254);
            this.middlePanel.TabIndex = 0;
            // 
            // tableLayoutPanel2
            // 
            this.tableLayoutPanel2.ColumnCount = 2;
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.Controls.Add(this.gbConfigure, 0, 2);
            this.tableLayoutPanel2.Controls.Add(this.cmbConfigure, 1, 0);
            this.tableLayoutPanel2.Controls.Add(this.label3, 0, 0);
            this.tableLayoutPanel2.Controls.Add(this.lblConfigureDescription, 0, 1);
            this.tableLayoutPanel2.Location = new System.Drawing.Point(12, 7);
            this.tableLayoutPanel2.Name = "tableLayoutPanel2";
            this.tableLayoutPanel2.RowCount = 4;
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 40F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.Size = new System.Drawing.Size(470, 241);
            this.tableLayoutPanel2.TabIndex = 14;
            // 
            // gbConfigure
            // 
            this.tableLayoutPanel2.SetColumnSpan(this.gbConfigure, 2);
            this.gbConfigure.Controls.Add(this.tableLayoutPanel3);
            this.gbConfigure.Dock = System.Windows.Forms.DockStyle.Fill;
            this.gbConfigure.Location = new System.Drawing.Point(3, 77);
            this.gbConfigure.Margin = new System.Windows.Forms.Padding(3, 10, 3, 3);
            this.gbConfigure.Name = "gbConfigure";
            this.gbConfigure.Size = new System.Drawing.Size(464, 165);
            this.gbConfigure.TabIndex = 12;
            this.gbConfigure.TabStop = false;
            this.gbConfigure.Text = "[ConfigurationOptions]";
            // 
            // tableLayoutPanel3
            // 
            this.tableLayoutPanel3.ColumnCount = 2;
            this.tableLayoutPanel3.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel3.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel3.Controls.Add(this.chkWebApp, 0, 2);
            this.tableLayoutPanel3.Controls.Add(this.chkGenerateCertificate, 0, 3);
            this.tableLayoutPanel3.Controls.Add(this.chkGenerateKeyPair, 0, 4);
            this.tableLayoutPanel3.Controls.Add(this.chkConfigureNgrok, 0, 0);
            this.tableLayoutPanel3.Controls.Add(this.lnkNgrok, 1, 0);
            this.tableLayoutPanel3.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel3.Location = new System.Drawing.Point(3, 16);
            this.tableLayoutPanel3.Name = "tableLayoutPanel3";
            this.tableLayoutPanel3.RowCount = 6;
            this.tableLayoutPanel3.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel3.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel3.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel3.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel3.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel3.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel3.Size = new System.Drawing.Size(458, 146);
            this.tableLayoutPanel3.TabIndex = 0;
            // 
            // chkWebApp
            // 
            this.chkWebApp.AutoSize = true;
            this.tableLayoutPanel3.SetColumnSpan(this.chkWebApp, 2);
            this.chkWebApp.Dock = System.Windows.Forms.DockStyle.Fill;
            this.chkWebApp.Enabled = false;
            this.chkWebApp.Location = new System.Drawing.Point(10, 26);
            this.chkWebApp.Margin = new System.Windows.Forms.Padding(10, 3, 3, 3);
            this.chkWebApp.Name = "chkWebApp";
            this.chkWebApp.Size = new System.Drawing.Size(445, 17);
            this.chkWebApp.TabIndex = 2;
            this.chkWebApp.Text = "[EnableTheGatewayWebInterface]";
            this.chkWebApp.UseVisualStyleBackColor = true;
            this.chkWebApp.CheckedChanged += new System.EventHandler(this.chkWebApp_CheckedChanged);
            // 
            // chkGenerateCertificate
            // 
            this.chkGenerateCertificate.AutoSize = true;
            this.tableLayoutPanel3.SetColumnSpan(this.chkGenerateCertificate, 2);
            this.chkGenerateCertificate.Dock = System.Windows.Forms.DockStyle.Fill;
            this.chkGenerateCertificate.Enabled = false;
            this.chkGenerateCertificate.Location = new System.Drawing.Point(30, 49);
            this.chkGenerateCertificate.Margin = new System.Windows.Forms.Padding(30, 3, 3, 3);
            this.chkGenerateCertificate.Name = "chkGenerateCertificate";
            this.chkGenerateCertificate.Size = new System.Drawing.Size(425, 17);
            this.chkGenerateCertificate.TabIndex = 3;
            this.chkGenerateCertificate.Text = "[GenerateASelfSignedHttpsCertificate]";
            this.chkGenerateCertificate.UseVisualStyleBackColor = true;
            // 
            // chkGenerateKeyPair
            // 
            this.chkGenerateKeyPair.AutoSize = true;
            this.tableLayoutPanel3.SetColumnSpan(this.chkGenerateKeyPair, 2);
            this.chkGenerateKeyPair.Dock = System.Windows.Forms.DockStyle.Fill;
            this.chkGenerateKeyPair.Enabled = false;
            this.chkGenerateKeyPair.Location = new System.Drawing.Point(30, 72);
            this.chkGenerateKeyPair.Margin = new System.Windows.Forms.Padding(30, 3, 3, 3);
            this.chkGenerateKeyPair.Name = "chkGenerateKeyPair";
            this.chkGenerateKeyPair.Size = new System.Drawing.Size(425, 17);
            this.chkGenerateKeyPair.TabIndex = 4;
            this.chkGenerateKeyPair.Text = "[GenerateEncryptionKeys]";
            this.chkGenerateKeyPair.UseVisualStyleBackColor = true;
            // 
            // chkConfigureNgrok
            // 
            this.chkConfigureNgrok.AutoSize = true;
            this.chkConfigureNgrok.Dock = System.Windows.Forms.DockStyle.Fill;
            this.chkConfigureNgrok.Location = new System.Drawing.Point(10, 3);
            this.chkConfigureNgrok.Margin = new System.Windows.Forms.Padding(10, 3, 3, 3);
            this.chkConfigureNgrok.Name = "chkConfigureNgrok";
            this.chkConfigureNgrok.Size = new System.Drawing.Size(234, 17);
            this.chkConfigureNgrok.TabIndex = 0;
            this.chkConfigureNgrok.Text = "[EnableAccessOverTheInternetUsingNgrok]";
            this.chkConfigureNgrok.UseVisualStyleBackColor = true;
            this.chkConfigureNgrok.CheckedChanged += new System.EventHandler(this.chkConfigureNgrok_CheckedChanged);
            // 
            // lnkNgrok
            // 
            this.lnkNgrok.AutoSize = true;
            this.lnkNgrok.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lnkNgrok.Location = new System.Drawing.Point(257, 3);
            this.lnkNgrok.Margin = new System.Windows.Forms.Padding(10, 3, 3, 3);
            this.lnkNgrok.Name = "lnkNgrok";
            this.lnkNgrok.Size = new System.Drawing.Size(198, 17);
            this.lnkNgrok.TabIndex = 1;
            this.lnkNgrok.TabStop = true;
            this.lnkNgrok.Text = "Visit ngrok.com";
            this.lnkNgrok.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.lnkNgrok.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.lnkNgrok_LinkClicked);
            // 
            // cmbConfigure
            // 
            this.cmbConfigure.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cmbConfigure.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbConfigure.FormattingEnabled = true;
            this.cmbConfigure.Location = new System.Drawing.Point(178, 3);
            this.cmbConfigure.Name = "cmbConfigure";
            this.cmbConfigure.Size = new System.Drawing.Size(289, 21);
            this.cmbConfigure.TabIndex = 0;
            this.cmbConfigure.SelectedIndexChanged += new System.EventHandler(this.cmbConfigure_SelectedIndexChanged);
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label3.Location = new System.Drawing.Point(3, 0);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(169, 27);
            this.label3.TabIndex = 14;
            this.label3.Text = "[ConfigureTheGatewayInstallation]";
            this.label3.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // lblConfigureDescription
            // 
            this.tableLayoutPanel2.SetColumnSpan(this.lblConfigureDescription, 2);
            this.lblConfigureDescription.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblConfigureDescription.ForeColor = System.Drawing.SystemColors.GrayText;
            this.lblConfigureDescription.Location = new System.Drawing.Point(3, 30);
            this.lblConfigureDescription.Margin = new System.Windows.Forms.Padding(3, 3, 3, 0);
            this.lblConfigureDescription.Name = "lblConfigureDescription";
            this.lblConfigureDescription.Size = new System.Drawing.Size(464, 37);
            this.lblConfigureDescription.TabIndex = 15;
            this.lblConfigureDescription.Text = "[RecommendedForMostInstallations]";
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
            this.label2.Size = new System.Drawing.Size(130, 13);
            this.label2.TabIndex = 1;
            this.label2.Text = "[CustomizeDlgDescription]";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.ForeColor = System.Drawing.SystemColors.HighlightText;
            this.label1.Location = new System.Drawing.Point(11, 8);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(116, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "[CustomizeDlgTitle]";
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
            this.back.TabIndex = 1;
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
            this.next.TabIndex = 0;
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
            this.border1.Visible = false;
            // 
            // CustomizeDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.ClientSize = new System.Drawing.Size(494, 361);
            this.Controls.Add(this.middlePanel);
            this.Controls.Add(this.topBorder);
            this.Controls.Add(this.topPanel);
            this.Controls.Add(this.bottomPanel);
            this.Name = "CustomizeDialog";
            this.Load += new System.EventHandler(this.OnLoad);
            this.contextMenuStrip1.ResumeLayout(false);
            this.middlePanel.ResumeLayout(false);
            this.tableLayoutPanel2.ResumeLayout(false);
            this.tableLayoutPanel2.PerformLayout();
            this.gbConfigure.ResumeLayout(false);
            this.tableLayoutPanel3.ResumeLayout(false);
            this.tableLayoutPanel3.PerformLayout();
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
        private System.Windows.Forms.CheckBox chkWebApp;
        private System.Windows.Forms.GroupBox gbConfigure;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel3;
        private System.Windows.Forms.CheckBox chkGenerateCertificate;
        private System.Windows.Forms.CheckBox chkGenerateKeyPair;
        private System.Windows.Forms.CheckBox chkConfigureNgrok;
        private System.Windows.Forms.LinkLabel lnkNgrok;
        private System.Windows.Forms.ComboBox cmbConfigure;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label lblConfigureDescription;
    }
}
