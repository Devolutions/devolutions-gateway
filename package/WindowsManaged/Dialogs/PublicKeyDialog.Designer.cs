using DevolutionsGateway.Controls;
using WixSharp;
using WixSharp.UI.Forms;

namespace WixSharpSetup.Dialogs
{
    partial class PublicKeyDialog
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
            this.lblKeysDescription = new System.Windows.Forms.Label();
            this.butBrowsePrivateKeyFile = new FileBrowseButton();
            this.txtPrivateKeyFile = new System.Windows.Forms.TextBox();
            this.lblPrivateKeyFile = new System.Windows.Forms.Label();
            this.lblPrivateKeyDescription = new System.Windows.Forms.Label();
            this.lblPublicKeyDescription = new System.Windows.Forms.Label();
            this.butBrowsePublicKeyFile = new FileBrowseButton();
            this.lblPublicKeyFile = new System.Windows.Forms.Label();
            this.txtPublicKeyFile = new System.Windows.Forms.TextBox();
            this.lnkKeyHint = new System.Windows.Forms.LinkLabel();
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
            this.middlePanel.Size = new System.Drawing.Size(494, 261);
            this.middlePanel.TabIndex = 0;
            // 
            // tableLayoutPanel2
            // 
            this.tableLayoutPanel2.ColumnCount = 3;
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Absolute, 150F));
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel2.Controls.Add(this.lblKeysDescription, 0, 0);
            this.tableLayoutPanel2.Controls.Add(this.butBrowsePrivateKeyFile, 2, 3);
            this.tableLayoutPanel2.Controls.Add(this.txtPrivateKeyFile, 1, 3);
            this.tableLayoutPanel2.Controls.Add(this.lblPrivateKeyFile, 0, 3);
            this.tableLayoutPanel2.Controls.Add(this.lblPrivateKeyDescription, 0, 4);
            this.tableLayoutPanel2.Controls.Add(this.lblPublicKeyDescription, 0, 2);
            this.tableLayoutPanel2.Controls.Add(this.butBrowsePublicKeyFile, 2, 1);
            this.tableLayoutPanel2.Controls.Add(this.lblPublicKeyFile, 0, 1);
            this.tableLayoutPanel2.Controls.Add(this.txtPublicKeyFile, 1, 1);
            this.tableLayoutPanel2.Controls.Add(this.lnkKeyHint, 0, 5);
            this.tableLayoutPanel2.Location = new System.Drawing.Point(22, 17);
            this.tableLayoutPanel2.Name = "tableLayoutPanel2";
            this.tableLayoutPanel2.RowCount = 6;
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 40F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 40F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 40F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.Size = new System.Drawing.Size(449, 219);
            this.tableLayoutPanel2.TabIndex = 2;
            // 
            // lblKeysDescription
            // 
            this.tableLayoutPanel2.SetColumnSpan(this.lblKeysDescription, 3);
            this.lblKeysDescription.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblKeysDescription.ForeColor = System.Drawing.SystemColors.GrayText;
            this.lblKeysDescription.Location = new System.Drawing.Point(3, 0);
            this.lblKeysDescription.Margin = new System.Windows.Forms.Padding(3, 0, 3, 5);
            this.lblKeysDescription.Name = "lblKeysDescription";
            this.lblKeysDescription.Size = new System.Drawing.Size(443, 35);
            this.lblKeysDescription.TabIndex = 15;
            this.lblKeysDescription.Text = "[ProvideAnEncryptionKeyPairForTokenVerification]";
            // 
            // butBrowsePrivateKeyFile
            // 
            this.butBrowsePrivateKeyFile.Location = new System.Drawing.Point(419, 111);
            this.butBrowsePrivateKeyFile.Name = "butBrowsePrivateKeyFile";
            this.butBrowsePrivateKeyFile.Size = new System.Drawing.Size(27, 20);
            this.butBrowsePrivateKeyFile.TabIndex = 3;
            this.butBrowsePrivateKeyFile.Text = "...";
            this.butBrowsePrivateKeyFile.UseVisualStyleBackColor = true;
            this.butBrowsePrivateKeyFile.Click += new System.EventHandler(this.butBrowsePrivateKeyFile_Click);
            // 
            // txtPrivateKeyFile
            // 
            this.txtPrivateKeyFile.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtPrivateKeyFile.Location = new System.Drawing.Point(153, 111);
            this.txtPrivateKeyFile.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.txtPrivateKeyFile.Name = "txtPrivateKeyFile";
            this.txtPrivateKeyFile.Size = new System.Drawing.Size(260, 20);
            this.txtPrivateKeyFile.TabIndex = 2;
            // 
            // lblPrivateKeyFile
            // 
            this.lblPrivateKeyFile.AutoSize = true;
            this.lblPrivateKeyFile.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPrivateKeyFile.Location = new System.Drawing.Point(3, 108);
            this.lblPrivateKeyFile.Margin = new System.Windows.Forms.Padding(3, 0, 3, 5);
            this.lblPrivateKeyFile.Name = "lblPrivateKeyFile";
            this.lblPrivateKeyFile.Size = new System.Drawing.Size(144, 23);
            this.lblPrivateKeyFile.TabIndex = 3;
            this.lblPrivateKeyFile.Text = "[PrivateKeyFile]";
            this.lblPrivateKeyFile.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // lblPrivateKeyDescription
            // 
            this.tableLayoutPanel2.SetColumnSpan(this.lblPrivateKeyDescription, 3);
            this.lblPrivateKeyDescription.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPrivateKeyDescription.ForeColor = System.Drawing.SystemColors.GrayText;
            this.lblPrivateKeyDescription.Location = new System.Drawing.Point(3, 139);
            this.lblPrivateKeyDescription.Margin = new System.Windows.Forms.Padding(3);
            this.lblPrivateKeyDescription.Name = "lblPrivateKeyDescription";
            this.lblPrivateKeyDescription.Size = new System.Drawing.Size(443, 34);
            this.lblPrivateKeyDescription.TabIndex = 2;
            this.lblPrivateKeyDescription.Text = "[ThePrivateKeyIsUsedTo]";
            // 
            // lblPublicKeyDescription
            // 
            this.tableLayoutPanel2.SetColumnSpan(this.lblPublicKeyDescription, 3);
            this.lblPublicKeyDescription.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPublicKeyDescription.ForeColor = System.Drawing.SystemColors.GrayText;
            this.lblPublicKeyDescription.Location = new System.Drawing.Point(3, 71);
            this.lblPublicKeyDescription.Margin = new System.Windows.Forms.Padding(3);
            this.lblPublicKeyDescription.Name = "lblPublicKeyDescription";
            this.lblPublicKeyDescription.Size = new System.Drawing.Size(443, 34);
            this.lblPublicKeyDescription.TabIndex = 0;
            this.lblPublicKeyDescription.Text = "[ThePublicKeyIsUsedTo]";
            // 
            // butBrowsePublicKeyFile
            // 
            this.butBrowsePublicKeyFile.Location = new System.Drawing.Point(419, 43);
            this.butBrowsePublicKeyFile.Name = "butBrowsePublicKeyFile";
            this.butBrowsePublicKeyFile.Size = new System.Drawing.Size(27, 20);
            this.butBrowsePublicKeyFile.TabIndex = 1;
            this.butBrowsePublicKeyFile.Text = "...";
            this.butBrowsePublicKeyFile.UseVisualStyleBackColor = true;
            this.butBrowsePublicKeyFile.Click += new System.EventHandler(this.butBrowsePublicKeyFile_Click);
            // 
            // lblPublicKeyFile
            // 
            this.lblPublicKeyFile.AutoSize = true;
            this.lblPublicKeyFile.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPublicKeyFile.Location = new System.Drawing.Point(3, 40);
            this.lblPublicKeyFile.Margin = new System.Windows.Forms.Padding(3, 0, 3, 5);
            this.lblPublicKeyFile.Name = "lblPublicKeyFile";
            this.lblPublicKeyFile.Size = new System.Drawing.Size(144, 23);
            this.lblPublicKeyFile.TabIndex = 1;
            this.lblPublicKeyFile.Text = "[PublicKeyFile]";
            this.lblPublicKeyFile.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // txtPublicKeyFile
            // 
            this.txtPublicKeyFile.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtPublicKeyFile.Location = new System.Drawing.Point(153, 43);
            this.txtPublicKeyFile.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.txtPublicKeyFile.Name = "txtPublicKeyFile";
            this.txtPublicKeyFile.Size = new System.Drawing.Size(260, 20);
            this.txtPublicKeyFile.TabIndex = 0;
            // 
            // lnkKeyHint
            // 
            this.tableLayoutPanel2.SetColumnSpan(this.lnkKeyHint, 3);
            this.lnkKeyHint.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lnkKeyHint.Location = new System.Drawing.Point(3, 176);
            this.lnkKeyHint.Name = "lnkKeyHint";
            this.lnkKeyHint.Size = new System.Drawing.Size(443, 43);
            this.lnkKeyHint.TabIndex = 16;
            this.lnkKeyHint.TabStop = true;
            this.lnkKeyHint.Text = "Find the public key file for Devolutions Server or Devolutions Hub";
            this.lnkKeyHint.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.lnkKeyHint.Visible = false;
            this.lnkKeyHint.LinkClicked += new System.Windows.Forms.LinkLabelLinkClickedEventHandler(this.lnkKeyHint_LinkClicked);
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
            this.label2.Size = new System.Drawing.Size(129, 13);
            this.label2.TabIndex = 1;
            this.label2.Text = "[PublicKeyDlgDescription]";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.ForeColor = System.Drawing.SystemColors.HighlightText;
            this.label1.Location = new System.Drawing.Point(11, 8);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(115, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "[PublicKeyDlgTitle]";
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
            // 
            // PublicKeyDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.ClientSize = new System.Drawing.Size(494, 361);
            this.Controls.Add(this.middlePanel);
            this.Controls.Add(this.topBorder);
            this.Controls.Add(this.topPanel);
            this.Controls.Add(this.bottomPanel);
            this.Name = "PublicKeyDialog";
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
        private System.Windows.Forms.TextBox txtPublicKeyFile;
        private FileBrowseButton butBrowsePublicKeyFile;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel2;
        private FileBrowseButton butBrowsePrivateKeyFile;
        private System.Windows.Forms.TextBox txtPrivateKeyFile;
        private System.Windows.Forms.Label lblPrivateKeyFile;
        private System.Windows.Forms.Label lblPrivateKeyDescription;
        private System.Windows.Forms.Label lblPublicKeyDescription;
        private System.Windows.Forms.Label lblPublicKeyFile;
        private System.Windows.Forms.Label lblKeysDescription;
        private System.Windows.Forms.LinkLabel lnkKeyHint;
    }
}
