using WixSharp;
using WixSharp.UI.Forms;

namespace WixSharpSetup.Dialogs
{
    partial class SummaryDialog
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
            this.label4 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.label9 = new System.Windows.Forms.Label();
            this.label11 = new System.Windows.Forms.Label();
            this.label12 = new System.Windows.Forms.Label();
            this.lblCertificateLabel = new System.Windows.Forms.Label();
            this.lblCertificateFileLabel = new System.Windows.Forms.Label();
            this.lblCertificatePasswordLabel = new System.Windows.Forms.Label();
            this.lblPrivateKeyLabel = new System.Windows.Forms.Label();
            this.label20 = new System.Windows.Forms.Label();
            this.label21 = new System.Windows.Forms.Label();
            this.lblAccessUri = new System.Windows.Forms.Label();
            this.lblHttpUri = new System.Windows.Forms.Label();
            this.lblTcpUrl = new System.Windows.Forms.Label();
            this.lblPublicKey = new System.Windows.Forms.Label();
            this.lblCertificateFile = new System.Windows.Forms.Label();
            this.lblCertificatePassword = new System.Windows.Forms.Label();
            this.lblPrivateKey = new System.Windows.Forms.Label();
            this.lblServiceStart = new System.Windows.Forms.Label();
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
            this.middlePanel.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.middlePanel.Controls.Add(this.tableLayoutPanel2);
            this.middlePanel.Location = new System.Drawing.Point(22, 75);
            this.middlePanel.Name = "middlePanel";
            this.middlePanel.Size = new System.Drawing.Size(449, 231);
            this.middlePanel.TabIndex = 16;
            // 
            // tableLayoutPanel2
            // 
            this.tableLayoutPanel2.ColumnCount = 2;
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel2.Controls.Add(this.label4, 0, 0);
            this.tableLayoutPanel2.Controls.Add(this.label5, 0, 1);
            this.tableLayoutPanel2.Controls.Add(this.label7, 0, 2);
            this.tableLayoutPanel2.Controls.Add(this.label9, 0, 3);
            this.tableLayoutPanel2.Controls.Add(this.label11, 0, 4);
            this.tableLayoutPanel2.Controls.Add(this.label12, 0, 5);
            this.tableLayoutPanel2.Controls.Add(this.lblCertificateLabel, 0, 6);
            this.tableLayoutPanel2.Controls.Add(this.lblCertificateFileLabel, 0, 7);
            this.tableLayoutPanel2.Controls.Add(this.lblCertificatePasswordLabel, 0, 8);
            this.tableLayoutPanel2.Controls.Add(this.lblPrivateKeyLabel, 0, 9);
            this.tableLayoutPanel2.Controls.Add(this.label20, 0, 11);
            this.tableLayoutPanel2.Controls.Add(this.label21, 0, 10);
            this.tableLayoutPanel2.Controls.Add(this.lblAccessUri, 1, 1);
            this.tableLayoutPanel2.Controls.Add(this.lblHttpUri, 1, 2);
            this.tableLayoutPanel2.Controls.Add(this.lblTcpUrl, 1, 3);
            this.tableLayoutPanel2.Controls.Add(this.lblPublicKey, 1, 5);
            this.tableLayoutPanel2.Controls.Add(this.lblCertificateFile, 1, 7);
            this.tableLayoutPanel2.Controls.Add(this.lblCertificatePassword, 1, 8);
            this.tableLayoutPanel2.Controls.Add(this.lblPrivateKey, 1, 9);
            this.tableLayoutPanel2.Controls.Add(this.lblServiceStart, 1, 11);
            this.tableLayoutPanel2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel2.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel2.Name = "tableLayoutPanel2";
            this.tableLayoutPanel2.RowCount = 13;
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 20F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 20F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 20F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 20F));
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 20F));
            this.tableLayoutPanel2.Size = new System.Drawing.Size(449, 231);
            this.tableLayoutPanel2.TabIndex = 0;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.label4, 2);
            this.label4.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label4.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(3, 3);
            this.label4.Margin = new System.Windows.Forms.Padding(3);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(443, 13);
            this.label4.TabIndex = 1;
            this.label4.Text = "[SummaryDlgListenersLabel]";
            this.label4.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label5.Location = new System.Drawing.Point(3, 20);
            this.label5.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(191, 13);
            this.label5.TabIndex = 2;
            this.label5.Text = "[SummaryDlgAccessUriLabel]";
            this.label5.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label7.Location = new System.Drawing.Point(3, 35);
            this.label7.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(191, 13);
            this.label7.TabIndex = 4;
            this.label7.Text = "[SummaryDlgHTTPLabel]";
            this.label7.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label9.Location = new System.Drawing.Point(3, 50);
            this.label9.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(191, 13);
            this.label9.TabIndex = 6;
            this.label9.Text = "[SummaryDlgTCPLabel]";
            this.label9.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.label11, 2);
            this.label11.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label11.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label11.Location = new System.Drawing.Point(3, 67);
            this.label11.Margin = new System.Windows.Forms.Padding(3);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(443, 13);
            this.label11.TabIndex = 8;
            this.label11.Text = "[SummaryDlgKeyPairLabel]";
            this.label11.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label12.Location = new System.Drawing.Point(3, 84);
            this.label12.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(191, 13);
            this.label12.TabIndex = 9;
            this.label12.Text = "[SummaryDlgPublicKeyLabel]";
            this.label12.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblCertificateLabel
            // 
            this.lblCertificateLabel.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.lblCertificateLabel, 2);
            this.lblCertificateLabel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblCertificateLabel.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblCertificateLabel.Location = new System.Drawing.Point(3, 101);
            this.lblCertificateLabel.Margin = new System.Windows.Forms.Padding(3);
            this.lblCertificateLabel.Name = "lblCertificateLabel";
            this.lblCertificateLabel.Size = new System.Drawing.Size(443, 13);
            this.lblCertificateLabel.TabIndex = 11;
            this.lblCertificateLabel.Text = "[SummaryDlgCertificateLabel]";
            this.lblCertificateLabel.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblCertificateFileLabel
            // 
            this.lblCertificateFileLabel.AutoSize = true;
            this.lblCertificateFileLabel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblCertificateFileLabel.Location = new System.Drawing.Point(3, 118);
            this.lblCertificateFileLabel.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblCertificateFileLabel.Name = "lblCertificateFileLabel";
            this.lblCertificateFileLabel.Size = new System.Drawing.Size(191, 13);
            this.lblCertificateFileLabel.TabIndex = 12;
            this.lblCertificateFileLabel.Text = "[SummaryDlgCertificateFileLabel]";
            this.lblCertificateFileLabel.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblCertificatePasswordLabel
            // 
            this.lblCertificatePasswordLabel.AutoSize = true;
            this.lblCertificatePasswordLabel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblCertificatePasswordLabel.Location = new System.Drawing.Point(3, 133);
            this.lblCertificatePasswordLabel.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblCertificatePasswordLabel.Name = "lblCertificatePasswordLabel";
            this.lblCertificatePasswordLabel.Size = new System.Drawing.Size(191, 13);
            this.lblCertificatePasswordLabel.TabIndex = 14;
            this.lblCertificatePasswordLabel.Text = "[SummaryDlgCertificatePasswordLabel]";
            this.lblCertificatePasswordLabel.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblPrivateKeyLabel
            // 
            this.lblPrivateKeyLabel.AutoSize = true;
            this.lblPrivateKeyLabel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPrivateKeyLabel.Location = new System.Drawing.Point(3, 148);
            this.lblPrivateKeyLabel.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblPrivateKeyLabel.Name = "lblPrivateKeyLabel";
            this.lblPrivateKeyLabel.Size = new System.Drawing.Size(191, 13);
            this.lblPrivateKeyLabel.TabIndex = 16;
            this.lblPrivateKeyLabel.Text = "[SummaryDlgCertificateKeyLabel]";
            this.lblPrivateKeyLabel.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // label20
            // 
            this.label20.AutoSize = true;
            this.label20.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label20.Location = new System.Drawing.Point(3, 182);
            this.label20.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.label20.Name = "label20";
            this.label20.Size = new System.Drawing.Size(191, 18);
            this.label20.TabIndex = 17;
            this.label20.Text = "[ServiceDlgInfoLabel]";
            this.label20.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // label21
            // 
            this.label21.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.label21, 2);
            this.label21.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label21.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label21.Location = new System.Drawing.Point(3, 165);
            this.label21.Margin = new System.Windows.Forms.Padding(3);
            this.label21.Name = "label21";
            this.label21.Size = new System.Drawing.Size(443, 13);
            this.label21.TabIndex = 18;
            this.label21.Text = "[ServiceDlgStartTypeLabel]:";
            this.label21.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblAccessUri
            // 
            this.lblAccessUri.AutoEllipsis = true;
            this.lblAccessUri.AutoSize = true;
            this.lblAccessUri.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblAccessUri.Location = new System.Drawing.Point(200, 20);
            this.lblAccessUri.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblAccessUri.Name = "lblAccessUri";
            this.lblAccessUri.Size = new System.Drawing.Size(246, 13);
            this.lblAccessUri.TabIndex = 19;
            this.lblAccessUri.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblHttpUri
            // 
            this.lblHttpUri.AutoEllipsis = true;
            this.lblHttpUri.AutoSize = true;
            this.lblHttpUri.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblHttpUri.Location = new System.Drawing.Point(200, 35);
            this.lblHttpUri.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblHttpUri.Name = "lblHttpUri";
            this.lblHttpUri.Size = new System.Drawing.Size(246, 13);
            this.lblHttpUri.TabIndex = 20;
            this.lblHttpUri.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblTcpUrl
            // 
            this.lblTcpUrl.AutoEllipsis = true;
            this.lblTcpUrl.AutoSize = true;
            this.lblTcpUrl.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblTcpUrl.Location = new System.Drawing.Point(200, 50);
            this.lblTcpUrl.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblTcpUrl.Name = "lblTcpUrl";
            this.lblTcpUrl.Size = new System.Drawing.Size(246, 13);
            this.lblTcpUrl.TabIndex = 21;
            this.lblTcpUrl.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblPublicKey
            // 
            this.lblPublicKey.AutoEllipsis = true;
            this.lblPublicKey.AutoSize = true;
            this.lblPublicKey.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPublicKey.Location = new System.Drawing.Point(200, 84);
            this.lblPublicKey.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblPublicKey.Name = "lblPublicKey";
            this.lblPublicKey.Size = new System.Drawing.Size(246, 13);
            this.lblPublicKey.TabIndex = 22;
            this.lblPublicKey.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblCertificateFile
            // 
            this.lblCertificateFile.AutoEllipsis = true;
            this.lblCertificateFile.AutoSize = true;
            this.lblCertificateFile.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblCertificateFile.Location = new System.Drawing.Point(200, 118);
            this.lblCertificateFile.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblCertificateFile.Name = "lblCertificateFile";
            this.lblCertificateFile.Size = new System.Drawing.Size(246, 13);
            this.lblCertificateFile.TabIndex = 23;
            this.lblCertificateFile.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblCertificatePassword
            // 
            this.lblCertificatePassword.AutoEllipsis = true;
            this.lblCertificatePassword.AutoSize = true;
            this.lblCertificatePassword.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblCertificatePassword.Location = new System.Drawing.Point(200, 133);
            this.lblCertificatePassword.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblCertificatePassword.Name = "lblCertificatePassword";
            this.lblCertificatePassword.Size = new System.Drawing.Size(246, 13);
            this.lblCertificatePassword.TabIndex = 24;
            this.lblCertificatePassword.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblPrivateKey
            // 
            this.lblPrivateKey.AutoEllipsis = true;
            this.lblPrivateKey.AutoSize = true;
            this.lblPrivateKey.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPrivateKey.Location = new System.Drawing.Point(200, 148);
            this.lblPrivateKey.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblPrivateKey.Name = "lblPrivateKey";
            this.lblPrivateKey.Size = new System.Drawing.Size(246, 13);
            this.lblPrivateKey.TabIndex = 25;
            this.lblPrivateKey.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblServiceStart
            // 
            this.lblServiceStart.AutoEllipsis = true;
            this.lblServiceStart.AutoSize = true;
            this.lblServiceStart.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblServiceStart.Location = new System.Drawing.Point(200, 182);
            this.lblServiceStart.Margin = new System.Windows.Forms.Padding(3, 1, 3, 1);
            this.lblServiceStart.Name = "lblServiceStart";
            this.lblServiceStart.Size = new System.Drawing.Size(246, 18);
            this.lblServiceStart.TabIndex = 26;
            this.lblServiceStart.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
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
            this.label2.Size = new System.Drawing.Size(125, 13);
            this.label2.TabIndex = 1;
            this.label2.Text = "[SummaryDlgDescription]";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.ForeColor = System.Drawing.SystemColors.HighlightText;
            this.label1.Location = new System.Drawing.Point(11, 8);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(109, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "[SummaryDlgTitle]";
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
            // SummaryDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.ClientSize = new System.Drawing.Size(494, 361);
            this.Controls.Add(this.middlePanel);
            this.Controls.Add(this.topBorder);
            this.Controls.Add(this.topPanel);
            this.Controls.Add(this.bottomPanel);
            this.Name = "SummaryDialog";
            this.Text = "[SummaryDlg_Title]";
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
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.Label label12;
        private System.Windows.Forms.Label lblCertificateLabel;
        private System.Windows.Forms.Label lblCertificateFileLabel;
        private System.Windows.Forms.Label lblCertificatePasswordLabel;
        private System.Windows.Forms.Label lblPrivateKeyLabel;
        private System.Windows.Forms.Label label20;
        private System.Windows.Forms.Label label21;
        private System.Windows.Forms.Label lblAccessUri;
        private System.Windows.Forms.Label lblHttpUri;
        private System.Windows.Forms.Label lblTcpUrl;
        private System.Windows.Forms.Label lblPublicKey;
        private System.Windows.Forms.Label lblCertificateFile;
        private System.Windows.Forms.Label lblCertificatePassword;
        private System.Windows.Forms.Label lblPrivateKey;
        private System.Windows.Forms.Label lblServiceStart;
    }
}