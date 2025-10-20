using DevolutionsGateway.Controls;
using WixSharp;
using WixSharp.UI.Forms;

namespace WixSharpSetup.Dialogs
{
    partial class CertificateDialog
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

            //this.SelectedCertificate?.Dispose(); TODO: .net48

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
            this.gbExternal = new System.Windows.Forms.GroupBox();
            this.pnlExternal = new System.Windows.Forms.TableLayoutPanel();
            this.butBrowsePrivateKeyFile = new DevolutionsGateway.Controls.FileBrowseButton();
            this.txtPrivateKeyFile = new System.Windows.Forms.TextBox();
            this.txtCertificatePassword = new System.Windows.Forms.TextBox();
            this.lblPrivateKeyFile = new System.Windows.Forms.Label();
            this.lblCertificatePassword = new System.Windows.Forms.Label();
            this.lblCertificateFile = new System.Windows.Forms.Label();
            this.txtCertificateFile = new System.Windows.Forms.TextBox();
            this.butBrowseCertificateFile = new DevolutionsGateway.Controls.FileBrowseButton();
            this.lblHint = new System.Windows.Forms.Label();
            this.lblCertificateFormats = new System.Windows.Forms.Label();
            this.gbSystem = new System.Windows.Forms.GroupBox();
            this.pnlSystem = new System.Windows.Forms.TableLayoutPanel();
            this.lblCertificateDescription = new System.Windows.Forms.Label();
            this.lblSelectedCertificate = new System.Windows.Forms.Label();
            this.cmbSearchBy = new System.Windows.Forms.ComboBox();
            this.label9 = new System.Windows.Forms.Label();
            this.cmbStoreLocation = new System.Windows.Forms.ComboBox();
            this.cmbStore = new System.Windows.Forms.ComboBox();
            this.label8 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.txtSearch = new System.Windows.Forms.TextBox();
            this.butSearchCertificate = new System.Windows.Forms.Button();
            this.butViewCertificate = new System.Windows.Forms.Button();
            this.label5 = new System.Windows.Forms.Label();
            this.cmbCertificateSource = new System.Windows.Forms.ComboBox();
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
            this.gbExternal.SuspendLayout();
            this.pnlExternal.SuspendLayout();
            this.gbSystem.SuspendLayout();
            this.pnlSystem.SuspendLayout();
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
            this.middlePanel.Controls.Add(this.gbExternal);
            this.middlePanel.Controls.Add(this.gbSystem);
            this.middlePanel.Controls.Add(this.label5);
            this.middlePanel.Controls.Add(this.cmbCertificateSource);
            this.middlePanel.Location = new System.Drawing.Point(0, 58);
            this.middlePanel.Name = "middlePanel";
            this.middlePanel.Size = new System.Drawing.Size(494, 261);
            this.middlePanel.TabIndex = 0;
            // 
            // gbExternal
            // 
            this.gbExternal.Controls.Add(this.pnlExternal);
            this.gbExternal.Location = new System.Drawing.Point(12, 34);
            this.gbExternal.Name = "gbExternal";
            this.gbExternal.Size = new System.Drawing.Size(470, 164);
            this.gbExternal.TabIndex = 1;
            this.gbExternal.TabStop = false;
            this.gbExternal.Text = "[BrowseForACertificateToUse]";
            // 
            // pnlExternal
            // 
            this.pnlExternal.ColumnCount = 3;
            this.pnlExternal.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Absolute, 150F));
            this.pnlExternal.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.pnlExternal.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.pnlExternal.Controls.Add(this.butBrowsePrivateKeyFile, 2, 5);
            this.pnlExternal.Controls.Add(this.txtPrivateKeyFile, 1, 5);
            this.pnlExternal.Controls.Add(this.txtCertificatePassword, 1, 3);
            this.pnlExternal.Controls.Add(this.lblPrivateKeyFile, 0, 5);
            this.pnlExternal.Controls.Add(this.lblCertificatePassword, 0, 3);
            this.pnlExternal.Controls.Add(this.lblCertificateFile, 0, 1);
            this.pnlExternal.Controls.Add(this.txtCertificateFile, 1, 1);
            this.pnlExternal.Controls.Add(this.butBrowseCertificateFile, 2, 1);
            this.pnlExternal.Controls.Add(this.lblHint, 1, 6);
            this.pnlExternal.Controls.Add(this.lblCertificateFormats, 1, 2);
            this.pnlExternal.Dock = System.Windows.Forms.DockStyle.Fill;
            this.pnlExternal.Location = new System.Drawing.Point(3, 16);
            this.pnlExternal.Name = "pnlExternal";
            this.pnlExternal.RowCount = 7;
            this.pnlExternal.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlExternal.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlExternal.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Absolute, 40F));
            this.pnlExternal.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlExternal.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlExternal.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlExternal.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlExternal.Size = new System.Drawing.Size(464, 145);
            this.pnlExternal.TabIndex = 8;
            // 
            // butBrowsePrivateKeyFile
            // 
            this.butBrowsePrivateKeyFile.Location = new System.Drawing.Point(434, 105);
            this.butBrowsePrivateKeyFile.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.butBrowsePrivateKeyFile.Name = "butBrowsePrivateKeyFile";
            this.butBrowsePrivateKeyFile.Size = new System.Drawing.Size(27, 20);
            this.butBrowsePrivateKeyFile.TabIndex = 4;
            this.butBrowsePrivateKeyFile.Text = "...";
            this.butBrowsePrivateKeyFile.UseVisualStyleBackColor = true;
            this.butBrowsePrivateKeyFile.Click += new System.EventHandler(this.butBrowsePrivateKeyFile_Click);
            // 
            // txtPrivateKeyFile
            // 
            this.txtPrivateKeyFile.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtPrivateKeyFile.Location = new System.Drawing.Point(153, 105);
            this.txtPrivateKeyFile.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.txtPrivateKeyFile.Name = "txtPrivateKeyFile";
            this.txtPrivateKeyFile.Size = new System.Drawing.Size(275, 20);
            this.txtPrivateKeyFile.TabIndex = 3;
            // 
            // txtCertificatePassword
            // 
            this.pnlExternal.SetColumnSpan(this.txtCertificatePassword, 2);
            this.txtCertificatePassword.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtCertificatePassword.Location = new System.Drawing.Point(153, 71);
            this.txtCertificatePassword.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.txtCertificatePassword.Name = "txtCertificatePassword";
            this.txtCertificatePassword.Size = new System.Drawing.Size(308, 20);
            this.txtCertificatePassword.TabIndex = 2;
            this.txtCertificatePassword.UseSystemPasswordChar = true;
            this.txtCertificatePassword.Visible = false;
            // 
            // lblPrivateKeyFile
            // 
            this.lblPrivateKeyFile.AutoSize = true;
            this.lblPrivateKeyFile.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblPrivateKeyFile.Location = new System.Drawing.Point(3, 105);
            this.lblPrivateKeyFile.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.lblPrivateKeyFile.Name = "lblPrivateKeyFile";
            this.lblPrivateKeyFile.Size = new System.Drawing.Size(144, 26);
            this.lblPrivateKeyFile.TabIndex = 4;
            this.lblPrivateKeyFile.Text = "[CertificateDlgCertKeyFileLabel]";
            this.lblPrivateKeyFile.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // lblCertificatePassword
            // 
            this.lblCertificatePassword.AutoSize = true;
            this.lblCertificatePassword.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblCertificatePassword.Location = new System.Drawing.Point(3, 71);
            this.lblCertificatePassword.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.lblCertificatePassword.Name = "lblCertificatePassword";
            this.lblCertificatePassword.Size = new System.Drawing.Size(144, 26);
            this.lblCertificatePassword.TabIndex = 7;
            this.lblCertificatePassword.Text = "[CertificateDlgCertPasswordLabel]";
            this.lblCertificatePassword.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.lblCertificatePassword.Visible = false;
            // 
            // lblCertificateFile
            // 
            this.lblCertificateFile.AutoSize = true;
            this.lblCertificateFile.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblCertificateFile.Location = new System.Drawing.Point(3, 3);
            this.lblCertificateFile.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.lblCertificateFile.Name = "lblCertificateFile";
            this.lblCertificateFile.Size = new System.Drawing.Size(144, 20);
            this.lblCertificateFile.TabIndex = 1;
            this.lblCertificateFile.Text = "[CertificateDlgCertFileLabel]";
            this.lblCertificateFile.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // txtCertificateFile
            // 
            this.txtCertificateFile.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtCertificateFile.Location = new System.Drawing.Point(153, 3);
            this.txtCertificateFile.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.txtCertificateFile.Name = "txtCertificateFile";
            this.txtCertificateFile.Size = new System.Drawing.Size(275, 20);
            this.txtCertificateFile.TabIndex = 0;
            this.txtCertificateFile.TextChanged += new System.EventHandler(this.txtCertificateFile_TextChanged);
            // 
            // butBrowseCertificateFile
            // 
            this.butBrowseCertificateFile.Location = new System.Drawing.Point(434, 3);
            this.butBrowseCertificateFile.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.butBrowseCertificateFile.Name = "butBrowseCertificateFile";
            this.butBrowseCertificateFile.Size = new System.Drawing.Size(27, 20);
            this.butBrowseCertificateFile.TabIndex = 1;
            this.butBrowseCertificateFile.Text = "...";
            this.butBrowseCertificateFile.UseVisualStyleBackColor = true;
            this.butBrowseCertificateFile.Click += new System.EventHandler(this.butBrowseCertificateFile_Click);
            // 
            // lblHint
            // 
            this.lblHint.AutoSize = true;
            this.pnlExternal.SetColumnSpan(this.lblHint, 2);
            this.lblHint.Dock = System.Windows.Forms.DockStyle.Top;
            this.lblHint.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblHint.ForeColor = System.Drawing.SystemColors.GrayText;
            this.lblHint.Location = new System.Drawing.Point(153, 136);
            this.lblHint.Name = "lblHint";
            this.lblHint.Size = new System.Drawing.Size(308, 13);
            this.lblHint.TabIndex = 8;
            // 
            // lblCertificateFormats
            // 
            this.pnlExternal.SetColumnSpan(this.lblCertificateFormats, 2);
            this.lblCertificateFormats.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblCertificateFormats.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblCertificateFormats.ForeColor = System.Drawing.SystemColors.GrayText;
            this.lblCertificateFormats.Location = new System.Drawing.Point(153, 28);
            this.lblCertificateFormats.Name = "lblCertificateFormats";
            this.lblCertificateFormats.Size = new System.Drawing.Size(308, 40);
            this.lblCertificateFormats.TabIndex = 9;
            this.lblCertificateFormats.Text = "[AnX509CertificateInBinaryOrPemEncoded]";
            // 
            // gbSystem
            // 
            this.gbSystem.Controls.Add(this.pnlSystem);
            this.gbSystem.Location = new System.Drawing.Point(12, 34);
            this.gbSystem.Name = "gbSystem";
            this.gbSystem.Size = new System.Drawing.Size(470, 224);
            this.gbSystem.TabIndex = 18;
            this.gbSystem.TabStop = false;
            this.gbSystem.Text = "[SearchForACertificateToUse]";
            this.gbSystem.Visible = false;
            // 
            // pnlSystem
            // 
            this.pnlSystem.ColumnCount = 3;
            this.pnlSystem.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Absolute, 150F));
            this.pnlSystem.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.pnlSystem.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.pnlSystem.Controls.Add(this.lblCertificateDescription, 1, 5);
            this.pnlSystem.Controls.Add(this.lblSelectedCertificate, 0, 5);
            this.pnlSystem.Controls.Add(this.cmbSearchBy, 1, 2);
            this.pnlSystem.Controls.Add(this.label9, 0, 2);
            this.pnlSystem.Controls.Add(this.cmbStoreLocation, 1, 0);
            this.pnlSystem.Controls.Add(this.cmbStore, 1, 1);
            this.pnlSystem.Controls.Add(this.label8, 0, 3);
            this.pnlSystem.Controls.Add(this.label7, 0, 1);
            this.pnlSystem.Controls.Add(this.label6, 0, 0);
            this.pnlSystem.Controls.Add(this.txtSearch, 1, 3);
            this.pnlSystem.Controls.Add(this.butSearchCertificate, 1, 4);
            this.pnlSystem.Controls.Add(this.butViewCertificate, 2, 5);
            this.pnlSystem.Dock = System.Windows.Forms.DockStyle.Fill;
            this.pnlSystem.Location = new System.Drawing.Point(3, 16);
            this.pnlSystem.Name = "pnlSystem";
            this.pnlSystem.RowCount = 6;
            this.pnlSystem.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlSystem.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlSystem.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlSystem.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlSystem.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.pnlSystem.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.pnlSystem.Size = new System.Drawing.Size(464, 205);
            this.pnlSystem.TabIndex = 9;
            // 
            // lblCertificateDescription
            // 
            this.lblCertificateDescription.AutoSize = true;
            this.lblCertificateDescription.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblCertificateDescription.Location = new System.Drawing.Point(153, 179);
            this.lblCertificateDescription.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.lblCertificateDescription.Name = "lblCertificateDescription";
            this.lblCertificateDescription.Size = new System.Drawing.Size(225, 21);
            this.lblCertificateDescription.TabIndex = 17;
            this.lblCertificateDescription.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // lblSelectedCertificate
            // 
            this.lblSelectedCertificate.AutoSize = true;
            this.lblSelectedCertificate.Dock = System.Windows.Forms.DockStyle.Fill;
            this.lblSelectedCertificate.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.lblSelectedCertificate.ForeColor = System.Drawing.SystemColors.GrayText;
            this.lblSelectedCertificate.Location = new System.Drawing.Point(3, 179);
            this.lblSelectedCertificate.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.lblSelectedCertificate.Name = "lblSelectedCertificate";
            this.lblSelectedCertificate.Size = new System.Drawing.Size(144, 21);
            this.lblSelectedCertificate.TabIndex = 16;
            this.lblSelectedCertificate.Text = "[SelectedCertificate]";
            this.lblSelectedCertificate.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.lblSelectedCertificate.Visible = false;
            // 
            // cmbSearchBy
            // 
            this.pnlSystem.SetColumnSpan(this.cmbSearchBy, 2);
            this.cmbSearchBy.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cmbSearchBy.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbSearchBy.FormattingEnabled = true;
            this.cmbSearchBy.Location = new System.Drawing.Point(153, 61);
            this.cmbSearchBy.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.cmbSearchBy.Name = "cmbSearchBy";
            this.cmbSearchBy.Size = new System.Drawing.Size(308, 21);
            this.cmbSearchBy.TabIndex = 3;
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label9.Location = new System.Drawing.Point(3, 61);
            this.label9.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(144, 21);
            this.label9.TabIndex = 13;
            this.label9.Text = "[SearchBy]";
            this.label9.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // cmbStoreLocation
            // 
            this.pnlSystem.SetColumnSpan(this.cmbStoreLocation, 2);
            this.cmbStoreLocation.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cmbStoreLocation.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbStoreLocation.FormattingEnabled = true;
            this.cmbStoreLocation.Location = new System.Drawing.Point(153, 3);
            this.cmbStoreLocation.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.cmbStoreLocation.Name = "cmbStoreLocation";
            this.cmbStoreLocation.Size = new System.Drawing.Size(308, 21);
            this.cmbStoreLocation.TabIndex = 1;
            // 
            // cmbStore
            // 
            this.pnlSystem.SetColumnSpan(this.cmbStore, 2);
            this.cmbStore.Dock = System.Windows.Forms.DockStyle.Fill;
            this.cmbStore.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbStore.FormattingEnabled = true;
            this.cmbStore.Location = new System.Drawing.Point(153, 32);
            this.cmbStore.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.cmbStore.Name = "cmbStore";
            this.cmbStore.Size = new System.Drawing.Size(308, 21);
            this.cmbStore.TabIndex = 2;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label8.Location = new System.Drawing.Point(3, 90);
            this.label8.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(144, 20);
            this.label8.TabIndex = 2;
            this.label8.Text = "[Search]";
            this.label8.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label7.Location = new System.Drawing.Point(3, 32);
            this.label7.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(144, 21);
            this.label7.TabIndex = 1;
            this.label7.Text = "[CertificateStore]";
            this.label7.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Dock = System.Windows.Forms.DockStyle.Fill;
            this.label6.Location = new System.Drawing.Point(3, 3);
            this.label6.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(144, 21);
            this.label6.TabIndex = 0;
            this.label6.Text = "[StoreLocation]";
            this.label6.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            // 
            // txtSearch
            // 
            this.pnlSystem.SetColumnSpan(this.txtSearch, 2);
            this.txtSearch.Dock = System.Windows.Forms.DockStyle.Fill;
            this.txtSearch.Location = new System.Drawing.Point(153, 90);
            this.txtSearch.Margin = new System.Windows.Forms.Padding(3, 3, 3, 5);
            this.txtSearch.Name = "txtSearch";
            this.txtSearch.Size = new System.Drawing.Size(308, 20);
            this.txtSearch.TabIndex = 4;
            this.txtSearch.TextChanged += new System.EventHandler(this.txtSubjectName_TextChanged);
            // 
            // butSearchCertificate
            // 
            this.butSearchCertificate.AutoSize = true;
            this.pnlSystem.SetColumnSpan(this.butSearchCertificate, 2);
            this.butSearchCertificate.Location = new System.Drawing.Point(153, 118);
            this.butSearchCertificate.Name = "butSearchCertificate";
            this.butSearchCertificate.Size = new System.Drawing.Size(88, 23);
            this.butSearchCertificate.TabIndex = 5;
            this.butSearchCertificate.Text = "[SearchButton]";
            this.butSearchCertificate.UseVisualStyleBackColor = true;
            this.butSearchCertificate.Click += new System.EventHandler(this.butSearchCertificate_Click);
            // 
            // butViewCertificate
            // 
            this.butViewCertificate.AutoSize = true;
            this.butViewCertificate.Location = new System.Drawing.Point(384, 179);
            this.butViewCertificate.Name = "butViewCertificate";
            this.butViewCertificate.Size = new System.Drawing.Size(77, 23);
            this.butViewCertificate.TabIndex = 6;
            this.butViewCertificate.Text = "[ViewButton]";
            this.butViewCertificate.UseVisualStyleBackColor = true;
            this.butViewCertificate.Visible = false;
            this.butViewCertificate.Click += new System.EventHandler(this.butViewCertificate_Click);
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(11, 10);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(94, 13);
            this.label5.TabIndex = 4;
            this.label5.Text = "[CertificateSource]";
            // 
            // cmbCertificateSource
            // 
            this.cmbCertificateSource.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbCertificateSource.FormattingEnabled = true;
            this.cmbCertificateSource.Location = new System.Drawing.Point(123, 7);
            this.cmbCertificateSource.Name = "cmbCertificateSource";
            this.cmbCertificateSource.Size = new System.Drawing.Size(178, 21);
            this.cmbCertificateSource.TabIndex = 0;
            this.cmbCertificateSource.SelectedIndexChanged += new System.EventHandler(this.cmbCertificateSource_SelectedIndexChanged);
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
            this.label2.Text = "[CertificateDlgDescription]";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.ForeColor = System.Drawing.SystemColors.HighlightText;
            this.label1.Location = new System.Drawing.Point(11, 8);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(117, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "[CertificateDlgTitle]";
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
            // CertificateDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.ClientSize = new System.Drawing.Size(494, 361);
            this.Controls.Add(this.middlePanel);
            this.Controls.Add(this.topBorder);
            this.Controls.Add(this.topPanel);
            this.Controls.Add(this.bottomPanel);
            this.Name = "CertificateDialog";
            this.Load += new System.EventHandler(this.OnLoad);
            this.contextMenuStrip1.ResumeLayout(false);
            this.middlePanel.ResumeLayout(false);
            this.middlePanel.PerformLayout();
            this.gbExternal.ResumeLayout(false);
            this.pnlExternal.ResumeLayout(false);
            this.pnlExternal.PerformLayout();
            this.gbSystem.ResumeLayout(false);
            this.pnlSystem.ResumeLayout(false);
            this.pnlSystem.PerformLayout();
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
        private FileBrowseButton butBrowseCertificateFile;
        private System.Windows.Forms.Label lblCertificateFile;
        private System.Windows.Forms.TextBox txtCertificateFile;
        private System.Windows.Forms.TableLayoutPanel pnlExternal;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.ComboBox cmbCertificateSource;
        private System.Windows.Forms.TableLayoutPanel pnlSystem;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Button butSearchCertificate;
        private System.Windows.Forms.ComboBox cmbStoreLocation;
        private System.Windows.Forms.ComboBox cmbStore;
        private System.Windows.Forms.TextBox txtSearch;
        private System.Windows.Forms.ComboBox cmbSearchBy;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.Label lblSelectedCertificate;
        private System.Windows.Forms.Button butViewCertificate;
        private System.Windows.Forms.Label lblCertificateDescription;
        private System.Windows.Forms.GroupBox gbSystem;
        private System.Windows.Forms.GroupBox gbExternal;
        private System.Windows.Forms.Label lblHint;
        private FileBrowseButton butBrowsePrivateKeyFile;
        private System.Windows.Forms.TextBox txtPrivateKeyFile;
        private System.Windows.Forms.TextBox txtCertificatePassword;
        private System.Windows.Forms.Label lblPrivateKeyFile;
        private System.Windows.Forms.Label lblCertificatePassword;
        private System.Windows.Forms.Label lblCertificateFormats;
    }
}
