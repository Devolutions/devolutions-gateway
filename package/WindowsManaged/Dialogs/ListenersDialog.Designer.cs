using WixSharp;
using WixSharp.UI.Forms;

namespace WixSharpSetup.Dialogs
{
    partial class ListenersDialog
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
            this.label3 = new System.Windows.Forms.Label();
            this.txtHttpPort = new System.Windows.Forms.TextBox();
            this.cmbHttpProtocol = new System.Windows.Forms.ComboBox();
            this.txtHttpHostname = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.txtTcpPort = new System.Windows.Forms.TextBox();
            this.txtTcpHostname = new System.Windows.Forms.TextBox();
            this.cmbTcpProtocol = new System.Windows.Forms.ComboBox();
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
            this.middlePanel.Location = new System.Drawing.Point(22, 75);
            this.middlePanel.Name = "middlePanel";
            this.middlePanel.Size = new System.Drawing.Size(449, 139);
            this.middlePanel.TabIndex = 16;
            // 
            // tableLayoutPanel2
            // 
            this.tableLayoutPanel2.ColumnCount = 3;
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle());
            this.tableLayoutPanel2.Controls.Add(this.label3, 0, 0);
            this.tableLayoutPanel2.Controls.Add(this.txtHttpPort, 2, 1);
            this.tableLayoutPanel2.Controls.Add(this.cmbHttpProtocol, 0, 1);
            this.tableLayoutPanel2.Controls.Add(this.txtHttpHostname, 1, 1);
            this.tableLayoutPanel2.Controls.Add(this.label4, 0, 3);
            this.tableLayoutPanel2.Controls.Add(this.txtTcpPort, 2, 4);
            this.tableLayoutPanel2.Controls.Add(this.txtTcpHostname, 1, 4);
            this.tableLayoutPanel2.Controls.Add(this.cmbTcpProtocol, 0, 4);
            this.tableLayoutPanel2.Dock = System.Windows.Forms.DockStyle.Fill;
            this.tableLayoutPanel2.Location = new System.Drawing.Point(0, 0);
            this.tableLayoutPanel2.Name = "tableLayoutPanel2";
            this.tableLayoutPanel2.RowCount = 5;
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.Size = new System.Drawing.Size(449, 139);
            this.tableLayoutPanel2.TabIndex = 17;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.label3, 3);
            this.label3.Location = new System.Drawing.Point(3, 3);
            this.label3.Margin = new System.Windows.Forms.Padding(3);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(126, 13);
            this.label3.TabIndex = 6;
            this.label3.Text = "[ListenersDlgHTTPLabel]";
            // 
            // txtHttpPort
            // 
            this.txtHttpPort.Location = new System.Drawing.Point(362, 22);
            this.txtHttpPort.Name = "txtHttpPort";
            this.txtHttpPort.Size = new System.Drawing.Size(40, 20);
            this.txtHttpPort.TabIndex = 2;
            // 
            // cmbHttpProtocol
            // 
            this.cmbHttpProtocol.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbHttpProtocol.FormattingEnabled = true;
            this.cmbHttpProtocol.Location = new System.Drawing.Point(3, 22);
            this.cmbHttpProtocol.Name = "cmbHttpProtocol";
            this.cmbHttpProtocol.Size = new System.Drawing.Size(70, 21);
            this.cmbHttpProtocol.TabIndex = 0;
            // 
            // txtHttpHostname
            // 
            this.txtHttpHostname.Enabled = false;
            this.txtHttpHostname.Location = new System.Drawing.Point(79, 22);
            this.txtHttpHostname.Name = "txtHttpHostname";
            this.txtHttpHostname.Size = new System.Drawing.Size(277, 20);
            this.txtHttpHostname.TabIndex = 1;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.tableLayoutPanel2.SetColumnSpan(this.label4, 3);
            this.label4.Location = new System.Drawing.Point(3, 49);
            this.label4.Margin = new System.Windows.Forms.Padding(3);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(118, 13);
            this.label4.TabIndex = 7;
            this.label4.Text = "[ListenersDlgTCPLabel]";
            // 
            // txtTcpPort
            // 
            this.txtTcpPort.Location = new System.Drawing.Point(362, 68);
            this.txtTcpPort.Name = "txtTcpPort";
            this.txtTcpPort.Size = new System.Drawing.Size(40, 20);
            this.txtTcpPort.TabIndex = 5;
            // 
            // txtTcpHostname
            // 
            this.txtTcpHostname.Enabled = false;
            this.txtTcpHostname.Location = new System.Drawing.Point(79, 68);
            this.txtTcpHostname.Name = "txtTcpHostname";
            this.txtTcpHostname.Size = new System.Drawing.Size(277, 20);
            this.txtTcpHostname.TabIndex = 4;
            // 
            // cmbTcpProtocol
            // 
            this.cmbTcpProtocol.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cmbTcpProtocol.Enabled = false;
            this.cmbTcpProtocol.FormattingEnabled = true;
            this.cmbTcpProtocol.Location = new System.Drawing.Point(3, 68);
            this.cmbTcpProtocol.Name = "cmbTcpProtocol";
            this.cmbTcpProtocol.Size = new System.Drawing.Size(70, 21);
            this.cmbTcpProtocol.TabIndex = 3;
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
            this.label2.Size = new System.Drawing.Size(124, 13);
            this.label2.TabIndex = 1;
            this.label2.Text = "[ListenersDlgDescription]";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.BackColor = System.Drawing.Color.Transparent;
            this.label1.Font = new System.Drawing.Font("Microsoft Sans Serif", 8.25F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label1.ForeColor = System.Drawing.SystemColors.HighlightText;
            this.label1.Location = new System.Drawing.Point(11, 8);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(110, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "[ListenersDlgTitle]";
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
            // ListenersDialog
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.ClientSize = new System.Drawing.Size(494, 361);
            this.Controls.Add(this.middlePanel);
            this.Controls.Add(this.topBorder);
            this.Controls.Add(this.topPanel);
            this.Controls.Add(this.bottomPanel);
            this.Name = "ListenersDialog";
            this.Text = "[ListenersDlg_Title]";
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
        private System.Windows.Forms.TextBox txtHttpPort;
        private System.Windows.Forms.TextBox txtHttpHostname;
        private System.Windows.Forms.ComboBox cmbHttpProtocol;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.TextBox txtTcpPort;
        private System.Windows.Forms.TextBox txtTcpHostname;
        private System.Windows.Forms.ComboBox cmbTcpProtocol;
        private System.Windows.Forms.TableLayoutPanel tableLayoutPanel2;
    }
}
