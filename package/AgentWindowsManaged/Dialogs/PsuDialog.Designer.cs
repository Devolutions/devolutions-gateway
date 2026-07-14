using WixSharp;
using WixSharp.UI.Forms;

namespace WixSharpSetup.Dialogs
{
    partial class PsuDialog
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
            this.middlePanel = new System.Windows.Forms.Panel();
            this.tableLayoutPanel2 = new System.Windows.Forms.TableLayoutPanel();
            this.labelServerUrl = new System.Windows.Forms.Label();
            this.serverUrl = new System.Windows.Forms.TextBox();
            this.labelServerUrlHint = new System.Windows.Forms.Label();
            this.labelAppToken = new System.Windows.Forms.Label();
            this.appToken = new System.Windows.Forms.TextBox();
            this.appTokenTypePanel = new System.Windows.Forms.FlowLayoutPanel();
            this.tokenValueRadio = new System.Windows.Forms.RadioButton();
            this.secretNameRadio = new System.Windows.Forms.RadioButton();
            this.labelAppTokenHint = new System.Windows.Forms.Label();
            this.labelAgentId = new System.Windows.Forms.Label();
            this.agentId = new System.Windows.Forms.TextBox();
            this.labelAgentIdHint = new System.Windows.Forms.Label();
            this.labelDisplayName = new System.Windows.Forms.Label();
            this.displayName = new System.Windows.Forms.TextBox();
            this.labelDisplayNameHint = new System.Windows.Forms.Label();
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
            this.middlePanel.SuspendLayout();
            this.tableLayoutPanel2.SuspendLayout();
            this.appTokenTypePanel.SuspendLayout();
            this.topPanel.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.banner)).BeginInit();
            this.bottomPanel.SuspendLayout();
            this.tableLayoutPanel1.SuspendLayout();
            this.SuspendLayout();
            //
            // middlePanel
            //
            this.middlePanel.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
            | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.middlePanel.AutoScroll = true;
            this.middlePanel.Controls.Add(this.tableLayoutPanel2);
            this.middlePanel.Location = new System.Drawing.Point(22, 75);
            this.middlePanel.Name = "middlePanel";
            this.middlePanel.Size = new System.Drawing.Size(449, 225);
            this.middlePanel.TabIndex = 0;
            //
            // tableLayoutPanel2
            //
            this.tableLayoutPanel2.ColumnCount = 1;
            this.tableLayoutPanel2.ColumnStyles.Add(new System.Windows.Forms.ColumnStyle(System.Windows.Forms.SizeType.Percent, 100F));
            this.tableLayoutPanel2.Controls.Add(this.labelServerUrl, 0, 0);
            this.tableLayoutPanel2.Controls.Add(this.serverUrl, 0, 1);
            this.tableLayoutPanel2.Controls.Add(this.labelServerUrlHint, 0, 2);
            this.tableLayoutPanel2.Controls.Add(this.labelAppToken, 0, 3);
            this.tableLayoutPanel2.Controls.Add(this.appToken, 0, 4);
            this.tableLayoutPanel2.Controls.Add(this.appTokenTypePanel, 0, 5);
            this.tableLayoutPanel2.Controls.Add(this.labelAppTokenHint, 0, 6);
            this.tableLayoutPanel2.Controls.Add(this.labelAgentId, 0, 7);
            this.tableLayoutPanel2.Controls.Add(this.agentId, 0, 8);
            this.tableLayoutPanel2.Controls.Add(this.labelAgentIdHint, 0, 9);
            this.tableLayoutPanel2.Controls.Add(this.labelDisplayName, 0, 10);
            this.tableLayoutPanel2.Controls.Add(this.displayName, 0, 11);
            this.tableLayoutPanel2.Controls.Add(this.labelDisplayNameHint, 0, 12);
            this.tableLayoutPanel2.AutoSize = true;
            this.tableLayoutPanel2.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            this.tableLayoutPanel2.Dock = System.Windows.Forms.DockStyle.Top;
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
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.RowStyles.Add(new System.Windows.Forms.RowStyle());
            this.tableLayoutPanel2.Size = new System.Drawing.Size(449, 285);
            this.tableLayoutPanel2.TabIndex = 0;
            //
            // labelServerUrl
            //
            this.labelServerUrl.AutoSize = true;
            this.labelServerUrl.BackColor = System.Drawing.Color.Transparent;
            this.labelServerUrl.Location = new System.Drawing.Point(3, 3);
            this.labelServerUrl.Margin = new System.Windows.Forms.Padding(3);
            this.labelServerUrl.Name = "labelServerUrl";
            this.labelServerUrl.Size = new System.Drawing.Size(200, 13);
            this.labelServerUrl.TabIndex = 0;
            this.labelServerUrl.Text = "[PsuDlgServerUrlLabel]";
            //
            // serverUrl
            //
            this.serverUrl.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.serverUrl.Location = new System.Drawing.Point(3, 22);
            this.serverUrl.Name = "serverUrl";
            this.serverUrl.Size = new System.Drawing.Size(443, 20);
            this.serverUrl.TabIndex = 1;
            //
            // labelServerUrlHint
            //
            this.labelServerUrlHint.AutoSize = true;
            this.labelServerUrlHint.BackColor = System.Drawing.Color.Transparent;
            this.labelServerUrlHint.ForeColor = System.Drawing.SystemColors.GrayText;
            this.labelServerUrlHint.Location = new System.Drawing.Point(3, 48);
            this.labelServerUrlHint.Margin = new System.Windows.Forms.Padding(3);
            this.labelServerUrlHint.Name = "labelServerUrlHint";
            this.labelServerUrlHint.Size = new System.Drawing.Size(300, 13);
            this.labelServerUrlHint.TabIndex = 2;
            this.labelServerUrlHint.Text = "[PsuDlgServerUrlHint]";
            //
            // labelAppToken
            //
            this.labelAppToken.AutoSize = true;
            this.labelAppToken.BackColor = System.Drawing.Color.Transparent;
            this.labelAppToken.Location = new System.Drawing.Point(3, 72);
            this.labelAppToken.Margin = new System.Windows.Forms.Padding(3, 8, 3, 3);
            this.labelAppToken.Name = "labelAppToken";
            this.labelAppToken.Size = new System.Drawing.Size(200, 13);
            this.labelAppToken.TabIndex = 3;
            this.labelAppToken.Text = "[PsuDlgAppTokenLabel]";
            //
            // appToken
            //
            this.appToken.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.appToken.Location = new System.Drawing.Point(3, 91);
            this.appToken.Name = "appToken";
            this.appToken.Size = new System.Drawing.Size(443, 20);
            this.appToken.TabIndex = 4;
            this.appToken.UseSystemPasswordChar = true;
            //
            // appTokenTypePanel
            //
            this.appTokenTypePanel.AutoSize = true;
            this.appTokenTypePanel.AutoSizeMode = System.Windows.Forms.AutoSizeMode.GrowAndShrink;
            this.appTokenTypePanel.Controls.Add(this.tokenValueRadio);
            this.appTokenTypePanel.Controls.Add(this.secretNameRadio);
            this.appTokenTypePanel.Location = new System.Drawing.Point(0, 114);
            this.appTokenTypePanel.Margin = new System.Windows.Forms.Padding(0);
            this.appTokenTypePanel.Name = "appTokenTypePanel";
            this.appTokenTypePanel.Size = new System.Drawing.Size(300, 27);
            this.appTokenTypePanel.TabIndex = 5;
            this.appTokenTypePanel.WrapContents = false;
            //
            // tokenValueRadio
            //
            this.tokenValueRadio.AutoSize = true;
            this.tokenValueRadio.BackColor = System.Drawing.Color.Transparent;
            this.tokenValueRadio.Checked = true;
            this.tokenValueRadio.Location = new System.Drawing.Point(3, 3);
            this.tokenValueRadio.Name = "tokenValueRadio";
            this.tokenValueRadio.Size = new System.Drawing.Size(100, 17);
            this.tokenValueRadio.TabIndex = 0;
            this.tokenValueRadio.TabStop = true;
            this.tokenValueRadio.Text = "[PsuDlgAppTokenValueOption]";
            this.tokenValueRadio.UseVisualStyleBackColor = false;
            //
            // secretNameRadio
            //
            this.secretNameRadio.AutoSize = true;
            this.secretNameRadio.BackColor = System.Drawing.Color.Transparent;
            this.secretNameRadio.Location = new System.Drawing.Point(109, 3);
            this.secretNameRadio.Name = "secretNameRadio";
            this.secretNameRadio.Size = new System.Drawing.Size(100, 17);
            this.secretNameRadio.TabIndex = 1;
            this.secretNameRadio.Text = "[PsuDlgAppTokenSecretOption]";
            this.secretNameRadio.UseVisualStyleBackColor = false;
            //
            // labelAppTokenHint
            //
            this.labelAppTokenHint.AutoSize = true;
            this.labelAppTokenHint.BackColor = System.Drawing.Color.Transparent;
            this.labelAppTokenHint.ForeColor = System.Drawing.SystemColors.GrayText;
            this.labelAppTokenHint.Location = new System.Drawing.Point(3, 144);
            this.labelAppTokenHint.Margin = new System.Windows.Forms.Padding(3);
            this.labelAppTokenHint.Name = "labelAppTokenHint";
            this.labelAppTokenHint.Size = new System.Drawing.Size(300, 13);
            this.labelAppTokenHint.TabIndex = 6;
            this.labelAppTokenHint.Text = "[PsuDlgAppTokenHint]";
            //
            // labelAgentId
            //
            this.labelAgentId.AutoSize = true;
            this.labelAgentId.BackColor = System.Drawing.Color.Transparent;
            this.labelAgentId.Location = new System.Drawing.Point(3, 168);
            this.labelAgentId.Margin = new System.Windows.Forms.Padding(3, 8, 3, 3);
            this.labelAgentId.Name = "labelAgentId";
            this.labelAgentId.Size = new System.Drawing.Size(200, 13);
            this.labelAgentId.TabIndex = 7;
            this.labelAgentId.Text = "[PsuDlgAgentIdLabel]";
            //
            // agentId
            //
            this.agentId.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.agentId.Location = new System.Drawing.Point(3, 187);
            this.agentId.Name = "agentId";
            this.agentId.Size = new System.Drawing.Size(443, 20);
            this.agentId.TabIndex = 8;
            //
            // labelAgentIdHint
            //
            this.labelAgentIdHint.AutoSize = true;
            this.labelAgentIdHint.BackColor = System.Drawing.Color.Transparent;
            this.labelAgentIdHint.ForeColor = System.Drawing.SystemColors.GrayText;
            this.labelAgentIdHint.Location = new System.Drawing.Point(3, 213);
            this.labelAgentIdHint.Margin = new System.Windows.Forms.Padding(3);
            this.labelAgentIdHint.Name = "labelAgentIdHint";
            this.labelAgentIdHint.Size = new System.Drawing.Size(300, 13);
            this.labelAgentIdHint.TabIndex = 9;
            this.labelAgentIdHint.Text = "[PsuDlgAgentIdHint]";
            //
            // labelDisplayName
            //
            this.labelDisplayName.AutoSize = true;
            this.labelDisplayName.BackColor = System.Drawing.Color.Transparent;
            this.labelDisplayName.Location = new System.Drawing.Point(3, 237);
            this.labelDisplayName.Margin = new System.Windows.Forms.Padding(3, 8, 3, 3);
            this.labelDisplayName.Name = "labelDisplayName";
            this.labelDisplayName.Size = new System.Drawing.Size(200, 13);
            this.labelDisplayName.TabIndex = 10;
            this.labelDisplayName.Text = "[PsuDlgDisplayNameLabel]";
            //
            // displayName
            //
            this.displayName.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)
            | System.Windows.Forms.AnchorStyles.Right)));
            this.displayName.Location = new System.Drawing.Point(3, 256);
            this.displayName.Name = "displayName";
            this.displayName.Size = new System.Drawing.Size(443, 20);
            this.displayName.TabIndex = 11;
            //
            // labelDisplayNameHint
            //
            this.labelDisplayNameHint.AutoSize = true;
            this.labelDisplayNameHint.BackColor = System.Drawing.Color.Transparent;
            this.labelDisplayNameHint.ForeColor = System.Drawing.SystemColors.GrayText;
            this.labelDisplayNameHint.Location = new System.Drawing.Point(3, 282);
            this.labelDisplayNameHint.Margin = new System.Windows.Forms.Padding(3);
            this.labelDisplayNameHint.Name = "labelDisplayNameHint";
            this.labelDisplayNameHint.Size = new System.Drawing.Size(300, 13);
            this.labelDisplayNameHint.TabIndex = 12;
            this.labelDisplayNameHint.Text = "[PsuDlgDisplayNameHint]";
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
            this.label2.AutoEllipsis = true;
            this.label2.BackColor = System.Drawing.Color.Transparent;
            this.label2.ForeColor = System.Drawing.SystemColors.HighlightText;
            this.label2.Location = new System.Drawing.Point(18, 31);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(409, 24);
            this.label2.TabIndex = 1;
            this.label2.Text = "[PsuDlgDescription]";
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
            this.label1.Text = "[PsuDlgTitle]";
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
            // PsuDialog
            //
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.ClientSize = new System.Drawing.Size(494, 361);
            this.Controls.Add(this.middlePanel);
            this.Controls.Add(this.topBorder);
            this.Controls.Add(this.topPanel);
            this.Controls.Add(this.bottomPanel);
            this.Name = "PsuDialog";
            this.Load += new System.EventHandler(this.OnLoad);
            this.middlePanel.ResumeLayout(false);
            this.tableLayoutPanel2.ResumeLayout(false);
            this.tableLayoutPanel2.PerformLayout();
            this.appTokenTypePanel.ResumeLayout(false);
            this.appTokenTypePanel.PerformLayout();
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
        private System.Windows.Forms.Label labelServerUrl;
        private System.Windows.Forms.TextBox serverUrl;
        private System.Windows.Forms.Label labelServerUrlHint;
        private System.Windows.Forms.Label labelAppToken;
        private System.Windows.Forms.TextBox appToken;
        private System.Windows.Forms.FlowLayoutPanel appTokenTypePanel;
        private System.Windows.Forms.RadioButton tokenValueRadio;
        private System.Windows.Forms.RadioButton secretNameRadio;
        private System.Windows.Forms.Label labelAppTokenHint;
        private System.Windows.Forms.Label labelAgentId;
        private System.Windows.Forms.TextBox agentId;
        private System.Windows.Forms.Label labelAgentIdHint;
        private System.Windows.Forms.Label labelDisplayName;
        private System.Windows.Forms.TextBox displayName;
        private System.Windows.Forms.Label labelDisplayNameHint;
    }
}
