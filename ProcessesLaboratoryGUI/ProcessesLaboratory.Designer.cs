namespace ProcessesLaboratoryGUI
{
    partial class ProcessesLaboratory
    {
        /// <summary>
        /// Обязательная переменная конструктора.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Освободить все используемые ресурсы.
        /// </summary>
        /// <param name="disposing">истинно, если управляемый ресурс должен быть удален; иначе ложно.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Код, автоматически созданный конструктором форм Windows

        /// <summary>
        /// Требуемый метод для поддержки конструктора — не изменяйте 
        /// содержимое этого метода с помощью редактора кода.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ProcessesLaboratory));
            this.menu_panel = new System.Windows.Forms.Panel();
            this.hidpro_btn = new System.Windows.Forms.Button();
            this.enpriv_btn = new System.Windows.Forms.Button();
            this.memreg_btn = new System.Windows.Forms.Button();
            this.main_panel = new System.Windows.Forms.Panel();
            this.ap_main_lbl = new System.Windows.Forms.Label();
            this.mr_main_lbl = new System.Windows.Forms.Label();
            this.hp_main_lbl = new System.Windows.Forms.Label();
            this.MainLabel = new System.Windows.Forms.Label();
            this.memreg_panel = new System.Windows.Forms.Panel();
            this.memreg_lbx = new System.Windows.Forms.ListBox();
            this.clear_btn = new System.Windows.Forms.Button();
            this.scan_btn = new System.Windows.Forms.Button();
            this.btns_panel = new System.Windows.Forms.Panel();
            this.hidpro_panel = new System.Windows.Forms.Panel();
            this.hidpro_lbx = new System.Windows.Forms.ListBox();
            this.enpriv_panel = new System.Windows.Forms.Panel();
            this.enpriv_lbx = new System.Windows.Forms.ListBox();
            this.menu_panel.SuspendLayout();
            this.main_panel.SuspendLayout();
            this.memreg_panel.SuspendLayout();
            this.btns_panel.SuspendLayout();
            this.hidpro_panel.SuspendLayout();
            this.enpriv_panel.SuspendLayout();
            this.SuspendLayout();
            // 
            // menu_panel
            // 
            this.menu_panel.BackColor = System.Drawing.SystemColors.ControlLight;
            this.menu_panel.Controls.Add(this.hidpro_btn);
            this.menu_panel.Controls.Add(this.enpriv_btn);
            this.menu_panel.Controls.Add(this.memreg_btn);
            this.menu_panel.Dock = System.Windows.Forms.DockStyle.Left;
            this.menu_panel.Location = new System.Drawing.Point(0, 0);
            this.menu_panel.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.menu_panel.Name = "menu_panel";
            this.menu_panel.Size = new System.Drawing.Size(278, 893);
            this.menu_panel.TabIndex = 0;
            // 
            // hidpro_btn
            // 
            this.hidpro_btn.Font = new System.Drawing.Font("Segoe UI", 10.125F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.hidpro_btn.Location = new System.Drawing.Point(0, 261);
            this.hidpro_btn.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.hidpro_btn.Name = "hidpro_btn";
            this.hidpro_btn.Size = new System.Drawing.Size(278, 108);
            this.hidpro_btn.TabIndex = 2;
            this.hidpro_btn.Text = "Hidden Processes";
            this.hidpro_btn.UseVisualStyleBackColor = true;
            this.hidpro_btn.Click += new System.EventHandler(this.hidpro_btn_Click);
            // 
            // enpriv_btn
            // 
            this.enpriv_btn.Font = new System.Drawing.Font("Segoe UI", 10.125F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.enpriv_btn.Location = new System.Drawing.Point(0, 145);
            this.enpriv_btn.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.enpriv_btn.Name = "enpriv_btn";
            this.enpriv_btn.Size = new System.Drawing.Size(278, 108);
            this.enpriv_btn.TabIndex = 1;
            this.enpriv_btn.Text = "Active Privileges";
            this.enpriv_btn.UseVisualStyleBackColor = true;
            this.enpriv_btn.Click += new System.EventHandler(this.enpriv_btn_Click);
            // 
            // memreg_btn
            // 
            this.memreg_btn.Font = new System.Drawing.Font("Segoe UI", 10.125F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.memreg_btn.Location = new System.Drawing.Point(0, 29);
            this.memreg_btn.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.memreg_btn.Name = "memreg_btn";
            this.memreg_btn.Size = new System.Drawing.Size(278, 108);
            this.memreg_btn.TabIndex = 0;
            this.memreg_btn.Text = "Memory regions";
            this.memreg_btn.UseVisualStyleBackColor = true;
            this.memreg_btn.Click += new System.EventHandler(this.memreg_btn_Click);
            // 
            // main_panel
            // 
            this.main_panel.Controls.Add(this.ap_main_lbl);
            this.main_panel.Controls.Add(this.mr_main_lbl);
            this.main_panel.Controls.Add(this.hp_main_lbl);
            this.main_panel.Controls.Add(this.MainLabel);
            this.main_panel.Location = new System.Drawing.Point(278, 0);
            this.main_panel.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.main_panel.Name = "main_panel";
            this.main_panel.Size = new System.Drawing.Size(1134, 806);
            this.main_panel.TabIndex = 1;
            // 
            // ap_main_lbl
            // 
            this.ap_main_lbl.AutoSize = true;
            this.ap_main_lbl.Font = new System.Drawing.Font("Segoe UI Semibold", 10.875F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.ap_main_lbl.Location = new System.Drawing.Point(6, 145);
            this.ap_main_lbl.Name = "ap_main_lbl";
            this.ap_main_lbl.Size = new System.Drawing.Size(916, 80);
            this.ap_main_lbl.TabIndex = 3;
            this.ap_main_lbl.Text = "# Active Privileges - показывает активные привилегии процессов. \r\nПозволяет обнар" +
    "ужить эскалацию привилегий до TCB и Debug\r\n";
            // 
            // mr_main_lbl
            // 
            this.mr_main_lbl.AutoSize = true;
            this.mr_main_lbl.Font = new System.Drawing.Font("Segoe UI Semibold", 10.875F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.mr_main_lbl.Location = new System.Drawing.Point(6, 29);
            this.mr_main_lbl.Name = "mr_main_lbl";
            this.mr_main_lbl.Size = new System.Drawing.Size(1049, 80);
            this.mr_main_lbl.TabIndex = 2;
            this.mr_main_lbl.Text = "# Memory regions - покажет все процессы имеющие RWX права регионов. \r\nА так же пр" +
    "оцессы, чьи права регионов были подозрительно изменены";
            // 
            // hp_main_lbl
            // 
            this.hp_main_lbl.AutoSize = true;
            this.hp_main_lbl.Font = new System.Drawing.Font("Segoe UI Semibold", 10.875F, System.Drawing.FontStyle.Bold);
            this.hp_main_lbl.Location = new System.Drawing.Point(6, 261);
            this.hp_main_lbl.Name = "hp_main_lbl";
            this.hp_main_lbl.Size = new System.Drawing.Size(1003, 80);
            this.hp_main_lbl.TabIndex = 1;
            this.hp_main_lbl.Text = "# Hidden Processes - Показывает процессы, которые были обнаружены \r\nNt функцией я" +
    "дра, но пропущены сканерами верхнего уровня. ";
            // 
            // MainLabel
            // 
            this.MainLabel.AutoSize = true;
            this.MainLabel.Font = new System.Drawing.Font("Segoe UI", 7.875F, System.Drawing.FontStyle.Italic, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.MainLabel.Location = new System.Drawing.Point(865, 854);
            this.MainLabel.Name = "MainLabel";
            this.MainLabel.Size = new System.Drawing.Size(257, 30);
            this.MainLabel.TabIndex = 0;
            this.MainLabel.Text = "Processes Laboratory v0.0.1";
            // 
            // memreg_panel
            // 
            this.memreg_panel.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.memreg_panel.Controls.Add(this.memreg_lbx);
            this.memreg_panel.Location = new System.Drawing.Point(278, 0);
            this.memreg_panel.Name = "memreg_panel";
            this.memreg_panel.Size = new System.Drawing.Size(1134, 806);
            this.memreg_panel.TabIndex = 4;
            this.memreg_panel.Visible = false;
            // 
            // memreg_lbx
            // 
            this.memreg_lbx.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.memreg_lbx.FormattingEnabled = true;
            this.memreg_lbx.ItemHeight = 30;
            this.memreg_lbx.Location = new System.Drawing.Point(0, 0);
            this.memreg_lbx.Name = "memreg_lbx";
            this.memreg_lbx.Size = new System.Drawing.Size(1134, 814);
            this.memreg_lbx.TabIndex = 1;
            // 
            // clear_btn
            // 
            this.clear_btn.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Right)));
            this.clear_btn.Location = new System.Drawing.Point(566, 0);
            this.clear_btn.Name = "clear_btn";
            this.clear_btn.Size = new System.Drawing.Size(567, 78);
            this.clear_btn.TabIndex = 3;
            this.clear_btn.Text = "Clear";
            this.clear_btn.UseVisualStyleBackColor = true;
            this.clear_btn.Click += new System.EventHandler(this.clear_btn_Click);
            // 
            // scan_btn
            // 
            this.scan_btn.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Bottom | System.Windows.Forms.AnchorStyles.Left)));
            this.scan_btn.Location = new System.Drawing.Point(0, 0);
            this.scan_btn.Name = "scan_btn";
            this.scan_btn.Size = new System.Drawing.Size(565, 78);
            this.scan_btn.TabIndex = 2;
            this.scan_btn.Text = "Start Detection";
            this.scan_btn.UseVisualStyleBackColor = true;
            this.scan_btn.Click += new System.EventHandler(this.scan_btn_Click);
            // 
            // btns_panel
            // 
            this.btns_panel.Controls.Add(this.clear_btn);
            this.btns_panel.Controls.Add(this.scan_btn);
            this.btns_panel.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.btns_panel.Location = new System.Drawing.Point(278, 806);
            this.btns_panel.Name = "btns_panel";
            this.btns_panel.Size = new System.Drawing.Size(1134, 87);
            this.btns_panel.TabIndex = 4;
            this.btns_panel.Visible = false;
            // 
            // hidpro_panel
            // 
            this.hidpro_panel.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.hidpro_panel.Controls.Add(this.hidpro_lbx);
            this.hidpro_panel.Location = new System.Drawing.Point(278, 0);
            this.hidpro_panel.Name = "hidpro_panel";
            this.hidpro_panel.Size = new System.Drawing.Size(1134, 806);
            this.hidpro_panel.TabIndex = 5;
            this.hidpro_panel.Visible = false;
            // 
            // hidpro_lbx
            // 
            this.hidpro_lbx.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.hidpro_lbx.FormattingEnabled = true;
            this.hidpro_lbx.ItemHeight = 30;
            this.hidpro_lbx.Location = new System.Drawing.Point(0, 0);
            this.hidpro_lbx.Name = "hidpro_lbx";
            this.hidpro_lbx.Size = new System.Drawing.Size(1134, 814);
            this.hidpro_lbx.TabIndex = 1;
            // 
            // enpriv_panel
            // 
            this.enpriv_panel.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.enpriv_panel.Controls.Add(this.enpriv_lbx);
            this.enpriv_panel.Location = new System.Drawing.Point(278, 0);
            this.enpriv_panel.Name = "enpriv_panel";
            this.enpriv_panel.Size = new System.Drawing.Size(1134, 806);
            this.enpriv_panel.TabIndex = 6;
            this.enpriv_panel.Visible = false;
            // 
            // enpriv_lbx
            // 
            this.enpriv_lbx.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom) 
            | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.enpriv_lbx.FormattingEnabled = true;
            this.enpriv_lbx.ItemHeight = 30;
            this.enpriv_lbx.Location = new System.Drawing.Point(0, 0);
            this.enpriv_lbx.Name = "enpriv_lbx";
            this.enpriv_lbx.Size = new System.Drawing.Size(1134, 814);
            this.enpriv_lbx.TabIndex = 1;
            // 
            // ProcessesLaboratory
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 30F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1412, 893);
            this.Controls.Add(this.enpriv_panel);
            this.Controls.Add(this.hidpro_panel);
            this.Controls.Add(this.btns_panel);
            this.Controls.Add(this.memreg_panel);
            this.Controls.Add(this.menu_panel);
            this.Controls.Add(this.main_panel);
            this.Font = new System.Drawing.Font("Segoe UI", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.Name = "ProcessesLaboratory";
            this.Text = "Processes Laboratory";
            this.menu_panel.ResumeLayout(false);
            this.main_panel.ResumeLayout(false);
            this.main_panel.PerformLayout();
            this.memreg_panel.ResumeLayout(false);
            this.btns_panel.ResumeLayout(false);
            this.hidpro_panel.ResumeLayout(false);
            this.enpriv_panel.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Panel menu_panel;
        private System.Windows.Forms.Panel main_panel;
        private System.Windows.Forms.Label hp_main_lbl;
        private System.Windows.Forms.Label MainLabel;
        private System.Windows.Forms.Button memreg_btn;
        private System.Windows.Forms.Button hidpro_btn;
        private System.Windows.Forms.Button enpriv_btn;
        private System.Windows.Forms.Label mr_main_lbl;
        private System.Windows.Forms.Label ap_main_lbl;
        private System.Windows.Forms.Panel memreg_panel;
        private System.Windows.Forms.Button clear_btn;
        private System.Windows.Forms.Button scan_btn;
        private System.Windows.Forms.ListBox memreg_lbx;
        private System.Windows.Forms.Panel btns_panel;
        private System.Windows.Forms.Panel hidpro_panel;
        private System.Windows.Forms.ListBox hidpro_lbx;
        private System.Windows.Forms.Panel enpriv_panel;
        private System.Windows.Forms.ListBox enpriv_lbx;
    }
}

