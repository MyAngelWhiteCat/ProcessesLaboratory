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
            this.hidproc_btn = new System.Windows.Forms.Button();
            this.actpriv_btn = new System.Windows.Forms.Button();
            this.memreg_btn = new System.Windows.Forms.Button();
            this.main_panel = new System.Windows.Forms.Panel();
            this.ap_main_lbl = new System.Windows.Forms.Label();
            this.mr_main_lbl = new System.Windows.Forms.Label();
            this.hp_main_lbl = new System.Windows.Forms.Label();
            this.MainLabel = new System.Windows.Forms.Label();
            this.memreg_panel = new System.Windows.Forms.Panel();
            this.menu_panel.SuspendLayout();
            this.main_panel.SuspendLayout();
            this.SuspendLayout();
            // 
            // menu_panel
            // 
            this.menu_panel.Controls.Add(this.hidproc_btn);
            this.menu_panel.Controls.Add(this.actpriv_btn);
            this.menu_panel.Controls.Add(this.memreg_btn);
            this.menu_panel.Dock = System.Windows.Forms.DockStyle.Left;
            this.menu_panel.Location = new System.Drawing.Point(0, 0);
            this.menu_panel.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.menu_panel.Name = "menu_panel";
            this.menu_panel.Size = new System.Drawing.Size(278, 893);
            this.menu_panel.TabIndex = 0;
            // 
            // hidproc_btn
            // 
            this.hidproc_btn.Font = new System.Drawing.Font("Segoe UI", 10.125F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.hidproc_btn.Location = new System.Drawing.Point(0, 261);
            this.hidproc_btn.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.hidproc_btn.Name = "hidproc_btn";
            this.hidproc_btn.Size = new System.Drawing.Size(278, 108);
            this.hidproc_btn.TabIndex = 2;
            this.hidproc_btn.Text = "Hidden Processes";
            this.hidproc_btn.UseVisualStyleBackColor = true;
            // 
            // actpriv_btn
            // 
            this.actpriv_btn.Font = new System.Drawing.Font("Segoe UI", 10.125F, System.Drawing.FontStyle.Bold, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.actpriv_btn.Location = new System.Drawing.Point(0, 145);
            this.actpriv_btn.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.actpriv_btn.Name = "actpriv_btn";
            this.actpriv_btn.Size = new System.Drawing.Size(278, 108);
            this.actpriv_btn.TabIndex = 1;
            this.actpriv_btn.Text = "Active Privileges";
            this.actpriv_btn.UseVisualStyleBackColor = true;
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
            // 
            // main_panel
            // 
            this.main_panel.Controls.Add(this.ap_main_lbl);
            this.main_panel.Controls.Add(this.mr_main_lbl);
            this.main_panel.Controls.Add(this.hp_main_lbl);
            this.main_panel.Controls.Add(this.MainLabel);
            this.main_panel.Controls.Add(this.memreg_panel);
            this.main_panel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.main_panel.Location = new System.Drawing.Point(278, 0);
            this.main_panel.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.main_panel.Name = "main_panel";
            this.main_panel.Size = new System.Drawing.Size(1134, 893);
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
            this.memreg_panel.Dock = System.Windows.Forms.DockStyle.Fill;
            this.memreg_panel.Location = new System.Drawing.Point(0, 0);
            this.memreg_panel.Name = "memreg_panel";
            this.memreg_panel.Size = new System.Drawing.Size(1134, 893);
            this.memreg_panel.TabIndex = 4;
            this.memreg_panel.Visible = false;
            // 
            // ProcessesLaboratory
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(12F, 30F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(1412, 893);
            this.Controls.Add(this.main_panel);
            this.Controls.Add(this.menu_panel);
            this.Font = new System.Drawing.Font("Segoe UI", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(204)));
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Margin = new System.Windows.Forms.Padding(3, 4, 3, 4);
            this.Name = "ProcessesLaboratory";
            this.Text = "Processes Laboratory";
            this.menu_panel.ResumeLayout(false);
            this.main_panel.ResumeLayout(false);
            this.main_panel.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.Panel menu_panel;
        private System.Windows.Forms.Panel main_panel;
        private System.Windows.Forms.Label hp_main_lbl;
        private System.Windows.Forms.Label MainLabel;
        private System.Windows.Forms.Button memreg_btn;
        private System.Windows.Forms.Button hidproc_btn;
        private System.Windows.Forms.Button actpriv_btn;
        private System.Windows.Forms.Label mr_main_lbl;
        private System.Windows.Forms.Label ap_main_lbl;
        private System.Windows.Forms.Panel memreg_panel;
    }
}

