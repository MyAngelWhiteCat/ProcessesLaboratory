using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

using System.Text.Json;

namespace ProcessesLaboratoryGUI
{
    public partial class ProcessesLaboratory : Form
    {
        public ProcessesLaboratory()
        {
            InitializeComponent();
        }

        private LogCallback _compromised_callback;
        
        private void SwitchToMainPanel()
        {
            main_panel.Visible = true;
            btns_panel.Visible = false;
            if (memreg_panel.Visible)
            {
                memreg_panel.Visible = false;
                memreg_btn.BackColor = SystemColors.ControlLightLight;
            }
        }

        private void OnCompromisedProcessesResult(string result_json)
        {
            if (memreg_lbx.InvokeRequired)
            {
                memreg_lbx.Invoke((Action)(() => OnCompromisedProcessesResult(result_json)));
                return;
            }
            try
            {
                var detect_result = JsonSerializer
                    .Deserialize<List<ProcessInfo>>(result_json);
                foreach (var process in detect_result)
                {
                    string line = $"[{process.pid}] {process.process_name} " +
                        $"- {process.comment}";
                    memreg_lbx.Items.Add(line);
                }
            } 
            catch (Exception ex)
            {
                memreg_lbx.Items.Add($"Error: {ex.Message}");
            }
        }

        private void memreg_btn_Click(object sender, EventArgs e)
        {
            if (!memreg_panel.Visible)
            {
                memreg_panel.Visible = true;
                main_panel.Visible = false;
                btns_panel.Visible = true;
                memreg_btn.BackColor = SystemColors.Control;
            }
            else
            {
                SwitchToMainPanel();
            }
        }

        private void scan_btn_Click(object sender, EventArgs e)
        {
            if (memreg_panel.Visible)
            {
                _compromised_callback = OnCompromisedProcessesResult;
                NativeMethods.DetectCompromisedProcesses(_compromised_callback);
            }
        }
    }
}
