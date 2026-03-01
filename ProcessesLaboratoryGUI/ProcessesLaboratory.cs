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
        private LogCallback _hidden_callback;
        private LogCallback _eprivileges_callback;

        private void SwitchToMainPanel()
        {
            main_panel.Visible = true;
            btns_panel.Visible = false;
            if (memreg_panel.Visible)
            {
                memreg_panel.Visible = false;
                memreg_btn.BackColor = SystemColors.ControlLightLight;
            }
            else if (enpriv_panel.Visible)
            {
                enpriv_panel.Visible = false;
                enpriv_btn.BackColor= SystemColors.ControlLightLight;
            }
        }
        private void OuputResultToListBox(ListBox listbox, string result_json)
        {
            if (listbox.InvokeRequired)
            {
                listbox.Invoke((Action)(() => OuputResultToListBox(listbox, result_json)));
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
                    listbox.Items.Add(line);
                }
            }
            catch (Exception ex)
            {
                listbox.Items.Add($"Error: {ex.Message}");
            }
        }

        private void OnCompromisedProcessesResult(string result_json)
        {
            OuputResultToListBox(memreg_lbx, result_json);
        }

        private void OnHiddenProcessesResult(string result_json)
        {
            OuputResultToListBox(hidpro_lbx, result_json);
        }

        private void OnEnabledPrivilegesResult(string result_json)
        {
            OuputResultToListBox(enpriv_lbx, result_json);
        }

        private void memreg_btn_Click(object sender, EventArgs e)
        {
            if (memreg_panel.Visible)
            {
                SwitchToMainPanel();
            }
            else
            {
                memreg_panel.Visible = true;
                main_panel.Visible = false;
                btns_panel.Visible = true;
                memreg_btn.BackColor = SystemColors.Control;
            }
        }

        private void scan_btn_Click(object sender, EventArgs e)
        {
            if (memreg_panel.Visible)
            {
                _compromised_callback = OnCompromisedProcessesResult;
                NativeMethods.DetectCompromisedProcesses(_compromised_callback);
            }
            else if (hidpro_panel.Visible)
            {
                _hidden_callback = OnHiddenProcessesResult;
                NativeMethods.DetectHiddenProcesses(_hidden_callback);
            }
            else if (enpriv_panel.Visible)
            {
                _eprivileges_callback = OnEnabledPrivilegesResult;
                NativeMethods.DetectEnabledPrivileges(_eprivileges_callback);
            }
        }

        private void enpriv_btn_Click(object sender, EventArgs e)
        {
            if (enpriv_panel.Visible)
            {
                SwitchToMainPanel();
            }
            else
            {
                memreg_panel.Visible = true;
                main_panel.Visible = false;
                btns_panel.Visible = true;
                memreg_btn.BackColor = SystemColors.Control;
            }
        }
    }
}
