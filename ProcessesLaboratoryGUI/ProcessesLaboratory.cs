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
                enpriv_btn.BackColor = SystemColors.ControlLightLight;
            }
            else if (hidpro_panel.Visible)
            {
                hidpro_panel.Visible = false;
                hidpro_btn.BackColor = SystemColors.ControlLightLight;
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
                if (detect_result.Count > 0)
                {

                    foreach (var process in detect_result)
                    {
                        string line = $"[{process.severity}][{process.pid}] {process.process_name} " +
                            $"- {process.comment}";
                        listbox.Items.Add(line);
                    }
                }
                else
                {
                    listbox.Items.Add("Empty scan result");
                }
                listbox.Items.Add("Scan complete!");
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

        private void scan_btn_Click(object sender, EventArgs e)
        {
            string start = "Scan started...";
            if (memreg_panel.Visible)
            {
                memreg_lbx.Items.Add(start);
                _compromised_callback = OnCompromisedProcessesResult;
                NativeMethods.DetectCompromisedProcesses(_compromised_callback);
            }
            else if (hidpro_panel.Visible)
            {
                hidpro_lbx.Items.Add(start);
                _hidden_callback = OnHiddenProcessesResult;
                NativeMethods.DetectHiddenProcesses(_hidden_callback);
            }
            else if (enpriv_panel.Visible)
            {
                enpriv_lbx.Items.Add(start);
                _eprivileges_callback = OnEnabledPrivilegesResult;
                NativeMethods.DetectEnabledPrivileges(_eprivileges_callback);
            }
        }
        private void clear_btn_Click(object sender, EventArgs e)
        {
            if (memreg_panel.Visible)
            {
                memreg_lbx.Items.Clear();
            }
            else if (hidpro_panel.Visible)
            {
                hidpro_lbx.Items.Clear();
            }
            else if (enpriv_panel.Visible)
            {
                enpriv_lbx.Items.Clear();
            }
        }

        private void memreg_btn_Click(object sender, EventArgs e)
        {
            if (memreg_panel.Visible)
            {
                SwitchToMainPanel();
            }
            else
            {
                memreg_btn.BackColor = SystemColors.Control;
                memreg_panel.Visible = true;
                btns_panel.Visible = true;

                main_panel.Visible = false;

                if (hidpro_panel.Visible)
                {
                    hidpro_panel.Visible = false;
                    hidpro_btn.BackColor = SystemColors.ControlLightLight;
                }

                if (enpriv_panel.Visible)
                {
                    enpriv_panel.Visible = false;
                    enpriv_btn.BackColor = SystemColors.ControlLightLight;
                }
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
                enpriv_btn.BackColor = SystemColors.Control;
                enpriv_panel.Visible = true;
                btns_panel.Visible = true;

                main_panel.Visible = false;

                if (hidpro_panel.Visible)
                {
                    hidpro_panel.Visible = false;
                    hidpro_btn.BackColor = SystemColors.ControlLightLight;
                }

                if (memreg_panel.Visible)
                {
                    memreg_panel.Visible = false;
                    memreg_btn.BackColor = SystemColors.ControlLightLight;
                }
            }
        }
        private void hidpro_btn_Click(object sender, EventArgs e)
        {
            if (hidpro_panel.Visible)
            {
                SwitchToMainPanel();
            }
            else
            {
                hidpro_btn.BackColor = SystemColors.Control;
                hidpro_panel.Visible = true;
                btns_panel.Visible = true;

                main_panel.Visible = false;

                if (enpriv_panel.Visible)
                {
                    enpriv_panel.Visible = false;
                    enpriv_btn.BackColor = SystemColors.ControlLightLight;
                }

                if (memreg_panel.Visible)
                {
                    memreg_panel.Visible = false;
                    memreg_btn.BackColor = SystemColors.ControlLightLight;
                }
            }
        }

    }
}
