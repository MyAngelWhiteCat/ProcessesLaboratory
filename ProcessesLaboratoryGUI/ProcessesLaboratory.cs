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
        private void OuputResultToRichTextBox(RichTextBox rtextbox, string result_json)
        {
            if (rtextbox.InvokeRequired)
            {
                rtextbox.Invoke((Action)(() => OuputResultToRichTextBox(rtextbox, result_json)));
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
                        rtextbox.AppendText(line + '\n');
                    }
                }
                else
                {
                    rtextbox.AppendText("Empty scan result\n");
                }
                rtextbox.AppendText("Scan complete!\n");
            }
            catch (Exception ex)
            {
                rtextbox.AppendText($"Error: {ex.Message}\n");
            }
        }

        private void OnCompromisedProcessesResult(string result_json)
        {
            OuputResultToRichTextBox(memreg_rtb, result_json);
        }

        private void OnHiddenProcessesResult(string result_json)
        {
            OuputResultToRichTextBox(hidpro_rtb, result_json);
        }

        private void OnEnabledPrivilegesResult(string result_json)
        {
            OuputResultToRichTextBox(enpriv_rtb, result_json);
        }

        private void scan_btn_Click(object sender, EventArgs e)
        {
            string start = "Scan started...\n";
            if (memreg_panel.Visible)
            {
                memreg_rtb.AppendText(start);
                _compromised_callback = OnCompromisedProcessesResult;
                NativeMethods.DetectCompromisedProcesses(_compromised_callback);
            }
            else if (hidpro_panel.Visible)
            {
                hidpro_rtb.AppendText(start);
                _hidden_callback = OnHiddenProcessesResult;
                NativeMethods.DetectHiddenProcesses(_hidden_callback);
            }
            else if (enpriv_panel.Visible)
            {
                enpriv_rtb.AppendText(start);
                _eprivileges_callback = OnEnabledPrivilegesResult;
                NativeMethods.DetectEnabledPrivileges(_eprivileges_callback);
            }
        }
        private void clear_btn_Click(object sender, EventArgs e)
        {
            if (memreg_panel.Visible)
            {
                memreg_rtb.Clear();
            }
            else if (hidpro_panel.Visible)
            {
                hidpro_rtb.Clear();
            }
            else if (enpriv_panel.Visible)
            {
                enpriv_rtb.Clear();
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
