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
using System.Xml;

namespace ProcessesLaboratoryGUI
{
    public partial class ProcessesLaboratory : Form
    {
        private class NavigationSection
        {
            public Button button { get; set; }
            public Panel panel { get; set; }   
            public Color active_color { get; set; }
            public Color inactive_color { get; set; }

            public NavigationSection(Button btn, Panel pnl)
            {
                button = btn;
                panel = pnl;
                active_color = SystemColors.ControlLight;
                inactive_color = SystemColors.ControlLightLight;
            }

            public void Show()
            {
                panel.Show();
                button.BackColor = active_color;
            }

            public void Hide()
            {
                panel.Hide();
                button.BackColor = inactive_color;
            }

            public bool IsVisible()
            {
                return panel.Visible;
            }

        }

        private List<NavigationSection> navigation_sections_;
        private NavigationSection active_section_;

        private void InitializeSections()
        {
            navigation_sections_ = new List<NavigationSection> {
                new NavigationSection(memreg_btn, memreg_panel),
                new NavigationSection(enpriv_btn, enpriv_panel),
                new NavigationSection(hidpro_btn, hidpro_panel),
                new NavigationSection(admrig_btn, admrig_pnl)
                };

            foreach (var section in navigation_sections_)
            {
                section.button.Click += (sender, e) => NavigateToSection(section);
            }

            active_section_ = null;

        }

        public ProcessesLaboratory()
        {
            InitializeComponent();
            InitializeSections();
        }

        private LogCallback _compromised_callback;
        private LogCallback _hidden_callback;
        private LogCallback _eprivileges_callback;
        private LogCallback _adminrights_callback;

        private void SwitchToMainPanel()
        {
            main_panel.Visible = true;
            btns_panel.Visible = false;
            foreach (var section in navigation_sections_)
            {
                section.Hide();
            }
            active_section_ = null;
        }

        private void NavigateToSection(NavigationSection section)
        {
            if (active_section_ == section)
            {
                SwitchToMainPanel();
                return;
            }

            if (!btns_panel.Visible)
            {
                btns_panel.Show();
            }

            foreach (var sec in navigation_sections_)
            {
                if (sec.IsVisible())
                {
                    sec.Hide();
                }
            }  

            section.Show();
            active_section_ = section;
            main_panel.Hide();
        }

        private void AppendColoredText(RichTextBox rtb, string text, Color color)
        {
            int start = rtb.TextLength;
            rtb.AppendText(text + "\n");
            rtb.Select(start, text.Length);
            rtb.SelectionColor = color;
            rtb.Select(rtb.TextLength, 0);
        }

        private void OutputResultToRichTextBox(RichTextBox rtextbox, string result_json)
        {
            if (rtextbox.InvokeRequired)
            {
                rtextbox.Invoke((Action)(() => OutputResultToRichTextBox(rtextbox, result_json)));
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

                        Color color = process.severity switch
                        {
                            "info" => Color.Blue,
                            "suspicious" => Color.Orange,
                            "malware" => Color.OrangeRed,
                            "critical" => Color.Red,
                            _ => Color.Black
                        };

                        AppendColoredText(rtextbox, line, color);
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
            OutputResultToRichTextBox(memreg_rtb, result_json);
        }

        private void OnHiddenProcessesResult(string result_json)
        {
            OutputResultToRichTextBox(hidpro_rtb, result_json);
        }

        private void OnEnabledPrivilegesResult(string result_json)
        {
            OutputResultToRichTextBox(enpriv_rtb, result_json);
        }

        private void OnAdminRightsResult(string result_json)
        {
            OutputResultToRichTextBox(admrig_rtb, result_json);
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
            else if (admrig_pnl.Visible)
            {
                admrig_rtb.AppendText(start);
                _adminrights_callback = OnAdminRightsResult;
                NativeMethods.DetectAdminRights(_adminrights_callback);
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
            else if (admrig_pnl.Visible)
            {
                admrig_rtb.Clear();
            }
        }

    }
}
