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

        private void OnCompromisedProcessesResult(string result)
        {
            
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
