using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

namespace ProcessesLaboratoryGUI
{

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void LogCallback(string message);

    internal static class NativeMethods
    {

        [DllImport("ProcessesLaboratoryApp.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void DetectHiddenProcesses(LogCallback callback);

        [DllImport("ProcessesLaboratoryApp.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void DetectCompromisedProcesses(LogCallback callback);

        [DllImport("ProcessesLaboratoryApp.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void DetectEnabledPrivileges(LogCallback callback);

        [DllImport("ProcessesLaboratoryApp.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void DetectAdminRights(LogCallback callback);
    }

}
