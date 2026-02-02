#include "domain.h"

#include <codecvt>
#include <locale>
#include <memory>
#include <ostream>
#include <string>
#include <string_view>

#include <Windows.h>
#include <winternl.h>

namespace proc_scan {

    namespace domain {

        void Snapshot::Insert(std::shared_ptr<ProcessInfo> proc_info) {
            pid_to_proc_info_[proc_info->pid_] = proc_info;
            proc_name_to_proc_info_[proc_info->process_name_] = proc_info;
        }

        std::shared_ptr<ProcessInfo> Snapshot::GetProcessInfo(std::string_view process_name) const {
            if (auto it = proc_name_to_proc_info_.find(std::string(process_name));
                it != proc_name_to_proc_info_.end()) {
                return it->second;
            }
            return nullptr;
        }

        std::shared_ptr<ProcessInfo> Snapshot::GetProcessInfo(DWORD pid) const {
            if (auto it = pid_to_proc_info_.find(pid);
                it != pid_to_proc_info_.end()) {
                return it->second;
            }
            return nullptr;
        }

        void ProcessInfo::Print(std::ostream& out) const {
            out << "================================================="
                << "\n[PID]       " << pid_
                << "\n[Prioritet] " << (priority_ ? std::to_string(priority_) : "Unknown")
                << "\n[Threads]   " << threads_count_
                << "\n[Name]      " << process_name_
                << "\n";
            out << "\n-------------------------------------------------\n";
        }

        void ProcessInfo::PrintModules(std::ostream& out) const {
            for (const auto& module : modules_) {
                module.Print(out);
            }
        }

        void ProcessInfo::PrintThreads(std::ostream& out) const {
            for (const auto& thread : threads_) {
                thread.Print(out);
            }
        }

        std::string WideCharToString(const WCHAR* wstr) {
            if (!wstr) {
                return "";
            }

            int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
            std::string str(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &str[0], size_needed, nullptr, nullptr);

            if (!str.empty() && str.back() == '\0') {
                str.pop_back();
            }
            return str;
        }

        std::unique_ptr<std::wstring> StringToWideChar(std::string_view str) {
            if (str.empty()) {
                return nullptr;
            }
            int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.data(), -1, nullptr, 0);
            wchar_t* wide_str = new wchar_t[size_needed];
            MultiByteToWideChar(CP_UTF8, 0, str.data(), -1, wide_str, size_needed);
            return std::make_unique<std::wstring>(wide_str);
        }

        std::string UnicodeToString(const UNICODE_STRING& ustr) {
            if (!ustr.Buffer || !ustr.Length) {
                return "";
            }

            std::wstring wstr(ustr.Buffer, ustr.Length / sizeof(wchar_t));
            std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
            return converter.to_bytes(wstr);
        }

        void ModuleInfo::Print(std::ostream& out) const {
            out << "\nModule info:"
                << "\n[ModuleID] " << module_id_
                << "\n[name]     " << name_
                << "\n[path]     " << path_
                << "\n";
        }

        void ThreadInfo::Print(std::ostream& out) const {
            out << "\nThread info:"
                << "\n[id]        " << thread_id_
                << "\n[owner id]  " << owner_id_
                << "\n[prioritet] " << priority_level_
                << "\n";
        }

    }
    
}