#pragma once

#include <Windows.h>
#include <string>

#include <unordered_map>
#include <chrono>
#include <memory>
#include <ostream>
#include <utility>
#include <vector>
#include <string_view>


namespace proc_scan {

    using SystemClock = std::chrono::system_clock;

    namespace domain {

        struct ModuleInfo {
            ModuleInfo() = default;
            ModuleInfo(DWORD dwPID, std::string&& name, std::string&& path)
                : pid_(dwPID)
                , name_(std::move(name))
                , path_(std::move(path))
            {

            }

            DWORD pid_{ 0 };
            std::string name_;
            std::string path_;
        };

        struct ProcessInfo {
            ProcessInfo() = default;
            ProcessInfo(DWORD pid, DWORD threads_count, std::string_view process_name)
                : pid_(pid)
                , threads_count_(threads_count)
                , process_name_(std::string(process_name))
            {

            }
            DWORD pid_{ 0 };
            DWORD threads_count_{ 0 };
            std::string process_name_;
            std::vector<ModuleInfo> modules_;

            void Print(std::ostream& out) const;

        };

        struct Snapshot {
            Snapshot(SystemClock::time_point time)
                : time_(time)
            {

            }

            void Insert(std::shared_ptr<ProcessInfo> proc_info);

            SystemClock::time_point time_;

            std::unordered_map<DWORD, std::shared_ptr<ProcessInfo>> pid_to_proc_info_;
            std::unordered_map<std::string_view, std::shared_ptr<ProcessInfo>> proc_name_to_proc_info_;

            std::shared_ptr<ProcessInfo> GetProcessInfo(std::string_view process_name) const;
            std::shared_ptr<ProcessInfo> GetProcessInfo(DWORD pid) const;
        };

        std::string WideCharToString(const WCHAR* wstr);
       
    }

}
