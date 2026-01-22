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

        struct ThreadInfo {
            ThreadInfo() = delete;
            ThreadInfo(DWORD thread_id, DWORD owner_id, LONG prioritet) 
                : thread_id_(thread_id)
                , owner_id_(owner_id)
                , prioritet_(prioritet)
            {

            }

            DWORD thread_id_{ 0 };
            DWORD owner_id_{ 0 };
            LONG prioritet_{ 0 };

            void Print(std::ostream& out) const;
        };

        struct ModuleInfo {
            ModuleInfo() = default;
            ModuleInfo(DWORD dwPID, std::string&& name, std::string&& path)
                : module_id_(dwPID)
                , name_(std::move(name))
                , path_(std::move(path))
            {

            }

            DWORD module_id_{ 0 };
            std::string name_;
            std::string path_;

            void Print(std::ostream& out) const;
        };

        struct ProcessInfo {
            ProcessInfo() = default;
            ProcessInfo(DWORD pid, DWORD threads_count, std::string&& process_name)
                : pid_(pid)
                , threads_count_(threads_count)
                , process_name_(std::move(process_name))
            {

            }
            DWORD pid_{ 0 };
            DWORD prioritet_{ -1 };
            DWORD threads_count_{ 0 };
            std::string process_name_;

            std::vector<ModuleInfo> modules_;
            std::vector<ThreadInfo> threads_;

            void Print(std::ostream& out) const;
            void PrintModules(std::ostream& out) const;
            void PrintThreads(std::ostream& out) const;

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
