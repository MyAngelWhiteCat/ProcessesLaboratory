#pragma once

#include <Windows.h>
#include <winternl.h>

#include <string>
#include <unordered_map>
#include <chrono>
#include <memory>
#include <ostream>
#include <utility>
#include <vector>
#include <string_view>


namespace proc_scan {

    using namespace std::literals;

    namespace domain {

        struct ProcessInfo;

        using SPProcessInfo = std::shared_ptr<ProcessInfo>;
        using PidToProcessIndex = std::unordered_map<DWORD, SPProcessInfo>;
        using ExeNameToProcessIndex = std::unordered_map<std::string, SPProcessInfo>;
        using Clock = std::chrono::high_resolution_clock;

        enum class ScanMethod;
        struct Snapshot;
        using Scan = std::unordered_map<ScanMethod, Snapshot>;
        
        struct NtNames {
            NtNames() = delete;
            static constexpr std::wstring_view NTDLL = L"ntdll.dll";
            static constexpr std::string_view NTQSI = "NtQuerySystemInformation";
        };

        typedef NTSTATUS(*PNtQuerySystemInformation)(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
            );

        enum class ScanMethod {
            ToolHelp = 0,
            NtQSI = 1
        };

        enum class AnalizerType {
            HiddenProcesses = 0
        };

        enum class ScanStrategy {
            Quick = 0,
            Base = 1,
            Full = 2,
            Runtime = 3,
        };

        struct ThreadInfo {
            ThreadInfo() = delete;
            ThreadInfo(DWORD thread_id, DWORD owner_id, LONG prioritet) 
                : thread_id_(thread_id)
                , owner_id_(owner_id)
                , priority_level_(prioritet)
            {

            }

            DWORD thread_id_{ 0 };
            DWORD owner_id_{ 0 };
            LONG priority_level_{ 0 };

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
            DWORD priority_{ 0 };
            DWORD threads_count_{ 0 };
            std::string process_name_;

            Clock::time_point timestamp_{Clock::now()};

            std::vector<ModuleInfo> modules_;
            std::vector<ThreadInfo> threads_;

            void Print(std::ostream& out) const;
            void PrintModules(std::ostream& out) const;
            void PrintThreads(std::ostream& out) const;

            void SetTimestamp();

        };

        struct Snapshot {
            Snapshot(Clock::time_point time) 
                : time_(time)
            {

            }

            void Insert(std::shared_ptr<ProcessInfo> proc_info);

            Clock::time_point time_;
            PidToProcessIndex pid_to_proc_info_;
            ExeNameToProcessIndex proc_name_to_proc_info_;

            std::shared_ptr<ProcessInfo> GetProcessInfo(std::string_view process_name) const;
            std::shared_ptr<ProcessInfo> GetProcessInfo(DWORD pid) const;
        };

        std::string WideCharToString(const WCHAR* wstr);
        std::unique_ptr<std::wstring> StringToWideChar(std::string_view str);
        std::string UnicodeToString(const UNICODE_STRING& ustr);
        HMODULE LoadModule(std::wstring_view module_name);

        template<typename Fn>
        Fn LoadFunctionFromModule(HMODULE hModule, std::string_view function_name) {
            return reinterpret_cast<Fn>(GetProcAddress(hModule, function_name.data()));
        }
    }
}
