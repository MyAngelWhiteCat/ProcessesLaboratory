#pragma once

#include <Windows.h>
#include <winternl.h>

#include <chrono>
#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>
#include "logger.h"
#include <stdexcept>


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
        
        // names of functions from ntdll.dll for loading
        struct NtNames {
            NtNames() = delete;
            static constexpr std::wstring_view NTDLL = L"ntdll.dll";
            static constexpr std::string_view NTQSI = "NtQuerySystemInformation";
        };

        // ptr template for NtQuerySystemInformation loaded from ntdll.dll
        typedef NTSTATUS(*pNtQuerySystemInformation)(
            SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation,
            ULONG SystemInformationLength,
            PULONG ReturnLength
            );


        enum class ScanMethod {
            ToolHelp = 0,
            NtQSI = 1
        };

        enum class AnalyzerType {
            HiddenProcesses = 0,
            CompromisedProcesses = 1
        };

        // WIP
        enum class ScanStrategy {
            Quick = 0, // "just check there is no some malware.exe" for the future database
            Base = 1, // classic scan of hidden procs, RWX regions and some future stuff
            Full = 2, // all scans, all analyzers
            Runtime = 3 // some circle of scans and analyzers
        };

        enum class MemDetection {
            ERROR_VALUE = 0,
            RWX = 1,
            RW_TO_RX = 2,
            RX_TO_RW = 3
        };

        struct SuspiciousMemory {
            std::optional<MemDetection> detection_;
            SIZE_T address_ = 0;
            SIZE_T size_bytes_ = 0;

            void Reset() {
                detection_.reset();
                address_ = 0;
                size_bytes_ = 0;
            }

            MemDetection GetDetection() {
                if (!detection_.has_value()) {
                    return MemDetection::ERROR_VALUE;
                }
                return detection_.value();
            }
        };

        enum class Severity {
            INFO = 0,
            SUSPICIOUS = 1,
            MALWARE = 2,
            CRITICAL = 3
        };

        struct SuspiciousProcess {
            SPProcessInfo proc_info_;
            std::string comment_;
            std::vector<SuspiciousMemory> suspicious_memory_;
            Severity severity_;
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

            void Print(std::ostream& out) const;
            void PrintModules(std::ostream& out) const;
            void PrintThreads(std::ostream& out) const;

            void SetPid(DWORD pid);
            DWORD GetPid() const;

            void SetPriority(DWORD priority);
            DWORD GetPriority() const;

            void SetThreadsCount(DWORD thread_count);
            DWORD GetThreadCount() const;

            void SetProcessName(std::string&& name);

            void SetProcessName(std::string_view name);
            const std::string_view GetProcessName() const;

            void AddModule(const ModuleInfo& module_info);
            void AddModule(ModuleInfo&& module_info);
            void SetModules(const std::vector<ModuleInfo>& modules);
            void SetModules(std::vector<ModuleInfo>&& modules);
            std::vector<ModuleInfo> GetModules() const;

            void AddThread(const ThreadInfo& thread_info);
            void AddThread(ThreadInfo&& thread_info);
            void SetThreads(std::vector<ThreadInfo>&& threads);
            void SetThreads(const std::vector<ThreadInfo>& threads);
            std::vector<ThreadInfo> GetThreads() const;

            void SetTimestamp();
            Clock::time_point GetTimestamp() const;

            HANDLE Open(DWORD access);
            BOOL Close() const;

        private:
            DWORD pid_{ 0 };
            DWORD priority_{ 0 };
            DWORD threads_count_{ 0 };
            std::string process_name_;

            Clock::time_point timestamp_{ Clock::now() };

            std::vector<ModuleInfo> modules_;
            std::vector<ThreadInfo> threads_;

            HANDLE hProcess_{ 0 };
        };

        struct Snapshot {
            Snapshot(Clock::time_point time) 
                : time_(time)
            {

            }

            Snapshot() {
                time_ = Clock::now();
            }

            void Insert(std::shared_ptr<ProcessInfo> proc_info);

            Clock::time_point time_;
            PidToProcessIndex pid_to_proc_info_;
            ExeNameToProcessIndex proc_name_to_proc_info_;

            size_t Size() const;

            std::shared_ptr<ProcessInfo> GetProcessInfo(std::string_view process_name) const;
            std::shared_ptr<ProcessInfo> GetProcessInfo(DWORD pid) const;
        };

        // Helpers methods
        std::string WideCharToString(const WCHAR* wstr);
        std::unique_ptr<std::wstring> StringToWideChar(std::string_view str);
        std::string UnicodeToString(const UNICODE_STRING& ustr);
        HMODULE LoadModule(std::wstring_view module_name);

        template<typename Fn>
        Fn LoadFunctionFromModule(HMODULE hModule, std::string_view function_name) {
            Fn func = reinterpret_cast<Fn>(GetProcAddress(hModule, function_name.data()));
            if (!func) {
                throw std::runtime_error("Incorrect load func: " + std::string(function_name));
            }
            LOG_DEBUG(std::string(function_name).append(" loaded"));
            return func;
        }
    }
}
