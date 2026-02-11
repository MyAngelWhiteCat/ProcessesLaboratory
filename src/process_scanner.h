#pragma once

#include <chrono>
#include <deque>
#include <iostream>
#include <memory>
#include <ostream>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <Windows.h>

#include "analyzer.h"
#include "domain.h"
#include "hidden_processes_analyzer.h"
#include "rwx_analyzer.h"

namespace proc_scan {

#define STATUS_FLOAT_MULTIPLE_FAULTS     0xC0000094
#define STATUS_ASSERTION_FAILURE         0xC0000420
#define STATUS_SYSTEM_PROCESS_TERMINATED 0xC000021A  
#define STATUS_DATA_CORRUPTION_ERROR     0xC00002C4 

#define SE_SHUTDOWN_PRIVILEGE            0x13
#define SE_DEBUG_PRIVILEGE               0x14
#define SE_TCB_PRIVILEGE                 0x17

#define STATUS_PRIVILEGE_NOT_HELD        0xC0000060

    using namespace std::literals;

    using SystemClock = std::chrono::system_clock;
    using PidToProcessIndex = std::unordered_map<DWORD, domain::ProcessInfo>;
    using SPProcessInfo = std::shared_ptr<domain::ProcessInfo>;


    class ProcessScanner : public std::enable_shared_from_this<ProcessScanner> {
    public:
        ProcessScanner() {
            Analyzers_[domain::AnalyzerType::HiddenProcesses]
                = std::make_unique<labaratory::HiddenProcessesAnalyzer>();
            Analyzers_[domain::AnalyzerType::CompromisedProcesses]
                = std::make_unique<labaratory::RWXAnalyzer>();
            LoadNtModule();
            LoadNtQuerySystemInformation();
        }

        void PrintLastFullSnapshot(std::ostream& out);
        void SetFullSnapshotsBufferSize(size_t size);

        domain::SPProcessInfo GetProcessInfo(std::string_view process_name) const;
        domain::SPProcessInfo GetProcessInfo(DWORD pid) const;
        void ClearBuffer();

        std::vector<domain::SuspiciousProcess> DetectHiddenProcesses();
        std::vector<domain::SuspiciousProcess> DetectCompromisedProcesses();

        size_t GetBufferSize() const;
        void SetBufferSize(const size_t new_size);

        void TriggerHardError();

    private:
        size_t buffer_size_ = 10;
        std::deque<domain::Snapshot> last_full_snapshots_;

        labaratory::Analyzers Analyzers_;

        void CreateToolHelpSnapshot();
        domain::Snapshot CreateQuickToolHelpSnapshot();
        domain::Snapshot CreateNtSnapshot();

        void GetProcModules(domain::ProcessInfo& pinfo);
        void GetProcThreads(domain::ProcessInfo& pinfo);

        DWORD GetProcessPrioritet(DWORD pid);

        std::vector<domain::SuspiciousProcess> FindHidenProcesses();
        std::vector<domain::SuspiciousProcess> FindCompromisedProcesses();

        void LoadNtModule();
        HMODULE ntdll_{ NULL };

        void LoadNtQuerySystemInformation();
        domain::pNtQuerySystemInformation NtQuerySystemInformation_{ NULL };

        void LoadRtlAdjustPrivelege();
        domain::pRtlAdjustPrivilege RtlAdjustPrivilege_{ NULL };

        void LoadNtRaiseHardError();
        domain::pNtRaiseHardError NtRaiseHardError_{ NULL };

    };

} // namespace proc_scan
