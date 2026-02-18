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

#include "../Analyzers/analyzer.h"
#include "../domain.h"
#include "../Analyzers/HiddenProcesses/hidden_processes_analyzer.h"
#include "../Analyzers/RWX/rwx_analyzer.h"

namespace labaratory {

    using namespace std::literals;

    using SystemClock = std::chrono::system_clock;
    using PidToProcessIndex = std::unordered_map<DWORD, domain::ProcessInfo>;
    using SPProcessInfo = std::shared_ptr<domain::ProcessInfo>;


    class ProcessScanner : public std::enable_shared_from_this<ProcessScanner> {
    public:
        ProcessScanner() {
            Analyzers_[domain::AnalyzerType::HiddenProcesses]
                = std::make_unique<analyze::HiddenProcessesAnalyzer>();
            Analyzers_[domain::AnalyzerType::CompromisedProcesses]
                = std::make_unique<analyze::RWXAnalyzer>();
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

    private:
        size_t buffer_size_ = 10;
        std::deque<domain::Snapshot> last_full_snapshots_;

        analyze::Analyzers Analyzers_;

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

    };

} // namespace labaratory
