#pragma once

#include "../SnapshotsProvider/snapshots_provider.h"
#include "../Analyzers/analyzer.h"
#include "../Analyzers/HiddenProcesses/hidden_processes_analyzer.h"
#include "../Analyzers/RWX/rwx_analyzer.h"
#include "../NtDll/ntdll.h"
#include "../domain.h"

#include <vector>
#include <memory>

namespace labaratory {

    using namespace std::literals;

    using SystemClock = std::chrono::system_clock;
    using PidToProcessIndex = std::unordered_map<DWORD, domain::ProcessInfo>;
    using SPProcessInfo = std::shared_ptr<domain::ProcessInfo>;


    class ProcessesLabaratory : public std::enable_shared_from_this<ProcessesLabaratory> {
    public:
        ProcessesLabaratory() {
            Analyzers_[domain::AnalyzerType::HiddenProcesses]
                = std::make_unique<analyze::HiddenProcessesAnalyzer>();
            Analyzers_[domain::AnalyzerType::CompromisedProcesses]
                = std::make_unique<analyze::RWXAnalyzer>();
        }

        std::vector<domain::SuspiciousProcess> DetectHiddenProcesses();
        std::vector<domain::SuspiciousProcess> DetectCompromisedProcesses();

    private:
        maltech::ntdll::NtDll ntdll_;
        analyze::Analyzers Analyzers_;
        SnapshotsProvider snapshots_provider_{ ntdll_ };

        std::vector<domain::SuspiciousProcess> FindHidenProcesses();
        std::vector<domain::SuspiciousProcess> FindCompromisedProcesses();

    };

}