#pragma once

#include "../SnapshotsProvider/snapshots_provider.h"
#include "../Analyzers/analyzer.h"
#include "../Analyzers/HiddenProcesses/hidden_processes_analyzer.h"
#include "../Analyzers/RWX/rwx_analyzer.h"
#include "../Analyzers/EscalatedPrivileges/privilege_analyzer.h"
#include "../NtDll/ntdll.h"
#include "../domain.h"

#include <vector>
#include <memory>

namespace laboratory {

    using namespace std::literals;

    using SystemClock = std::chrono::system_clock;
    using PidToProcessIndex = std::unordered_map<DWORD, domain::ProcessInfo>;
    using SPProcessInfo = std::shared_ptr<domain::ProcessInfo>;


    class ProcessesLaboratory : public std::enable_shared_from_this<ProcessesLaboratory> {
    public:
        ProcessesLaboratory() {
            analyzers_[domain::AnalyzerType::HiddenProcesses]
                = std::make_unique<analyze::HiddenProcessesAnalyzer>();
            analyzers_[domain::AnalyzerType::CompromisedProcesses]
                = std::make_unique<analyze::RWXAnalyzer>();
            analyzers_[domain::AnalyzerType::EscalatedPrivileges]
                = std::make_unique<analyze::PrivilegeAnalyzer>(ntdll_);
        }

        std::vector<domain::SuspiciousProcess> StartFullScan();
        std::vector<domain::SuspiciousProcess> DetectHiddenProcesses();
        std::vector<domain::SuspiciousProcess> DetectCompromisedProcesses();
        std::vector<domain::SuspiciousProcess> DetectEscalatedPrivileges();

    private:
        maltech::ntdll::NtDll ntdll_;
        analyze::Analyzers analyzers_;
        SnapshotsProvider snapshots_provider_{ ntdll_ };
        maltech::escalator::PrivilegeEscalator privilege_escalator{ ntdll_ };

        std::vector<domain::SuspiciousProcess> FindHidenProcesses(const domain::Scan& scan);
        std::vector<domain::SuspiciousProcess> FindCompromisedProcesses(const domain::Scan& scan);
        std::vector<domain::SuspiciousProcess> FindEscalatedPrivileges(const domain::Scan& scan);


        domain::Scan GetNtAndThSnapshots();
    };

}