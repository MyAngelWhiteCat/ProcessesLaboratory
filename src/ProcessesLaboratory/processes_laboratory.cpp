#include "processes_laboratory.h"
#include "../Logger/logger.h"
#include "../domain.h"

#include <future>
#include <stdexcept>
#include <vector>
#include <exception>
#include <utility>


namespace laboratory {

    using namespace std::literals;

    std::vector<domain::SuspiciousProcess> ProcessesLaboratory::StartFullScan() {
        std::vector<domain::SuspiciousProcess> result;
        try {
            domain::Scan scan = GetNtAndThSnapshots();
            auto hidden_future = std::async(std::launch::async
                , [&scan, self = shared_from_this()] {
                return self->FindHidenProcesses(scan);
                });
            auto compromised_future = std::async(std::launch::async
                , [&scan, self = shared_from_this()] {
                return self->FindCompromisedProcesses(scan);
                });
            result = std::move(compromised_future.get());
            auto hidden = std::move(hidden_future.get());
            result.reserve(result.size() + hidden.size());
            for (auto& elem : hidden) {
                result.push_back(std::move(elem));
            }
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Full scan error: "s + e.what());
        }
        return result;
    }

    std::vector<domain::SuspiciousProcess> ProcessesLaboratory::DetectHiddenProcesses() {
        std::vector<domain::SuspiciousProcess> hidden_processes;
        try {
            auto scans = GetNtAndThSnapshots();
            hidden_processes = FindHidenProcesses(scans);
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Error while checking for hidden processes: "s + e.what());
        }

        return hidden_processes;
    }

    std::vector<domain::SuspiciousProcess> ProcessesLaboratory::DetectCompromisedProcesses() {
        std::vector<domain::SuspiciousProcess> compromised_processes;
        try {
            auto scans = GetNtAndThSnapshots();
            compromised_processes = FindCompromisedProcesses(scans);
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Compomised processes detection error: "s + e.what());
        }
        return compromised_processes;
    }

    std::vector<domain::SuspiciousProcess> ProcessesLaboratory::DetectEscalatedPrivileges() {
        std::vector<domain::SuspiciousProcess> procs_with_escalated_privileges;
        try {
            domain::Scan scan;
            scan[domain::ScanMethod::NtQSI] = snapshots_provider_.GetNtSnapshot();
            procs_with_escalated_privileges = FindEscalatedPrivileges(scan);
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Escalated privileges detection error: "s + e.what());
        }
        return procs_with_escalated_privileges;
    }

    std::vector<domain::SuspiciousProcess> 
        ProcessesLaboratory::FindHidenProcesses(const domain::Scan& scan) {
        try {
            auto analyzer = analyzers_.find(domain::AnalyzerType::HiddenProcesses);
            if (analyzer == analyzers_.end()) {
                throw std::runtime_error("Hidden processes Analyzer not initialized");
            }

            LOG_DEBUG("Start finding hidden processes");
            return analyzer->second->Analyze(scan).suspicious_processes_;
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Hidden processes analyze error: "s + e.what());
        }

        return {}; // Dummy for no warning
    }

    std::vector<domain::SuspiciousProcess> 
        ProcessesLaboratory::FindCompromisedProcesses(const domain::Scan& scan) {
        try {
            auto analyzer = analyzers_.find(domain::AnalyzerType::CompromisedProcesses);
            if (analyzer == analyzers_.end()) {
                throw std::runtime_error("Compromised processes Analyzer not initialized");
            }
            LOG_DEBUG("Start finding compromised processes");
            return analyzer->second->Analyze(scan).suspicious_processes_;
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Compromised process analyze error: "s + e.what());
        }
        return {}; // Dummy for no warning
    }

    std::vector<domain::SuspiciousProcess> 
        ProcessesLaboratory::FindEscalatedPrivileges(const domain::Scan& scan) {
        try {
            auto analyzer = analyzers_.find(domain::AnalyzerType::EscalatedPrivileges);
            if (analyzer == analyzers_.end()) {
                throw std::runtime_error("Escalated priviliges analyzer not init");
            }
            LOG_DEBUG("Start finding escalated privileges");
            return analyzer->second->Analyze(scan).suspicious_processes_;
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Ecalated privileges analyze error: "s + e.what());
        }
        return {};
    }

    domain::Scan ProcessesLaboratory::GetNtAndThSnapshots() {
        domain::Scan scan;
        auto snapshot_future = std::async(std::launch::async,
            [self = this->shared_from_this()] {
                return self->snapshots_provider_.GetToolHelpSnapshot();
            });
        auto ntsnapshot_future = std::async(std::launch::async,
            [self = this->shared_from_this()] {
                return self->snapshots_provider_.GetNtSnapshot();
            });
        scan[domain::ScanMethod::ToolHelp] = snapshot_future.get();
        scan[domain::ScanMethod::NtQSI] = ntsnapshot_future.get();
        return scan;
    }

}