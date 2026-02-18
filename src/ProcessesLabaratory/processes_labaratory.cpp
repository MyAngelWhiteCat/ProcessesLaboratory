#include "processes_labaratory.h"
#include "../Logger/logger.h"
#include "../domain.h"

#include <future>
#include <stdexcept>
#include <vector>
#include <exception>
#include <utility>


namespace labaratory {

    using namespace std::literals;

    std::vector<domain::SuspiciousProcess> ProcessesLabaratory::DetectHiddenProcesses() {
        std::vector<domain::SuspiciousProcess> hidden_processes;
        try {
            hidden_processes = FindHidenProcesses();
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Error while checking for hidden processes: "s + e.what());
        }

        return hidden_processes;
    }

    std::vector<domain::SuspiciousProcess> ProcessesLabaratory::DetectCompromisedProcesses() {
        std::vector<domain::SuspiciousProcess> compromised_processes;
        try {
            compromised_processes = FindCompromisedProcesses();
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Compomised processes detection error: "s + e.what());
        }
        return compromised_processes;
    }

    std::vector<domain::SuspiciousProcess> ProcessesLabaratory::FindHidenProcesses() {
        try {
            domain::Scan scan;
            auto snapshot_future = std::async(std::launch::async,
                [self = this->shared_from_this()] {
                    return self->snapshots_provider_.GetToolHelpSnapshot();
                });
            auto ntsnapshot_future = std::async(std::launch::async,
                [self = this->shared_from_this()] {
                    return self->snapshots_provider_.GetNtSnapshot();
                });

            auto analyzer = Analyzers_.find(domain::AnalyzerType::HiddenProcesses);
            if (analyzer == Analyzers_.end()) {
                throw std::runtime_error("Hidden processes Analyzer not initialized");
            }

            scan[domain::ScanMethod::ToolHelp] = snapshot_future.get();
            scan[domain::ScanMethod::NtQSI] = ntsnapshot_future.get();

            LOG_DEBUG("Snapshots ready. Start finding hidden processes");
            return analyzer->second->Analyze(std::move(scan)).suspicious_processes_;
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Hidden processes analyze error: "s + e.what());
        }

        return {}; // Dummy for no warning
    }

    std::vector<domain::SuspiciousProcess> ProcessesLabaratory::FindCompromisedProcesses() {
        domain::Scan scan;
        try {
            auto snapshot_future = std::async(std::launch::async,
                [self = this->shared_from_this()] {
                    return self->snapshots_provider_.GetNtSnapshot();
                });

            auto analyzer = Analyzers_.find(domain::AnalyzerType::CompromisedProcesses);
            if (analyzer == Analyzers_.end()) {
                throw std::runtime_error("Compromised processes Analyzer not initialized");
            }

            scan[domain::ScanMethod::NtQSI] = snapshot_future.get();

            LOG_DEBUG("Snapshots ready. Start finding compromised processes");
            return analyzer->second->Analyze(std::move(scan)).suspicious_processes_;
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Compromised process analyze error: "s + e.what());
        }
        return {}; // Dummy for no warning
    }

}