#include "hidden_processes_analyzer.h"
#include "analyzer.h"
#include "domain.h"

#include <stdexcept>


namespace proc_scan {

    namespace labaratory {

        AnalyzeResult HiddenProcessesAnalyzer::StartAnalyze(domain::Scan&& scan) {
            if (!(scan.contains(domain::ScanMethod::NtQSI)
                && scan.contains(domain::ScanMethod::ToolHelp))) {
                throw std::invalid_argument("Invalid scan");
            }

            auto& nt_scan = scan.at(domain::ScanMethod::NtQSI);
            auto& th_scan = scan.at(domain::ScanMethod::ToolHelp);

            if (nt_scan.pid_to_proc_info_.empty() || th_scan.pid_to_proc_info_.empty()) {
                throw std::invalid_argument("Empty snapshot");
            }

            AnalyzeResult result;
            for (const auto& [pid, sp_proc] : nt_scan.pid_to_proc_info_) {
                if (!th_scan.pid_to_proc_info_.contains(pid)) {
                    result.suspicious_processes_.emplace_back(sp_proc,
                        "Captured by NtSnapshot but do not exist in ToolHelp snapshot");
                }
            }
            return result;
        }

    }

}
