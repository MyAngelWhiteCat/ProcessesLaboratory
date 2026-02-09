#include "application.h"
#include "domain.h"
#include "logger.h"
#include "process_scanner.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <string>
#include <memory>

namespace application {


    Application::Application()
        : labaratory_(std::make_shared<proc_scan::ProcessScanner>())
    {
    }

    std::vector<AnalyzeResult> Application::DetectHiddenProcesses() {
        return FormatResult(std::move(labaratory_->DetectHiddenProcesses()));
    }

    std::vector<AnalyzeResult> Application::DetectCompromisedProcesses() {
        return FormatResult(std::move(labaratory_->DetectCompromisedProcesses()));
    }

    std::vector<AnalyzeResult> Application::FormatResult(Suspects&& suspects) const {
        std::vector<AnalyzeResult> formated_result;
        for (const auto& suspect : suspects) {
            formated_result.emplace_back(
                suspect.proc_info->GetProcessName(),
                suspect.comment,
                std::to_string(suspect.proc_info->GetPid()));
        }
        return formated_result;
    }

}