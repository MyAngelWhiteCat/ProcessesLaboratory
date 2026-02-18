#include "application.h"
#include "domain.h"
#include "Logger/logger.h"
#include "ProcessScanner/process_scanner.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace application {

    Application::Application()
        : labaratory_(std::make_shared<labaratory::ProcessScanner>())
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
        for (auto& suspect : suspects) {
            formated_result.emplace_back(
                std::string(suspect.proc_info_->GetProcessName()),
                std::move(suspect.comment_),
                std::to_string(suspect.proc_info_->GetPid()));
        }
        return formated_result;
    }

}