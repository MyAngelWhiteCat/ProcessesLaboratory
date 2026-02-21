#include "application.h"
#include "domain.h"
#include "Logger/logger.h"
#include "ProcessesLaboratory/processes_laboratory.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace application {

    Application::Application()
        : laboratory_(std::make_shared<laboratory::ProcessesLaboratory>())
    {
        LOG_DEBUG("Application constructed");
    }

    std::vector<AnalyzeResult> Application::FullScan() {
        return FormatResult(std::move(laboratory_->StartFullScan()));
    }

    std::vector<AnalyzeResult> Application::DetectHiddenProcesses() {
        return FormatResult(std::move(laboratory_->DetectHiddenProcesses()));
    }

    std::vector<AnalyzeResult> Application::DetectCompromisedProcesses() {
        return FormatResult(std::move(laboratory_->DetectCompromisedProcesses()));
    }

    std::vector<AnalyzeResult> Application::DetectEnabledPrivileges() {
        return FormatResult(std::move(laboratory_->DetectEnabledPrivileges()));
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