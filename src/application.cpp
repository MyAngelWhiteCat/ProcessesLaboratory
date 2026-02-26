#include "application.h"
#include "domain.h"
#include "Logger/logger.h"
#include "ProcessesLaboratory/processes_laboratory.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace application {

    static std::unique_ptr<Application> app;

    Application* GetApp() {
        if (!app) {
            app = std::make_unique<Application>();
        }
        return app.get();
    }

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

    json SerializeResult(std::vector<AnalyzeResult>&& suspects) {
        json serialized_result = json::array();
        for (auto& suspect : suspects) {
            json serialized_suspect;
            serialized_suspect[names::PROCESS_NAME] =
                std::move(suspect.process_name_);
            serialized_suspect[names::PID] =
                std::move(suspect.pid_);
            serialized_suspect[names::COMMENT] =
                std::move(suspect.comment_);
            serialized_result.push_back(serialized_suspect);
        }
        return serialized_result;
    }

    APPLICATION_API const char* GetDetectedHiddenProcesses() {
        static std::string result;
        result = SerializeResult(std::move(GetApp()->DetectHiddenProcesses())).dump();
        return result.c_str();
    }

    APPLICATION_API const char* GetDetectedCompromisedProcesses() {
        static std::string result;
        result = SerializeResult(std::move(GetApp()->DetectCompromisedProcesses())).dump();
        return result.c_str();
    }

    APPLICATION_API const char* GetDetectedEnabledPrivileges() {
        static std::string result;
        result = SerializeResult(std::move(GetApp()->DetectEnabledPrivileges())).dump();
        return result.c_str();
    }

}