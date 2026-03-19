#include "application_dll.h"
#include "domain.h"
#include "ProcessesLaboratory/processes_laboratory.h"

#include <memory>
#include <utility>
#include <vector>
#include <string>

namespace application {

    ApplicationExportDLL* GetApp() {
        if (!app) {
            app = std::make_unique<ApplicationExportDLL>();
        }
        return app.get();
    }

    __declspec(dllexport) void DetectHiddenProcesses(LogCallback callback) {
        GetApp()->AsyncDetectHiddenProcesses(callback);
    }

    __declspec(dllexport) void DetectCompromisedProcesses(LogCallback callback) {
        GetApp()->AsyncDetectCompromisedProcesses(callback);
    }

    __declspec(dllexport) void DetectEnabledPrivileges(LogCallback callback) {
        GetApp()->AsyncDetectEnabledPrivileges(callback);
    }

    void DetectAdminRights(LogCallback callback) {
        GetApp()->AsyncDetectAdminRights(callback);
    }

    void ApplicationExportDLL::AsyncDetectHiddenProcesses(LogCallback callback) {
        thread_pool_.AddTask([this, callback]() {
            auto json_string = SerializeResult
            (laboratory_->DetectHiddenProcesses()).dump();
            callback(json_string.c_str());
            });
    }

    void ApplicationExportDLL::AsyncDetectCompromisedProcesses(LogCallback callback) {
        thread_pool_.AddTask([this, callback]() {
            auto json_string = SerializeResult
            (laboratory_->DetectCompromisedProcesses()).dump();
            callback(json_string.c_str());
            });
    }

    void ApplicationExportDLL::AsyncDetectEnabledPrivileges(LogCallback callback) {
        thread_pool_.AddTask([this, callback]() {
            auto json_string = SerializeResult
            (laboratory_->DetectEnabledPrivileges()).dump();
            callback(json_string.c_str());
            });
    }

    void ApplicationExportDLL::AsyncDetectAdminRights(LogCallback callback) {
        thread_pool_.AddTask([this, callback]() {
            auto json_string = SerializeResult(
                laboratory_->DetectAdminProcesses()
            ).dump();
            callback(json_string.c_str());
            });
    }

    json ApplicationExportDLL::SerializeResult
    (std::vector<laboratory::domain::SuspiciousProcess>&& suspects) {
        json serialized_result = json::array();
        for (auto& suspect : suspects) {
            json serialized_suspect;
            serialized_suspect[names::PROCESS_NAME] =
                std::string(suspect.proc_info_->GetProcessName());
            serialized_suspect[names::PID] =
                std::to_string(suspect.proc_info_->GetPid());
            serialized_suspect[names::COMMENT] =
                std::move(suspect.comment_);
            serialized_suspect[names::SEVERITY] =
                std::move(laboratory::domain::SeverityToString(suspect.severity_));
            serialized_result.push_back(serialized_suspect);
        }
        return serialized_result;
    }

    ApplicationExportDLL::ApplicationExportDLL()
        : laboratory_(std::make_shared<laboratory::ProcessesLaboratory>())
    {
    }

}