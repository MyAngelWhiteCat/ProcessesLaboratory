#include "application_dll.h"
#include "domain.h"

#include <memory>
#include <utility>
#include <vector>

namespace application {

    ApplicationExportDLL* GetApp() {
        if (!app) {
            app = std::move(std::make_unique<ApplicationExportDLL>());
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

    void ApplicationExportDLL::AsyncDetectHiddenProcesses(LogCallback callback) {
        thread_pool_.AddTask([this, callback]() {
            callback(SerializeResult(laboratory_->DetectHiddenProcesses()).dump().c_str());
            });
    }

    void ApplicationExportDLL::AsyncDetectCompromisedProcesses(LogCallback callback) {
        thread_pool_.AddTask([this, callback]() {
            callback(SerializeResult(laboratory_->DetectCompromisedProcesses()).dump().c_str());
            });
    }

    void ApplicationExportDLL::AsyncDetectEnabledPrivileges(LogCallback callback) {
        thread_pool_.AddTask([this, callback]() {
            callback(SerializeResult(laboratory_->DetectEnabledPrivileges()).dump().c_str());
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
            serialized_result.push_back(serialized_suspect);
        }
        return serialized_result;
    }

    ApplicationExportDLL::ApplicationExportDLL()
        : laboratory_(std::make_shared<laboratory::ProcessesLaboratory>())
    {
    }

}