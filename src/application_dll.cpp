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
        
    }

    __declspec(dllexport) void DetectCompromisedProcesses(LogCallback callback) {
        
    }

    __declspec(dllexport) void DetectEnabledPrivileges(LogCallback callback) {
        
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

}