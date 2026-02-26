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

    __declspec(dllexport) void GetDetectedHiddenProcesses(LogCallback callback) {
        
    }

    __declspec(dllexport) void GetDetectedCompromisedProcesses(LogCallback callback) {
        
    }

    __declspec(dllexport) void GetDetectedEnabledPrivileges(LogCallback callback) {
        
    }

    json ApplicationExportDLL::SerializeResult
    (std::vector<laboratory::domain::AnalyzeResult>&& suspects) {
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

}