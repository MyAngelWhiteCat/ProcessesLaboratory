#include "application_dll.h"
#include "application.h"

#include <memory>

namespace application {

    Application* GetApp() {
        if (!app) {
            app = std::make_unique<Application>();
        }
        return app.get();
    }

    __declspec(dllexport) void GetDetectedHiddenProcesses(LogCallback callback) {
        static std::string result;
        result = SerializeResult(std::move(GetApp()->DetectHiddenProcesses())).dump();
        callback(result.c_str());
    }

    __declspec(dllexport) void GetDetectedCompromisedProcesses(LogCallback callback) {
        static std::string result;
        result = SerializeResult(std::move(GetApp()->DetectCompromisedProcesses())).dump();
        callback(result.c_str());
    }

    __declspec(dllexport) void GetDetectedEnabledPrivileges(LogCallback callback) {
        static std::string result;
        result = SerializeResult(std::move(GetApp()->DetectEnabledPrivileges())).dump();
        callback(result.c_str());
    }

}