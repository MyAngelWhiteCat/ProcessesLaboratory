#include "application_dll.h"

namespace application {

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