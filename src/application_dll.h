#pragma once 
#include "application.h"

#include <memory>

namespace application {

    typedef void (*LogCallback)(const char* result);

    static std::unique_ptr<Application> app;
    Application* GetApp();

    extern "C" {
        __declspec(dllexport) void GetDetectedHiddenProcesses(LogCallback callback);
        __declspec(dllexport) void GetDetectedCompromisedProcesses(LogCallback callback);
        __declspec(dllexport) void GetDetectedEnabledPrivileges(LogCallback callback);
    }

}