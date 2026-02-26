#pragma once 
#include "application.h"

namespace application {

    typedef void (*LogCallback)(const char* result);

    extern "C" {
        __declspec(dllexport) void GetDetectedHiddenProcesses(LogCallback callback);
        __declspec(dllexport) void GetDetectedCompromisedProcesses(LogCallback callback);
        __declspec(dllexport) void GetDetectedEnabledPrivileges(LogCallback callback);
    }


}