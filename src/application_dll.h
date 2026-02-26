#pragma once 
#include "application.h"

#ifdef APPLICATION_EXPORT
#define APPLICATION_API __declspec(dllexport)
#else
#define APPLICATION_API __declspec(dllimport)
#endif

extern "C" {
    APPLICATION_API const char* GetDetectedHiddenProcesses();
    APPLICATION_API const char* GetDetectedCompromisedProcesses();
    APPLICATION_API const char* GetDetectedEnabledPrivileges();
}