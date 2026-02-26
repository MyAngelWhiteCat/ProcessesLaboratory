#pragma once

#include "domain.h"
#include "ProcessesLaboratory/processes_laboratory.h"
#include "ThreadPool/thread_pool.h"

#include "nlohmann/json.hpp"
#include <nlohmann/json_fwd.hpp>

#include <memory>
#include <vector>

#include <Windows.h>

namespace application {

    using json = nlohmann::json;
    using names = laboratory::domain::SuspiciousProcessSerializerNames;

    typedef void (*LogCallback)(const char* result);


    extern "C" {
        __declspec(dllexport) void GetDetectedHiddenProcesses(LogCallback callback);
        __declspec(dllexport) void GetDetectedCompromisedProcesses(LogCallback callback);
        __declspec(dllexport) void GetDetectedEnabledPrivileges(LogCallback callback);
    }

    class ApplicationExportDLL {
    public:

    private:
        ThreadPool thread_pool_{ GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS) };
        std::shared_ptr<laboratory::ProcessesLaboratory> laboratory_;
        json SerializeResult(std::vector<laboratory::domain::AnalyzeResult>&& suspects);
    };

    static std::unique_ptr<ApplicationExportDLL> app;
    ApplicationExportDLL* GetApp();
}