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
        __declspec(dllexport) void DetectHiddenProcesses(LogCallback callback);
        __declspec(dllexport) void DetectCompromisedProcesses(LogCallback callback);
        __declspec(dllexport) void DetectEnabledPrivileges(LogCallback callback);
    }

    class ApplicationExportDLL {
    public:
        ApplicationExportDLL();

        void AsyncDetectHiddenProcesses(LogCallback callback);
        void AsyncDetectCompromisedProcesses(LogCallback callback);
        void AsyncDetectEnabledPrivileges(LogCallback callback);

    private:
        ThreadPool thread_pool_{ GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS) };
        std::shared_ptr<laboratory::ProcessesLaboratory> laboratory_;
        json SerializeResult(std::vector<laboratory::domain::SuspiciousProcess>&& suspects);
    };

    static std::unique_ptr<ApplicationExportDLL> app;
    ApplicationExportDLL* GetApp();

}