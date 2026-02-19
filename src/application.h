#pragma once

#include "domain.h"
#include "ProcessesLaboratory/processes_laboratory.h"
#include "ThreadPool/thread_pool.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <Windows.h>


namespace application {

    using Suspects = std::vector<laboratory::domain::SuspiciousProcess>;

    struct AnalyzeResult {
        AnalyzeResult(
            std::string&& process_name,
            std::string&& comment,
            std::string&& pid)
            : process_name_(std::move(process_name))
            , comment_(std::move(comment))
            , pid_(std::move(pid)) 
        {
        }

        std::string process_name_;
        std::string comment_;
        std::string pid_;
    };

    class Application {
    public:
        Application();

        template <typename Callback>
        void AsyncDetectHiddenProcesses(Callback&& callback);
        template <typename Callback>
        void AsyncDetectCompromisedProcesses(Callback&& callback);

    private:
        ThreadPool thread_pool_{ GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS) };
        std::shared_ptr<laboratory::ProcessesLaboratory> laboratory_;
        std::vector<AnalyzeResult> FormatResult(Suspects&& suspects) const;


        std::vector<AnalyzeResult> DetectHiddenProcesses();
        std::vector<AnalyzeResult> DetectCompromisedProcesses();
    };

    template<typename Callback>
    inline void Application::AsyncDetectHiddenProcesses(Callback&& callback) {
        auto detect_func = [callback = std::forward<Callback>(callback), this] {
            callback(DetectHiddenProcesses());
            };
        thread_pool_.AddTask(detect_func);
    }

    template<typename Callback>
    inline void Application::AsyncDetectCompromisedProcesses(Callback&& callback) {
        auto detect_func = [callback = std::forward<Callback>(callback), this] {
            callback(DetectCompromisedProcesses());
            };
        thread_pool_.AddTask(detect_func);
    }

}