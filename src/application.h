#pragma once

#include "domain.h"
#include "process_scanner.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>


namespace application {

    using Suspects = std::vector<proc_scan::domain::SuspiciousProcess>;

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
        
        std::vector<AnalyzeResult> DetectHiddenProcesses();
        std::vector<AnalyzeResult> DetectCompromisedProcesses();


    private:
        std::shared_ptr<proc_scan::ProcessScanner> labaratory_;

        std::vector<AnalyzeResult> FormatResult(Suspects&& suspects) const;
    };

}