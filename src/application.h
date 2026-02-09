#pragma once

#include "process_scanner.h"

#include <vector>
#include <string>
#include <memory>


namespace application {

    struct AnalyzeResult {
        std::string process_name;
        std::string comment;
        std::string pid;
    };

    class Application {
    public:
        Application();
        
        std::vector<AnalyzeResult> DetectHiddenProcesses();
        std::vector<AnalyzeResult> DetectCompromisedProcesses();


    private:
        std::shared_ptr<proc_scan::ProcessScanner> labaratory_;

    };

}