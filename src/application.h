#pragma once

#include "process_scanner.h"
#include "logger.h"

#include <vector>
#include <string>


namespace application {

    struct AnalyzeResult {
        std::string process_name;
        std::string comment;
        std::string pid;
    };

    class Application {
    public:
        
        std::vector<AnalyzeResult> DetectHiddenProcesses();
        std::vector<AnalyzeResult> DetectCompromisedProcesses();


    private:
        proc_scan::ProcessScanner labaratory_;


    };

}