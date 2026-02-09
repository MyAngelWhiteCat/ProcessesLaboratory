#include "application.h"
#include "domain.h"
#include "logger.h"
#include "process_scanner.h"

#include <vector>
#include <string>
#include <memory>

namespace application {


    Application::Application()
        : labaratory_(std::make_shared<proc_scan::ProcessScanner>())
    {
    }

    std::vector<AnalyzeResult> Application::DetectHiddenProcesses() {
        return std::vector<AnalyzeResult>();
    }

    std::vector<AnalyzeResult> Application::DetectCompromisedProcesses() {
        return std::vector<AnalyzeResult>();
    }

}