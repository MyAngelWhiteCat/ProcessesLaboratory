#include "application.h"
#include "domain.h"
#include "logger.h"

#include <vector>
#include <string>

namespace application {

    std::vector<AnalyzeResult> Application::DetectHiddenProcesses() {
        return std::vector<AnalyzeResult>();
    }

    std::vector<AnalyzeResult> Application::DetectCompromisedProcesses() {
        return std::vector<AnalyzeResult>();
    }

}