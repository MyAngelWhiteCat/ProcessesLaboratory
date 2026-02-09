#pragma once

#include "process_scanner.h"
#include "domain.h"

#include <vector>
#include <string>

namespace application {

    class Application {
    public:
        
        std::vector<proc_scan::domain::SuspiciousProcess> DetectHiddenProcesses();
        std::vector<proc_scan::domain::SuspiciousProcess> DetectCompromisedProcesses();


    private:
        proc_scan::ProcessScanner labaratory_;

        std::string FormatToString(std::vector<proc_scan::domain::SuspiciousProcess>);

    };

}