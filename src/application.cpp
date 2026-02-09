#include "application.h"

namespace application {



    std::vector<proc_scan::domain::SuspiciousProcess> Application::DetectHiddenProcesses() {
        return std::vector<proc_scan::domain::SuspiciousProcess>();
    }

    std::vector<proc_scan::domain::SuspiciousProcess> Application::DetectCompromisedProcesses() {
        return std::vector<proc_scan::domain::SuspiciousProcess>();
    }

    std::string Application::FormatToString(std::vector<proc_scan::domain::SuspiciousProcess>) {
        return std::string();
    }

}