#include "process_scanner.h"

#include <iostream>


void ScanForHiddenProcesses(proc_scan::ProcessScanner& proc_scanner) {
        auto hp = proc_scanner.DetectHiddenProcesses();
        if (hp.empty()) {
            std::cout << "No hidden processes found" << std::endl;
        }
    else {
        for (const auto& hidden_proc : hp) {
            std::cout << "Suspicious process: \n";
            hidden_proc.proc_info->Print(std::cout);
            std::cout << "Reason: " << hidden_proc.comment << "\n";
        }
    }
}

void ScanForCompromisedProcesses(proc_scan::ProcessScanner& proc_scanner) {
    auto hp = proc_scanner.DetectCompromisedProcesses();
    if (hp.empty()) {
        std::cout << "No compromised processes found" << std::endl;
    }
        else {
            for (const auto& hidden_proc : hp) {
                std::cout << "Suspicious process: \n";
                hidden_proc.proc_info->Print(std::cout);
                std::cout << "Reason: " << hidden_proc.comment << "\n";
            }
        }
    }

int main() {
    logging::Logger logger;
    logger.Init();

    try {
        ScanForHiddenProcesses(proc_scanner);
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }


}