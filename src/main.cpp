#include "process_scanner.h"
#include "logger.h"

#include <iostream>
#include <memory>

void ScanForHiddenProcesses(std::shared_ptr<proc_scan::ProcessScanner> proc_scanner) {
    auto hp = proc_scanner->DetectHiddenProcesses();
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

void ScanForCompromisedProcesses(std::shared_ptr<proc_scan::ProcessScanner> proc_scanner) {
    auto hp = proc_scanner->DetectCompromisedProcesses();
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
        auto proc_scanner = std::make_shared<proc_scan::ProcessScanner>();
        ScanForHiddenProcesses(proc_scanner);
        ScanForCompromisedProcesses(proc_scanner);
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }


}