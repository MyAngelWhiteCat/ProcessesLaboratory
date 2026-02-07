#include "process_scanner.h"

#include <iostream>


int main() {
    proc_scan::ProcessScanner proc_scanner;
    try {
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
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }


}