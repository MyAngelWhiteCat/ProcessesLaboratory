#include "process_scanner.h"

#include <iostream>


int main() {
    proc_scan::ProcessScanner proc_scanner;
    try {
        auto hp = proc_scanner.CheckForHiddenProcesses();
        if (hp.empty()) {
            std::cout << "No hidden processes found" << std::endl;
        }
        else {
            for (const auto& hidden_proc : hp) {
                hidden_proc->Print(std::cout);
            }
        }
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }


}