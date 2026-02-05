#include "process_scanner.h"

#include <iostream>


int main() {
    proc_scan::ProcessScanner proc_scanner;
    try {
        if (auto proc = proc_scanner.GetProcessInfo("timer.exe")) {
            std::cout << "Founded: \n";
            proc->Print(std::cout);
        }
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }


}