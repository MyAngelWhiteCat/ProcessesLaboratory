#include "process_scanner.h"

#include <iostream>

int main() {
    proc_scan::ProcessScanner proc_scanner;

    proc_scanner.CreateFullSnapshot();
    proc_scanner.PrintLastFullSnapshot(std::cout);

    if (auto proc = proc_scanner.GetProcessInfo("svchost.exe")) {
        std::cout << "Founded: \n";
        proc->Print(std::cout);
    }
}