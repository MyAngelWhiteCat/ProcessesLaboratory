#include "process_scanner.h"

#include <iostream>


int main() {
    proc_scan::ProcessScanner proc_scanner;

    proc_scanner.CreateSnapshot();
    proc_scanner.PrintLastFullSnapshot(std::cout);

    if (auto proc = proc_scanner.GetProcessInfo("Telegram.exe")) {
        std::cout << "Founded: \n";
        proc->Print(std::cout);
    }
}