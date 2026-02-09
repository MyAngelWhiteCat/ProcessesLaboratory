#include "application.h"
#include "logger.h"

#include <iostream>
#include <memory>

void ScanForHiddenProcesses(application::Application& application) {
    auto hp = application.DetectHiddenProcesses();
    if (hp.empty()) {
        LOG_INFO("No hidden processes found");
    }
    else {
        for (const auto& hidden_proc : hp) {
            std::cout << "Suspicious process: \n"
                << "[" << hidden_proc.pid_ << "] " 
                <<hidden_proc.process_name_
                << "\nReason: " << hidden_proc.comment_ << "\n";
        }
    }
}

void ScanForCompromisedProcesses(application::Application& application) {
    auto cp = application.DetectCompromisedProcesses();
    if (cp.empty()) {
        LOG_INFO("No compromised processes found");
    }
    else {
        for (const auto& compromised_proc : cp) {
            std::cout << "Suspicious process: \n"
                << "[" << compromised_proc.pid_ << "] "
                << compromised_proc.process_name_
                << "\nReason: " << compromised_proc.comment_ << "\n";
        }
    }
}

int main() {
    logging::Logger logger;
    logger.Init();

    try {
        application::Application application;
        ScanForHiddenProcesses(application);
        ScanForCompromisedProcesses(application);
    }
    catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
    }


}