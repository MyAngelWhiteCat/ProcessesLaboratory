#include "Logger/logger.h"

#include <exception>
#include <Windows.h>
#include <iostream>


using namespace std::literals;

typedef void (*LogCallback)(const char* result);

typedef void(*pDetectCompromisedProcesses)(
    LogCallback
    );

void TestCallback(const char* text) {
    std::cout << text << std::endl;
}

int main() {
    try {
        logging::Logger logger;
        logger.Init();

        HMODULE module = LoadLibraryA("ProcessesLaboratoryApp.dll");
        auto* DetectCompromisedProcesses = 
            reinterpret_cast<pDetectCompromisedProcesses>
            (GetProcAddress(module, "DetectCompromisedProcesses"));
        
        DetectCompromisedProcesses(TestCallback);
        while (true) {
            Sleep(1000);
        }
    }
    catch (const std::exception& e) {
        LOG_CRITICAL("Error: "s.append(e.what()));
        MessageBox(NULL, e.what(), "Error", MB_ICONERROR);
    }

}




