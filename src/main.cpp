#include "Logger/logger.h"
#include "gui.h"

#include <exception>
#include <Windows.h>



using namespace std::literals;

int main() {
    try {
        logging::Logger logger;
        logger.Init();
        LPCWSTR wnd_name = L"ProcLab";
        HINSTANCE hInstance = GetModuleHandleW(NULL);
        GUI gui;
        gui.Create(wnd_name, hInstance);
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        gui.Start();
    }
    catch (const std::exception& e) {
        LOG_CRITICAL("System error: "s.append(e.what()));
        MessageBox(NULL, e.what(), "System Error", MB_ICONERROR);
    }

}




