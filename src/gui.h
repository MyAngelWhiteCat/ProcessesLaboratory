#pragma once

#include "application.h"

#include <Windows.h>
#include <mutex>
#include <string>
#include <string_view>

#define WM_APP_LOG_MESSAGE (WM_APP + 1)

using namespace std::literals;

class GUI {
public:
    GUI() = default;
    ~GUI() {
        if (hWnd_) {
            DestroyWindow(hWnd_);
        }
    }

    void Start();
    void Create(LPCWSTR wnd_name, HINSTANCE hInstance);
    void SetHwnd(HWND hWnd);

private:
    application::Application application_;
    HWND hWnd_{ nullptr };
    HWND listbox_{ nullptr };
    SIZE_T max_horizontal_size_{ 0 };

    static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    void CreateControls();
    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);
    ATOM RegisterMainWindow(HINSTANCE hInstance, LPCWSTR lpszClassName);
    void SetHorizontalScrollSize(std::wstring_view str);
    void LogToGUI(const std::wstring& text);

    // Application interactions =======================================================================

    void ScanForHiddenProcesses();
    void ScanForCompromisedProcesses();

    void StartFullScan();
    void StartScanForHiddenProcesses();
    void StartScanForCompromisedProcesses();
    void EmulateHardErrorHandling();
};

