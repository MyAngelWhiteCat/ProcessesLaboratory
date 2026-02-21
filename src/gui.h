#pragma once

#include "application.h"

#include <Windows.h>
#include <string>
#include <string_view>
#include <vector>

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
    HWND debug_console_{ nullptr };
    SIZE_T max_horizontal_size_{ 0 };
    const int scan_count_ = 2;// For "full scan complete" output...
    int completed_scans_ = 0;//  For "full scan complete" output...

    static LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
    void CreateControls();
    LRESULT HandleMessage(UINT message, WPARAM wParam, LPARAM lParam);
    ATOM RegisterMainWindow(HINSTANCE hInstance, LPCWSTR lpszClassName);
    void SetHorizontalScrollSize(std::wstring_view str);
    void LogToGUI(const std::wstring& text) const;
    void OutputFullScanProgress();

    // Application interactions =======================================================================

    void OutputHiddenProcessesScanResult(const std::vector<application::AnalyzeResult>& hp);
    void OutputCompromisedProcessesScanResult(const std::vector<application::AnalyzeResult>& cp);
    void OutputEscalatedPrivilegesScanResult(const std::vector<application::AnalyzeResult>& ep);
};

