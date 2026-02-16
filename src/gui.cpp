#include "domain.h"
#include "gui.h"
#include "Logger/logger.h"

#include <exception>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <Windows.h>

void GUI::Start() {
    MSG msg{ 0 };
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
}

void GUI::Create(LPCWSTR wnd_name, HINSTANCE hInstance) {
    ATOM reg_res = RegisterMainWindow(hInstance, wnd_name);
    if (!reg_res) {
        throw std::runtime_error("Window register error: "s.append(std::to_string(GetLastError())));
    }

    HWND hWnd = CreateWindowExW(0, wnd_name, L"Processes Labaratory",
        WS_OVERLAPPEDWINDOW | WS_VISIBLE, 250, 250,
        800, 600, NULL, NULL, hInstance, this
    );
    if (!hWnd_) {
        throw std::runtime_error("Window creation error: "s.append(std::to_string(GetLastError())));
    }
}

void GUI::SetHwnd(HWND hWnd) {
    hWnd_ = hWnd;
}

LRESULT GUI::WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    GUI* pThis = nullptr;

    if (message == WM_NCCREATE) {
        auto* create_struct = reinterpret_cast<CREATESTRUCTW*>(lParam);
        pThis = static_cast<GUI*>(create_struct->lpCreateParams);
        SetWindowLongPtrW(hWnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
        pThis->SetHwnd(hWnd);
    }
    else {
        pThis = reinterpret_cast<GUI*>(GetWindowLongPtrW(hWnd, GWLP_USERDATA));
    }

    if (pThis) {
        return pThis->HandleMessage(message, wParam, lParam);
    }

    return DefWindowProcW(hWnd, message, wParam, lParam);
}

void GUI::CreateControls() {
    CreateWindowW(L"BUTTON", L"Full check", WS_CHILD | WS_VISIBLE,
        25, 25, 100, 50,
        hWnd_, (HMENU)1001, NULL, NULL);

    CreateWindowW(L"BUTTON", L"Find Hidden", WS_CHILD | WS_VISIBLE,
        25, 95, 100, 50,
        hWnd_, (HMENU)1002, NULL, NULL);

    CreateWindowW(L"BUTTON", L"Find RWX", WS_CHILD | WS_VISIBLE,
        25, 165, 100, 50,
        hWnd_, (HMENU)1003, NULL, NULL);

    CreateWindowW(L"BUTTON", L"Clear LOGS", WS_CHILD | WS_VISIBLE,
        25, 500, 100, 50,
        hWnd_, (HMENU)1004, NULL, NULL);

    debug_console_ = CreateWindowW(L"BUTTON", L"Show Console", WS_CHILD | WS_VISIBLE,
        25, 400, 100, 50,
        hWnd_, (HMENU)1005, NULL, NULL);

    listbox_ = CreateWindowW(L"LISTBOX", NULL, WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL,
        150, 25, 595, 500,
        hWnd_, (HMENU)1006, NULL, NULL);
}

LRESULT GUI::HandleMessage(UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_CREATE:
        CreateControls();
        break;
    case WM_COMMAND:
    {
        if (LOWORD(wParam) == 1001) {
            LOG_DEBUG("Pressed full scan");
            std::jthread([this]() {
                StartFullScan();
                }).detach();
        }
        else if (LOWORD(wParam) == 1002) {
            LOG_DEBUG("Pressed scan for hidden processes");
            std::jthread([this]() {
                StartScanForHiddenProcesses();
                }).detach();
        }
        else if (LOWORD(wParam) == 1003) {
            LOG_DEBUG("Pressed scan for compromised processes");
            std::jthread([this]() {
                ScanForCompromisedProcesses();
                }).detach();
        }
        else if (LOWORD(wParam) == 1004) {
            LOG_DEBUG("Clearing logs...");
            SendMessageW(listbox_, LB_RESETCONTENT, 0, 0);
        }
        else if (LOWORD(wParam) == 1005) {
            LOG_DEBUG("Show console");
            ShowWindow(GetConsoleWindow(), SW_NORMAL);
            DestroyWindow(debug_console_);
            debug_console_ = CreateWindowW(L"BUTTON", L"Hide Console", WS_CHILD | WS_VISIBLE,
                25, 400, 100, 50,
                hWnd_, (HMENU)1007, NULL, NULL);
        }
        else if (LOWORD(wParam) == 1007) {
            LOG_DEBUG("Hide console");
            ShowWindow(GetConsoleWindow(), SW_HIDE);
            DestroyWindow(debug_console_);
            debug_console_ = CreateWindowW(L"BUTTON", L"Show Console", WS_CHILD | WS_VISIBLE,
                25, 400, 100, 50,
                hWnd_, (HMENU)1005, NULL, NULL);
        }
    }
    break;
    case WM_APP_LOG_MESSAGE:
    {
        if (!IsWindow(hWnd_)) {
            LOG_CRITICAL("hWnd_ is not a valid window!");
        }
        auto* text = reinterpret_cast<std::wstring*>(lParam);
        SendMessageW(listbox_, LB_ADDSTRING, 0, (LPARAM)text->c_str());
        int count = SendMessageW(listbox_, LB_GETCOUNT, 0, 0);
        SendMessageW(listbox_, LB_SETTOPINDEX, count - 1, 0);
        delete text;
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(wParam);
        break;
    default:
        return DefWindowProcW(hWnd_, message, wParam, lParam);
    }
    return 0;
}

ATOM GUI::RegisterMainWindow(HINSTANCE hInstance, LPCWSTR lpszClassName) {
    WNDCLASSEXW wnd{ 0 };
    wnd.cbSize = sizeof(WNDCLASSEXW);
    wnd.lpfnWndProc = GUI::WndProc;
    wnd.lpszClassName = lpszClassName;
    wnd.hInstance = hInstance;
    wnd.style = CS_HREDRAW | CS_VREDRAW;
    wnd.hbrBackground = (HBRUSH)COLOR_APPWORKSPACE;
    wnd.hCursor = LoadCursorW(NULL, MAKEINTRESOURCEW(IDC_ARROW));
    return RegisterClassExW(&wnd);
}

void GUI::SetHorizontalScrollSize(std::wstring_view str) {
    HDC hdc = GetDC(listbox_);
    HFONT hFont = (HFONT)SendMessageW(listbox_, WM_GETFONT, 0, 0);
    SelectObject(hdc, hFont);

    SIZE size;
    GetTextExtentPoint32W(hdc, str.data(), str.length(), &size);
    ReleaseDC(listbox_, hdc);
    max_horizontal_size_ = max(max_horizontal_size_, size.cx);
    SendMessageW(listbox_, LB_SETHORIZONTALEXTENT, max_horizontal_size_ + 10, 0);
}

void GUI::LogToGUI(const std::wstring& text) {
    auto* msg = new std::wstring(text);
    PostMessageW(hWnd_, WM_APP_LOG_MESSAGE, 0, (LPARAM)msg);
}

void GUI::ScanForHiddenProcesses() {
    auto hp = application_.DetectHiddenProcesses();
    if (hp.empty()) {
        LOG_INFO("No hidden processes found");
        LogToGUI(L"No hidden processes found");
    }
    else {
        for (const auto& hidden_proc : hp) {
            std::wstringstream strm{};
            strm << "[" << proc_scan::domain::StringToWideChar(hidden_proc.pid_)->c_str() << "]["
                << proc_scan::domain::StringToWideChar(hidden_proc.process_name_)->c_str()
                << "] " << proc_scan::domain::StringToWideChar(hidden_proc.comment_)->c_str()
                << "\n";
            auto* wstr = new std::wstring(strm.str());
            SetHorizontalScrollSize(wstr->c_str());
            LogToGUI(wstr->c_str());
        }
    }
}

void GUI::ScanForCompromisedProcesses() {
    auto cp = application_.DetectCompromisedProcesses();
    if (cp.empty()) {
        LOG_INFO("No compromised processes found");
        LogToGUI(L"No compromised processes found");
    }
    else {
        for (const auto& compromised_proc : cp) {
            std::wstringstream strm{};
            strm << "[" << proc_scan::domain::StringToWideChar(compromised_proc.pid_)->c_str() << "]["
                << proc_scan::domain::StringToWideChar(compromised_proc.process_name_)->c_str()
                << "] " << proc_scan::domain::StringToWideChar(compromised_proc.comment_)->c_str()
                << "\n";
            auto* wstr = new std::wstring(strm.str());
            SetHorizontalScrollSize(wstr->c_str());
            LogToGUI(wstr->c_str());
        }
    }
}

void GUI::StartFullScan() {
    try {
        LogToGUI(L"Full scan started");
        ScanForHiddenProcesses();
        ScanForCompromisedProcesses();
        LogToGUI(L"Full scan complete");
    }
    catch (const std::exception& e) {
        LOG_ERROR(e.what());
        MessageBox(NULL, e.what(), "Error", MB_ICONERROR);
    }
}

void GUI::StartScanForHiddenProcesses() {
    try {
        LogToGUI(L"Scan for hidden processes started");
        ScanForHiddenProcesses();
        LogToGUI(L"Scan for hidden processes complete");
    }
    catch (const std::exception& e) {
        LOG_ERROR(e.what());
        MessageBox(NULL, e.what(), "Error", MB_ICONERROR);
    }
}

void GUI::StartScanForCompromisedProcesses() {
    try {
        LogToGUI(L"Scan for compromised processes started");
        ScanForCompromisedProcesses();
        LogToGUI(L"Scan for compromised processes complete");
    }
    catch (const std::exception& e) {
        LOG_ERROR(e.what());
        MessageBox(NULL, e.what(), "Error", MB_ICONERROR);
    }
}
