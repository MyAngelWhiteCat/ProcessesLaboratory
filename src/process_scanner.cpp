#include "domain.h"
#include "process_scanner.h"

#include <iostream>
#include <stdexcept>
#include <string>
#include <utility>
#include <ranges>

#include <TlHelp32.h>
#include <string_view>


namespace proc_scan {

    void ProcessScanner::CreateFullSnapshot() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        auto now = SystemClock::now();

        if (hSnapshot == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Snapshot creating error: " + std::to_string(GetLastError()));
        }
        
        PROCESSENTRY32W proc_entry{ 0 };
        proc_entry.dwSize = sizeof(PROCESSENTRY32W);
        if (!Process32FirstW(hSnapshot, &proc_entry)) {
            CloseHandle(hSnapshot);
            throw std::runtime_error("Snapshot reading error: " + std::to_string(GetLastError()));
        }

        domain::Snapshot snapshot(now);
        do {
            auto proc_info = 
                std::make_shared<domain::ProcessInfo>
                    (proc_entry.th32ProcessID, proc_entry.cntThreads
                   , domain::WideCharToString(proc_entry.szExeFile));
            snapshot.Insert(proc_info);

        } while (Process32NextW(hSnapshot, &proc_entry));

        if (last_full_snapshots_.size() >= buffer_size_) {
            last_full_snapshots_.pop_front();
        }
        last_full_snapshots_.push_back(std::move(snapshot));
        CloseHandle(hSnapshot);
    }

    void ProcessScanner::PrintLastFullSnapshot(std::ostream& out) {
        domain::Snapshot& last_snapshot = last_full_snapshots_.back();
        for (const auto& [_, proc] : last_snapshot.pid_to_proc_info_) {
            proc->Print(out);
        }
    }

    void ProcessScanner::SetFullSnapshotsBufferSize(size_t size) {
        buffer_size_ = size;
    }

    std::shared_ptr<domain::ProcessInfo> ProcessScanner::GetProcessInfo(std::string_view process_name) const {
        for (const auto& snapshot : last_full_snapshots_ | std::views::reverse) {
            if (auto proc = snapshot.GetProcessInfo(process_name)) {
                return proc;
            }
        }
        return nullptr;
    }

    std::shared_ptr<domain::ProcessInfo> ProcessScanner::GetProcessInfo(DWORD pid) const {
        for (const auto& snapshot : last_full_snapshots_ | std::views::reverse) {
            if (auto proc = snapshot.GetProcessInfo(pid)) {
                return proc;
            }
        }
        return nullptr;
    }

    void ProcessScanner::ClearBuffer() {
        last_full_snapshots_.clear();
    }

    void ProcessScanner::GetProcModules(domain::ProcessInfo& pinfo) {
        MODULEENTRY32W module_entry{ 0 };
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pinfo.pid_);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Module snapshot creating error: " 
                + std::to_string(GetLastError()));
        }

        module_entry.dwSize = sizeof(MODULEENTRY32);
        
        if (!Module32FirstW(hSnapshot, &module_entry)) {
            throw std::runtime_error("Module reading error: " + std::to_string(GetLastError()));
        }

        do {
            domain::ModuleInfo minfo(module_entry.th32ModuleID
                , domain::WideCharToString(module_entry.szModule)
                , domain::WideCharToString(module_entry.szExePath));
            
            pinfo.modules_.push_back(std::move(minfo));
        } while (Module32NextW(hSnapshot, &module_entry));

        CloseHandle(hSnapshot);
    }

}
