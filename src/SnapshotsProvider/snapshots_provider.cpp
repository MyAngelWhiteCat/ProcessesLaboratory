#include "../domain.h"
#include "../Logger/logger.h"
#include "snapshots_provider.h"

#include <iostream>
#include <ranges>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <TlHelp32.h>
#include <Windows.h>
#include <winternl.h>

#include <exception>
#include <future>
#include <memory>
#include <vector>


namespace laboratory {

    using namespace std::literals;

    void SnapshotsProvider::CreateToolHelpFullSnapshot() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        auto now = domain::Clock::now();

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
            auto proc_info = std::make_shared<domain::ProcessInfo>
                (proc_entry.th32ProcessID, proc_entry.cntThreads
                    , domain::WideCharToString(proc_entry.szExeFile));
            try {
                if (DWORD prioritet = GetProcessPrioritet(proc_info->GetPid())) {
                    proc_info->SetPriority(prioritet);
                }
            }
            catch (const std::exception& e) {
                LOG_CRITICAL("Getting prioritet error: "s + e.what());
            }
            try {
                GetProcModules(*proc_info);
            }
            catch (const std::exception& e) {
                LOG_CRITICAL("Reading process modules error: "s + e.what());
            }

            try {
                GetProcThreads(*proc_info);
            }
            catch (const std::exception& e) {
                LOG_CRITICAL("Reading process threads error: "s + e.what());
            }

            snapshot.Insert(proc_info);

        } while (Process32NextW(hSnapshot, &proc_entry));

        if (last_full_snapshots_.size() >= buffer_size_) {
            last_full_snapshots_.pop_front();
        }
        last_full_snapshots_.push_back(std::move(snapshot));
        CloseHandle(hSnapshot);
    }

    domain::Snapshot SnapshotsProvider::CreateQuickToolHelpSnapshot() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Quick Snapshot creating error: " + std::to_string(GetLastError()));
        }

        PROCESSENTRY32W proc_entry{ 0 };
        proc_entry.dwSize = sizeof(PROCESSENTRY32W);
        if (!Process32FirstW(hSnapshot, &proc_entry)) {
            CloseHandle(hSnapshot);
            throw std::runtime_error("Quick Snapshot reading error: " + std::to_string(GetLastError()));
        }

        domain::Snapshot snapshot(domain::Clock::now());
        do {
            snapshot.Insert(std::make_shared<domain::ProcessInfo>
                (proc_entry.th32ProcessID
                    , proc_entry.cntThreads
                    , domain::WideCharToString(proc_entry.szExeFile)
                ));

        } while (Process32NextW(hSnapshot, &proc_entry));

        CloseHandle(hSnapshot);
        LOG_INFO("Quick toolhelp snapshot Ready. Size: " + std::to_string(snapshot.Size()));
        return snapshot;
    }

    domain::Snapshot SnapshotsProvider::GetNtSnapshot() {
        return CreateNtSnapshot();
    }

    domain::Snapshot SnapshotsProvider::GetToolHelpSnapshot() {
        return CreateQuickToolHelpSnapshot();
    }

    domain::Snapshot SnapshotsProvider::GetLastFullSnapshot() {
        if (!last_full_snapshots_.empty()) {
            return last_full_snapshots_.back();
        }
        return {};
    }

    void SnapshotsProvider::PrintLastFullSnapshot(std::ostream& out) {
        domain::Snapshot& last_snapshot = last_full_snapshots_.back();
        for (const auto& [_, proc] : last_snapshot.pid_to_proc_info_) {
            proc->Print(out);
        }
    }

    void SnapshotsProvider::SetFullSnapshotsBufferSize(size_t size) {
        buffer_size_ = size;
    }

    SPProcessInfo SnapshotsProvider::GetProcessInfo(std::string_view process_name) const {
        for (const auto& snapshot : last_full_snapshots_ | std::views::reverse) {
            if (auto proc = snapshot.GetProcessInfo(process_name)) {
                return proc;
            }
        }
        return nullptr;
    }

    SPProcessInfo SnapshotsProvider::GetProcessInfo(DWORD pid) const {
        for (const auto& snapshot : last_full_snapshots_ | std::views::reverse) {
            if (auto proc = snapshot.GetProcessInfo(pid)) {
                return proc;
            }
        }
        return nullptr;
    }

    void SnapshotsProvider::ClearBuffer() {
        last_full_snapshots_.clear();
    }

    size_t SnapshotsProvider::GetBufferSize() const {
        return buffer_size_;
    }

    void SnapshotsProvider::SetBufferSize(const size_t new_size) {
        buffer_size_ = new_size;
    }

    void SnapshotsProvider::GetProcModules(domain::ProcessInfo& pinfo) {
        MODULEENTRY32W module_entry{ 0 };

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pinfo.GetPid());
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Process " + std::to_string(pinfo.GetPid())
                + " modules snapshot creating error: "
                + std::to_string(GetLastError()));
        }

        module_entry.dwSize = sizeof(MODULEENTRY32W);

        if (!Module32FirstW(hSnapshot, &module_entry)) {
            CloseHandle(hSnapshot);
            throw std::runtime_error("Module reading error: " + std::to_string(GetLastError()));
        }

        do {
            domain::ModuleInfo minfo(module_entry.th32ModuleID
                , domain::WideCharToString(module_entry.szModule)
                , domain::WideCharToString(module_entry.szExePath));

            pinfo.AddModule(std::move(minfo));
        } while (Module32NextW(hSnapshot, &module_entry));

        CloseHandle(hSnapshot);
    }

    void SnapshotsProvider::GetProcThreads(domain::ProcessInfo& pinfo) {
        THREADENTRY32 thread_entry{ 0 };

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            throw std::runtime_error("Creating threads snapshot error: "
                + std::to_string(GetLastError()));
        }

        thread_entry.dwSize = sizeof(THREADENTRY32);

        if (!Thread32First(hSnapshot, &thread_entry)) {
            CloseHandle(hSnapshot);
            throw std::runtime_error("Thread reading error: " + std::to_string(GetLastError()));
        }

        do {
            if (thread_entry.th32OwnerProcessID == pinfo.GetPid()) {
                domain::ThreadInfo tinfo(thread_entry.th32ThreadID
                    , thread_entry.th32OwnerProcessID, thread_entry.tpBasePri);

                pinfo.AddThread(std::move(tinfo));
            }

        } while (Thread32Next(hSnapshot, &thread_entry));

        CloseHandle(hSnapshot);
    }

    DWORD SnapshotsProvider::GetProcessPrioritet(DWORD pid) {
        DWORD process_prioritet = 0;
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if (hProcess == NULL) {
            throw std::runtime_error("Can't open process " + std::to_string(pid));
        }

        process_prioritet = GetPriorityClass(hProcess);
        if (!process_prioritet) {
            CloseHandle(hProcess);
            throw std::runtime_error("Can't get prioritet of " + std::to_string(pid)
                + ". Error code: " + std::to_string(GetLastError()));
        }
        CloseHandle(hProcess);
        return process_prioritet;
    }

    domain::Snapshot SnapshotsProvider::CreateNtSnapshot() {
        ULONG sysinfo_len = 0;
        NTSTATUS status = ntdll_.NtQuerySystemInformation(SystemProcessInformation
            , NULL
            , sysinfo_len
            , &sysinfo_len
        );

        const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            throw std::runtime_error("Can't get sysinfo's length");
        }

        std::vector<BYTE> buffer(sysinfo_len);
        status = ntdll_.NtQuerySystemInformation(SystemProcessInformation
            , buffer.data()
            , sysinfo_len
            , &sysinfo_len
        );

        if (!NT_SUCCESS(status)) {
            throw std::runtime_error("Can't get system information: "
                + std::to_string(GetLastError()));
        }

        PSYSTEM_PROCESS_INFORMATION sysinfo =
            reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>
            (buffer.data());

        domain::Snapshot processes(domain::Clock::now());
        while (true) {
            processes.Insert(std::make_shared<domain::ProcessInfo>(
                HandleToUlong(sysinfo->UniqueProcessId)
                , static_cast<DWORD>(sysinfo->NumberOfThreads)
                , domain::UnicodeToString(sysinfo->ImageName))
            );

            if (sysinfo->NextEntryOffset == 0) {
                break;
            }
            sysinfo = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>
                (reinterpret_cast<BYTE*>(sysinfo)
                    + sysinfo->NextEntryOffset);
        }

        LOG_DEBUG("NtSnapshot Ready. Size: "s.append(std::to_string(processes.Size())));
        return processes;
    }

}
