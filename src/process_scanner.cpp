#include "domain.h"
#include "logger.h"
#include "process_scanner.h"

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
#include <string_view>
#include <unordered_map>
#include <vector>


namespace proc_scan {

    using namespace std::literals;

    void ProcessScanner::CreateToolHelpSnapshot() {
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

    domain::Snapshot ProcessScanner::CreateQuickToolHelpSnapshot() {
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
        LOG_INFO("Quick snapshot Ready");
        return snapshot;
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

    SPProcessInfo ProcessScanner::GetProcessInfo(std::string_view process_name) const {
        for (const auto& snapshot : last_full_snapshots_ | std::views::reverse) {
            if (auto proc = snapshot.GetProcessInfo(process_name)) {
                return proc;
            }
        }
        return nullptr;
    }

    SPProcessInfo ProcessScanner::GetProcessInfo(DWORD pid) const {
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

    std::vector<domain::SuspiciousProcess> ProcessScanner::DetectHiddenProcesses() {
        std::vector<domain::SuspiciousProcess> hidden_processes;
        try {
            hidden_processes = FindHidenProcesses();
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Error while checking for hidden processes: "s + e.what());
        }

        return {};
    }

    std::vector<domain::SuspiciousProcess> ProcessScanner::DetectCompromisedProcesses() {
        std::vector<domain::SuspiciousProcess> compromised_processes;
        try {
            compromised_processes = FindCompromisedProcesses();
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Compomised processes detection error: "s + e.what());
        }
        return compromised_processes;
    }

    std::vector<domain::SuspiciousProcess> ProcessScanner::FindHidenProcesses() {
        try {
            domain::Scan scan;
            auto snapshot_future = std::async(std::launch::async,
                [this] {return CreateQuickToolHelpSnapshot(); });
            auto ntsnapshot_future = std::async(std::launch::async,
                [this] {return CreateNtSnapshot(); });

            auto analyzer = Analyzers_.find(domain::AnalyzerType::HiddenProcesses);
            if (analyzer == Analyzers_.end()) {
                throw std::runtime_error("Hidden processes Analyzer not initialized");
            }

            scan[domain::ScanMethod::ToolHelp] = snapshot_future.get();
            scan[domain::ScanMethod::NtQSI] = ntsnapshot_future.get();

            LOG_DEBUG("Snapshots ready. Start finding hidden processes");
            return analyzer->second->Analyze(std::move(scan)).suspicious_processes_;
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Hidden processes analyze error: "s + e.what());
        }

        return {}; // Dummy for no warning
    }

    std::vector<domain::SuspiciousProcess> ProcessScanner::FindCompromisedProcesses() {
        domain::Scan scan;
        try {
            auto snapshot_future = std::async(std::launch::async, 
                [this]() { return CreateNtSnapshot(); });

            auto analyzer = Analyzers_.find(domain::AnalyzerType::CompromisedProcesses);
            if (analyzer == Analyzers_.end()) {
                throw std::runtime_error("Compromised processes Analyzer not initialized");
            }

            scan[domain::ScanMethod::NtQSI] = snapshot_future.get();
            
            LOG_DEBUG("Snapshots ready. Start finding compromised processes");
            return analyzer->second->Analyze(std::move(scan)).suspicious_processes_;
        }
        catch (const std::exception& e) {
            LOG_CRITICAL("Compromised process analyze error: "s + e.what());
        }
        return {}; // Dummy for no warning
    }

    void ProcessScanner::LoadNtModule() {
        if (ntdll_) return;
        ntdll_ = domain::LoadModule(domain::NtNames::NTDLL);
        if (!ntdll_) {
            throw std::runtime_error("Can't load: "s
                + domain::WideCharToString(domain::NtNames::NTDLL.data()));
        }
        LOG_DEBUG("NtModule loaded");
    }

    void ProcessScanner::LoadNtQuerySystemInformation() {
        if (NtQuerySystemInformation_) return;
        NtQuerySystemInformation_ = domain::LoadFunctionFromModule
            <domain::PNtQuerySystemInformation>(ntdll_, domain::NtNames::NTQSI);
        if (!NtQuerySystemInformation_) {
            throw std::runtime_error("Incorrect load func: " + std::string(domain::NtNames::NTQSI));
        }
        LOG_DEBUG("NtQuerySystemInformation loaded");
    }

    size_t ProcessScanner::GetBufferSize() const {
        return buffer_size_;
    }

    void ProcessScanner::SetBufferSize(const size_t new_size) {
        buffer_size_ = new_size;
    }

    void ProcessScanner::GetProcModules(domain::ProcessInfo& pinfo) {
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

    void ProcessScanner::GetProcThreads(domain::ProcessInfo& pinfo) {
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

    DWORD ProcessScanner::GetProcessPrioritet(DWORD pid) {
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

    domain::Snapshot ProcessScanner::CreateNtSnapshot() {
        LOG_DEBUG("In CreateNtSnapshot");
        if (!NtQuerySystemInformation_) {
            throw std::logic_error("Should load NtQuerySystemInformation before using NtScan");
        }

        ULONG sysinfo_len = 0;
        NTSTATUS status = NtQuerySystemInformation_(SystemProcessInformation
            , NULL
            , sysinfo_len
            , &sysinfo_len
        );

        const NTSTATUS STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            throw std::runtime_error("Can't get sysinfo's length");
        }

        std::vector<BYTE> buffer(sysinfo_len);
        status = NtQuerySystemInformation_(SystemProcessInformation
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
