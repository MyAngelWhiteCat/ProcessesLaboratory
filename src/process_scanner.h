#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <ostream>
#include <exception>
#include <iostream>
#include <future>
#include <vector>

#include <Windows.h>
#include <winternl.h>

#include "domain.h"
#include "logger.h"
#include <unordered_map>

namespace proc_scan {

    using namespace std::literals;

    using SystemClock = std::chrono::system_clock;

    typedef NTSTATUS(*PNtQuerySystemInformation)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
        );

    class ProcessScanner {
    public:
        void CreateSnapshot();
        std::unordered_map<DWORD, domain::ProcessInfo>  CreateQuickSnapshot();

        void PrintLastFullSnapshot(std::ostream& out);
        void SetFullSnapshotsBufferSize(size_t size);

        std::shared_ptr<domain::ProcessInfo> GetProcessInfo(std::string_view process_name) const;
        std::shared_ptr<domain::ProcessInfo> GetProcessInfo(DWORD pid) const;
        void ClearBuffer();

        std::vector<domain::ProcessInfo> FindHidenProcesses() {
            try {
                std::vector<domain::ProcessInfo> hidden_processes;
                auto snapshot_future = std::async(std::launch::async,
                    [this] {return CreateQuickSnapshot(); });
                auto processes_future = std::async(std::launch::async,
                    [this] {return FastFindProcesses(); });

                auto snap_processes = snapshot_future.get();
                auto processes = processes_future.get();
                for (const auto& proc : processes) {
                    if (snap_processes.contains(proc.pid_)) {
                        LOG_INFO("["s + std::to_string(proc.pid_) + "] "s
                            + proc.process_name_ + " OK\n"s);
                    }
                    else {
                        LOG_INFO("["s + std::to_string(proc.pid_) + "] "s
                            + proc.process_name_ + " MAYBE HIDDEN!\n"s);
                        hidden_processes.push_back(proc);
                    }
                }
                return processes;
            }
            catch (const std::exception& e) {
                std::cout << "Error getting PIDs: " << e.what() << std::endl;
            }

        }

    private:
        size_t buffer_size_ = 10;
        std::deque<domain::Snapshot> last_full_snapshots_;

        void GetProcModules(domain::ProcessInfo& pinfo);
        void GetProcThreads(domain::ProcessInfo& pinfo);
        DWORD GetProcessPrioritet(DWORD pid);
        std::vector<DWORD> FastFindPIDs();
    };

} // namespace proc_scan
