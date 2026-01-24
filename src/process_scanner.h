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
        void PrintLastFullSnapshot(std::ostream& out);
        void SetFullSnapshotsBufferSize(size_t size);

        std::shared_ptr<domain::ProcessInfo> GetProcessInfo(std::string_view process_name) const;
        std::shared_ptr<domain::ProcessInfo> GetProcessInfo(DWORD pid) const;
        void ClearBuffer();

        void FindHidenProcesses() {
            try {
                CreateSnapshot();
                auto pids = FastFindPIDs();
                for (const auto& pid : pids) {
                    if (GetProcessInfo(pid)) {
                        std::cout << pid << " OK\n";
                    }
                    else {
                        std::cout << pid << " HIDDEN!\n";
                    }
                }
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
