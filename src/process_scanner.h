#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <ostream>
#include <iostream>
#include <vector>

#include <Windows.h>

#include "domain.h"
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

        std::vector<domain::ProcessInfo> FindHidenProcesses();

    private:
        size_t buffer_size_ = 10;
        std::deque<domain::Snapshot> last_full_snapshots_;

        void GetProcModules(domain::ProcessInfo& pinfo);
        void GetProcThreads(domain::ProcessInfo& pinfo);
        DWORD GetProcessPrioritet(DWORD pid);
        std::vector<domain::ProcessInfo> FastFindProcesses();
    };

} // namespace proc_scan
