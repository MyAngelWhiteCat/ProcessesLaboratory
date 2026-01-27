#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <ostream>
#include <iostream>
#include <vector>
#include <unordered_map>

#include <Windows.h>

#include "domain.h"

namespace proc_scan {

    using namespace std::literals;

    using SystemClock = std::chrono::system_clock;
    using PidToProcessIndex = std::unordered_map<DWORD, domain::ProcessInfo>;
    using SPProcessInfo = std::shared_ptr<domain::ProcessInfo>;

    typedef NTSTATUS(*PNtQuerySystemInformation)(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength
        );

    class ProcessScanner {
    public:
        void CreateSnapshot();
        domain::PidToProcessIndex CreateQuickSnapshot();

        void PrintLastFullSnapshot(std::ostream& out);
        void SetFullSnapshotsBufferSize(size_t size);

        domain::SPProcessInfo GetProcessInfo(std::string_view process_name) const;
        domain::SPProcessInfo GetProcessInfo(DWORD pid) const;
        void ClearBuffer();

        std::vector<domain::ProcessInfo> FindHidenProcesses();

        size_t GetBufferSize() const;
        void SetBufferSize(const size_t new_size);

    private:
        size_t buffer_size_ = 10;
        std::deque<domain::Snapshot> last_full_snapshots_;

        void GetProcModules(domain::ProcessInfo& pinfo);
        void GetProcThreads(domain::ProcessInfo& pinfo);
        DWORD GetProcessPrioritet(DWORD pid);
        std::vector<domain::ProcessInfo> FastFindProcesses();
    };

} // namespace proc_scan
