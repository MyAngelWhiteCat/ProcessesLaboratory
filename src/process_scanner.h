#pragma once

#include <chrono>
#include <deque>
#include <memory>
#include <ostream>
#include <iostream>
#include <Windows.h>

#include "domain.h"

namespace proc_scan {

    using SystemClock = std::chrono::system_clock;

    class ProcessScanner {
    public:
        void CreateSnapshot();
        void PrintLastFullSnapshot(std::ostream& out);
        void SetFullSnapshotsBufferSize(size_t size);

        std::shared_ptr<domain::ProcessInfo> GetProcessInfo(std::string_view process_name) const;
        std::shared_ptr<domain::ProcessInfo> GetProcessInfo(DWORD pid) const;
        void ClearBuffer();

    private:
        size_t buffer_size_ = 10;
        std::deque<domain::Snapshot> last_full_snapshots_;

        void GetProcModules(domain::ProcessInfo& pinfo);
        void GetProcThreads(domain::ProcessInfo& pinfo);
        DWORD GetProcessPrioritet(DWORD pid);
    };

} // namespace proc_scan
