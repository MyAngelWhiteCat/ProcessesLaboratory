#pragma once

#include <chrono>
#include <deque>
#include <iostream>
#include <memory>
#include <ostream>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <Windows.h>

#include "../domain.h"
#include "../NtDll/ntdll.h"


namespace laboratory {

    using namespace std::literals;

    using SystemClock = std::chrono::system_clock;
    using PidToProcessIndex = std::unordered_map<DWORD, domain::ProcessInfo>;
    using SPProcessInfo = std::shared_ptr<domain::ProcessInfo>;


    class SnapshotsProvider {
    public:
        SnapshotsProvider(maltech::ntdll::NtDll& ntdll)
            : ntdll_(ntdll)
        {
        }

        domain::Snapshot GetNtSnapshot();
        domain::Snapshot GetToolHelpSnapshot();
        domain::Snapshot GetLastFullSnapshot();

        domain::SPProcessInfo GetProcessInfo(std::string_view process_name) const;
        domain::SPProcessInfo GetProcessInfo(DWORD pid) const;
        void ClearBuffer();

    private:
        maltech::ntdll::NtDll& ntdll_;

        void CreateToolHelpFullSnapshot();
        domain::Snapshot CreateQuickToolHelpSnapshot();

        domain::Snapshot CreateNtSnapshot();

        void GetProcModules(domain::ProcessInfo& pinfo);
        void GetProcThreads(domain::ProcessInfo& pinfo);

        DWORD GetProcessPrioritet(DWORD pid);

    };

} // namespace laboratory
