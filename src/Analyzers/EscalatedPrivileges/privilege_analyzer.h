#pragma once

#include "../analyzer.h"
#include "../../domain.h"
#include "../../NtDll/ntdll.h"

#include <Windows.h>

namespace laboratory {

    namespace analyze {

        struct PrivilegeNames {
            PrivilegeNames() = delete;

            static constexpr std::string_view DEBUG = "SeDebugPrivilege"sv;
            static constexpr std::string_view TCB = "SeTcbPrivilege"sv;
            static constexpr std::string_view LOAD_DRIVER = "SeLoadDriverPrivilege"sv;
            static constexpr std::string_view TAKE_OWNERSHIP = "SeTakeOwnershipPrivilege"sv;
        };

        class PrivilegeAnalyzer : public Analyzer {
        public:
            PrivilegeAnalyzer(maltech::ntdll::NtDll& ntdll)
                : ntdll_(ntdll)
            {

            }

        private:
            maltech::ntdll::NtDll& ntdll_;

            AnalyzeResult StartAnalyze(const domain::Scan& scan) override;
            domain::SPProcessInfo AnalyzeProcess(DWORD pid);
        };

    }

}