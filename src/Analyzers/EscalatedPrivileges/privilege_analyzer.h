#pragma once

#include "../analyzer.h"
#include "../../domain.h"
#include "../../NtDll/ntdll.h"

#include <Windows.h>

#include <string_view>
#include <string>

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
            std::string AnalyzeProcess(DWORD pid);

            HANDLE GetNtHandle(DWORD pid);
            HANDLE GetProcessToken(HANDLE hProcess);
            std::vector<std::byte> GetPrivilegesBytes(HANDLE hToken);
            ULONG GetTokeninfoLen(HANDLE hToken);
            std::string IsPrivelegeDangerous(LUID luid);
            LUID GetPrivilegeLUID(const std::string_view privilege_name);
            bool IsPrivilegeEqual(LUID lhs, LUID rhs);
        };

    }

}