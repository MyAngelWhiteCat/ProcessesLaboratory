#pragma once

#include "../NtDll/ntdll.h"

#include <Windows.h>

#include <string>
#include <string_view>


namespace maltech {

    namespace escalator {

        using namespace std::literals;

        struct PrivilegeName {
            PrivilegeName() = delete;

            static constexpr std::string_view DEBUG = "SeDebugPrivilege"sv;
            static constexpr std::string_view TCB = "SeTcbPrivilege"sv;
            static constexpr std::string_view LOAD_DRIVER = "SeLoadDriverPrivilege"sv;
            static constexpr std::string_view TAKE_OWNERSHIP = "SeTakeOwnershipPrivilege"sv;
            static constexpr std::string_view SHUTDOWN = "SeShutdownPrivilege"sv;
        };

        using namespace std::literals;
    
        class PrivilegeEscalator {
        public:
            PrivilegeEscalator(ntdll::NtDll& ntdll)
                : ntdll_(ntdll)
            {
            }

            void EscalateToTCB();
            void EscalateToDebug();
            void EscalateToShutdown();
            void ResetPrivilege();

        private:
            ntdll::NtDll& ntdll_;
            std::string current_privilege_;
            BOOLEAN was_enabled_{ FALSE };
            BOOLEAN is_escaled_ = FALSE;

            void EscalateTo(const std::string_view privilege, BOOLEAN is_disable = false);
            void LogStatus(NTSTATUS status);

            LUID GetPrivilegeLUID(const std::string_view privilege_name);
            HANDLE GetProcessToken(HANDLE hProcess);
            HANDLE GetNtHandle(DWORD pid);
            ULONG GetTokeninfoLen(HANDLE hToken);

        };
        
    }

}

