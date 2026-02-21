#pragma once

#include "../NtDll/ntdll.h"

#include <Windows.h>


namespace maltech {

    namespace escalator {

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
            ULONG current_privilege_ = 0;
            BOOLEAN was_enabled_{ FALSE };
            BOOLEAN is_escaled_ = FALSE;

            void EscalateTo(ULONG privilege);
            void LogStatus(NTSTATUS status);
        };
        
    }

}

