#pragma once

#include "../analyzer.h"
#include "../../domain.h"
#include "../../NtDll/ntdll.h"

#include <Windows.h>

namespace laboratory {

    namespace analyze {

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