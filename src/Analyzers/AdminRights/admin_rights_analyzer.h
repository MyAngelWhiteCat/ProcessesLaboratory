#pragma once

#include "../analyzer.h"
#include "../../domain.h"
#include "../../NtDll/ntdll.h"

#include <Windows.h>


namespace laboratory {

    namespace analyze {
        
        class AdminRightsAnalyzer : public Analyzer {
        public:
            AdminRightsAnalyzer(maltech::ntdll::NtDll& ntdll)
            {
                SetupNtdllPtr(&ntdll);
            }
            
        private:

            AnalyzeResult StartAnalyze(const domain::Scan& scans) override;

            std::pair<domain::Severity, std::string> AnalyzeProcess(DWORD pid);

            bool CheckByIntegrityLevel(HANDLE hToken);
            bool CheckByAdminGroup(HANDLE hToken);
            bool CheckByUAC(HANDLE hToken);

            DWORD GetRid(PSID sid);
        };

    }

}