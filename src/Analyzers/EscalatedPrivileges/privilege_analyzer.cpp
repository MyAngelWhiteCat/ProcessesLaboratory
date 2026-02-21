#include "privilege_analyzer.h"
#include "../../domain.h"
#include "../analyzer.h"

#include <Windows.h>


namespace laboratory {

    namespace analyze {

        AnalyzeResult PrivilegeAnalyzer::StartAnalyze(const domain::Scan& scan) {
            return {};
        }

        domain::SPProcessInfo PrivilegeAnalyzer::AnalyzeProcess(DWORD pid) {
            return domain::SPProcessInfo();
        }

    }

}