#include "admin_rights_analyzer.h"
#include "../analyzer.h"

#include <Windows.h>

#include <string>

namespace laboratory {

    namespace analyze {

        AnalyzeResult AdminRightsAnalyzer::StartAnalyze(const domain::Scan& scans) {
            return AnalyzeResult();
        }

        std::pair<domain::Severity, std::string> AdminRightsAnalyzer::AnalyzeProcess(DWORD pid) {
            return std::pair<domain::Severity, std::string>();
        }

        bool AdminRightsAnalyzer::CheckByIntegrityLevel(HANDLE hToken) {
            return false;
        }

        bool AdminRightsAnalyzer::CheckByAdminGroud(HANDLE hToken) {
            return false;
        }

        bool AdminRightsAnalyzer::CheckByUAC(HANDLE hToken) {
            return false;
        }

    }

}