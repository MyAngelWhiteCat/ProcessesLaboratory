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

        bool AdminRightsAnalyzer::CheckByIntegrityLevel(PHANDLE hToken) {
            return false;
        }

        bool AdminRightsAnalyzer::CheckByAdminGroud(PHANDLE hToken) {
            return false;
        }

        bool AdminRightsAnalyzer::CheckByUAC(PHANDLE hToken) {
            return false;
        }

    }

}