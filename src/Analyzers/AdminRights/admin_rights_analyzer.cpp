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
            domain::Severity severity = domain::Severity::INFO;
            std::string comment;

            domain::RaiiHandle hProcess(GetNtHandle(pid, PROCESS_QUERY_INFORMATION));
            domain::RaiiHandle hToken(GetProcessToken(hProcess.Get(), TOKEN_QUERY));

            bool integrity_level = CheckByIntegrityLevel(hToken.Get());
            bool admin_group = CheckByAdminGroud(hToken.Get());
            bool is_elevated = CheckByUAC(hToken.Get());

            if (admin_group && !is_elevated) {
                comment = "Process in admin group";
            }
            else if (integrity_level || is_elevated) {
                comment = "Process run as administrator";
                severity = domain::Severity::SUSPICIOUS;
            }

            return { severity, comment };
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