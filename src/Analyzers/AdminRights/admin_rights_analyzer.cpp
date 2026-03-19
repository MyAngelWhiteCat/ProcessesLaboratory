#include "admin_rights_analyzer.h"
#include "../../domain.h"
#include "../analyzer.h"

#include <Windows.h>

#include <string>
#include <utility>
#include <stdexcept>

namespace laboratory {

    namespace analyze {

        AnalyzeResult AdminRightsAnalyzer::StartAnalyze(const domain::Scan& scan) {
            auto snapshot = scan.find(domain::ScanMethod::NtQSI);
            if (snapshot == scan.end()) {
                throw std::runtime_error("Invalid scan");
            }

            AnalyzeResult result;

            for (const auto& [pid, proc_info] : snapshot->second.pid_to_proc_info_) {
                try {
                    LOG_INFO("Analyze "s + std::string(proc_info->GetProcessName()));
                auto [severity, comment] = AnalyzeProcess(pid);
                if (!comment.empty()) {
                    result.suspicious_processes_.emplace_back(
                        proc_info,
                        comment,
                        severity
                    );
                }
            }
                catch (const std::exception& e) {
                    LOG_ERROR("Admin rights analyze error: "s + e.what());
                }
            }
            return result;
        }

        std::pair<domain::Severity, std::string> AdminRightsAnalyzer::AnalyzeProcess(DWORD pid) {
            domain::Severity severity = domain::Severity::INFO;
            std::string comment;

            domain::RaiiHandle hProcess(GetNtHandle(pid, PROCESS_QUERY_INFORMATION));
            domain::RaiiHandle hToken(GetProcessToken(hProcess.Get(), TOKEN_QUERY));

            bool integrity_level = CheckByIntegrityLevel(hToken.Get());
            bool admin_group = CheckByAdminGroup(hToken.Get());
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
            auto il_bytes = GetTokenInfo(hToken, TokenIntegrityLevel);
            auto integrity_level = reinterpret_cast<PTOKEN_MANDATORY_LABEL>(il_bytes.data());
            return GetRid(integrity_level->Label.Sid) == SECURITY_MANDATORY_HIGH_RID;
        }

        bool AdminRightsAnalyzer::CheckByAdminGroup(HANDLE hToken) {
            auto tg_bytes = GetTokenInfo(hToken, TokenGroups);
            auto token_groups = reinterpret_cast<PTOKEN_GROUPS>(tg_bytes.data());
            for (const auto& token_group : token_groups->Groups) {
                if (GetRid(token_group.Sid) == SECURITY_MANDATORY_HIGH_RID) {
                    return true;
                }
            }
            return false;
        }

        bool AdminRightsAnalyzer::CheckByUAC(HANDLE hToken) {
            auto el_bytes = GetTokenInfo(hToken, TokenElevation);
            auto token_elevation = reinterpret_cast<PTOKEN_ELEVATION>(el_bytes.data());
            return token_elevation->TokenIsElevated;
        }

        DWORD AdminRightsAnalyzer::GetRid(PSID sid) {
            PUCHAR count = GetSidSubAuthorityCount(sid);
            DWORD rid = *GetSidSubAuthority(sid, (*count) - 1);
            return rid;
        }

    }

}