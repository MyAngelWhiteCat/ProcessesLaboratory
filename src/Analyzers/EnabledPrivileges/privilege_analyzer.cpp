#include "privilege_analyzer.h"
#include "../../domain.h"
#include "../analyzer.h"
#include "../../Logger/logger.h"

#include <Windows.h>

#include <stdexcept>
#include <string>
#include <cstddef>
#include <vector>
#include <memory>
#include <string_view>
#include <exception>


namespace laboratory {

    namespace analyze {

        AnalyzeResult PrivilegeAnalyzer::StartAnalyze(const domain::Scan& scan) {
            auto snapshot = scan.find(domain::ScanMethod::NtQSI);
            if (snapshot == scan.end()) {
                throw std::runtime_error("Invalid scan");
            }

            AnalyzeResult result;
            for (auto& [pid, proc_info] : snapshot->second.pid_to_proc_info_) {
                try {
                    LOG_DEBUG("Start analyze PID: "s
                        + std::to_string(pid)
                        + " - "
                        + std::string(proc_info->GetProcessName()));
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
                    LOG_ERROR(e.what());
                }
            }
            return result;
        }

        std::pair<domain::Severity, std::string> PrivilegeAnalyzer::AnalyzeProcess(DWORD pid) {
            domain::RaiiHandle hProcess(GetNtHandle(pid, PROCESS_QUERY_INFORMATION));
            domain::RaiiHandle hToken(GetProcessToken(hProcess.Get(), TOKEN_QUERY));
            auto privileges_bytes = GetPrivilegesBytes(hToken.Get());
            TOKEN_PRIVILEGES* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>
                (privileges_bytes.data());

            domain::Severity severity = domain::Severity::INFO;
            std::string comment;
            for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
                auto& privilege = privileges->Privileges[i];
                if (privilege.Attributes == SE_PRIVILEGE_ENABLED) {
                    if (IsPrivelegeDangerous(privilege.Luid)) {
                        severity = domain::Severity::SUSPICIOUS;
                    }
                    comment += "[" + GetPrivilegeName(&privilege.Luid) + "]";
                }
            }
            LOG_DEBUG(comment);
            return { severity, comment };
        }

        std::vector<std::byte> PrivilegeAnalyzer::GetPrivilegesBytes(HANDLE hToken) {
            return GetTokenInfo(hToken, TokenPrivileges);
        }

        bool PrivilegeAnalyzer::IsPrivelegeDangerous(LUID luid) {
            bool is_dangerous = false;
            if (IsPrivilegeEqual(luid, GetPrivilegeLUID(PrivilegeNames::DEBUG))) {
                is_dangerous = true;
            } 
            else if (IsPrivilegeEqual(luid, GetPrivilegeLUID(PrivilegeNames::LOAD_DRIVER))) {
                is_dangerous = true;
            }
            else if (IsPrivilegeEqual(luid, GetPrivilegeLUID(PrivilegeNames::TAKE_OWNERSHIP))) {
                is_dangerous = true;
            }
            else if (IsPrivilegeEqual(luid, GetPrivilegeLUID(PrivilegeNames::TCB))) {
                is_dangerous = true;
            }
            return is_dangerous;
        }

        LUID PrivilegeAnalyzer::GetPrivilegeLUID(const std::string_view privilege_name) {
            LUID luid{ 0 };
            LookupPrivilegeValueA(NULL, privilege_name.data(), &luid);
            return luid;
        }

        std::string PrivilegeAnalyzer::GetPrivilegeName(PLUID luid) {
            char name[256];
            DWORD name_len = 256;
            LookupPrivilegeNameA(NULL, luid, name, &name_len);
            return std::string(name, name_len);
        }

        bool PrivilegeAnalyzer::IsPrivilegeEqual(LUID lhs, LUID rhs) {
            return lhs.HighPart == rhs.HighPart && lhs.LowPart == rhs.LowPart;
        }

    }

}