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
                    std::string comment = AnalyzeProcess(pid);
                    if (!comment.empty()) {
                        result.suspicious_processes_.emplace_back(
                            proc_info,
                            comment,
                            domain::Severity::INFO
                        );
                    }
                }
                catch (const std::exception& e) {
                    LOG_ERROR(e.what());
                }
            }
            return result;
        }

        std::string PrivilegeAnalyzer::AnalyzeProcess(DWORD pid) {
            domain::RaiiHandle hProcess(GetNtHandle(pid));
            domain::RaiiHandle hToken(GetProcessToken(hProcess.Get()));
            auto privileges_bytes = GetPrivilegesBytes(hToken.Get());
            TOKEN_PRIVILEGES* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>
                (privileges_bytes.data());
            std::string comment;
            for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
                auto& privilege = privileges->Privileges[i];
                if (privilege.Attributes == SE_PRIVILEGE_ENABLED) {
                    char name[256];
                    DWORD name_len = 256;
                    LookupPrivilegeNameA(NULL, &privilege.Luid, name, &name_len);
                    comment += "[" + std::string(name, name_len) + "]";
                }
            }
            LOG_DEBUG(comment);
            return comment;
        }

        HANDLE PrivilegeAnalyzer::GetNtHandle(DWORD pid) {
            CLIENT_ID client_id{ (HANDLE)pid, NULL };
            OBJECT_ATTRIBUTES attributes = { sizeof(attributes) };
            HANDLE hProcess{ 0 };
            NTSTATUS status = ntdll_.NtOpenProcess(
                &hProcess,
                PROCESS_QUERY_INFORMATION,
                &attributes,
                &client_id);

            if (!NT_SUCCESS(status)) {
                std::ostringstream strm{};
                strm << std::hex << status;
                throw std::runtime_error("NtOpenProcess failed for PID " +
                    std::to_string(pid) +
                    " with status: 0x" +
                    strm.str());
            }
            
            if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
                throw std::runtime_error("Error while nt open process #"s 
                    + std::to_string(pid)
                    + ". Error code: "
                    + std::to_string(GetLastError()));
            }

            return hProcess;
        }

        HANDLE PrivilegeAnalyzer::GetProcessToken(HANDLE hProcess) {
            HANDLE hToken{ 0 };
            ntdll_.NtOpenProcessToken(
                hProcess,
                TOKEN_QUERY,
                &hToken);

            if (!hToken || hToken == INVALID_HANDLE_VALUE) {
                throw std::runtime_error("Error while nt open token. Error code: "
                    + std::to_string(GetLastError()));
            }

            return hToken;
        }

        std::vector<std::byte> PrivilegeAnalyzer::GetPrivilegesBytes(HANDLE hToken) {
            ULONG tokeninfo_len = GetTokeninfoLen(hToken);
            std::vector<std::byte> buffer(tokeninfo_len);
            ntdll_.NtQueryInformationToken(
                hToken,
                TokenPrivileges,
                buffer.data(),
                tokeninfo_len,
                &tokeninfo_len
            );

            return buffer;
        }

        ULONG PrivilegeAnalyzer::GetTokeninfoLen(HANDLE hToken) {
            ULONG tokeninfo_len = 0;
            ntdll_.NtQueryInformationToken(
                hToken,
                TokenPrivileges,
                NULL,
                0,
                &tokeninfo_len
            );
            return tokeninfo_len;
        }

        std::string PrivilegeAnalyzer::IsPrivelegeDangerous(LUID luid) {
            if (IsPrivilegeEqual(luid, GetPrivilegeLUID(PrivilegeNames::DEBUG))) {
                return "DEBUG";
            } 
            else if (IsPrivilegeEqual(luid, GetPrivilegeLUID(PrivilegeNames::LOAD_DRIVER))) {
                return "LOAD_DRIVER";
            }
            else if (IsPrivilegeEqual(luid, GetPrivilegeLUID(PrivilegeNames::TAKE_OWNERSHIP))) {
                return "TAKE_OWNERSHIP";
            }
            else if (IsPrivilegeEqual(luid, GetPrivilegeLUID(PrivilegeNames::TCB))) {
                return "TCB";
            }
            return "";
        }

        LUID PrivilegeAnalyzer::GetPrivilegeLUID(const std::string_view privilege_name) {
            LUID luid{ 0 };
            LookupPrivilegeValueA(NULL, privilege_name.data(), &luid);
            return luid;
        }

        bool PrivilegeAnalyzer::IsPrivilegeEqual(LUID lhs, LUID rhs) {
            return lhs.HighPart == rhs.HighPart && lhs.LowPart == rhs.LowPart;
        }

    }

}