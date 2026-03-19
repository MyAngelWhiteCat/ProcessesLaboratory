#include "analyzer.h"

#include <optional>
#include <chrono>
#include <utility>

#include "../domain.h"
#include <stdexcept>


namespace laboratory {

    namespace analyze {

        AnalyzeResult Analyzer::Analyze(const domain::Scan& scans) {
            auto result = StartAnalyze(scans);
            last_analyze_timestamp_ = Clock::now();
            return result;
        }

        std::optional<Clock::time_point> Analyzer::GeLastAnalyzeTimestamp() {
            return last_analyze_timestamp_;
        }

        void Analyzer::SetupNtdllPtr(maltech::ntdll::NtDll* ntdll) {
            ntdll_ = ntdll;
        }

        HANDLE Analyzer::GetNtHandle(DWORD pid, ACCESS_MASK desired_access) {
            if (!ntdll_) {
                throw std::runtime_error("Need to setup ntdll ptr before"
                    " using Nt functions in analyzers");
            }
            CLIENT_ID client_id{ (HANDLE)pid, NULL };
            OBJECT_ATTRIBUTES attributes = { sizeof(attributes) };
            HANDLE hProcess{ 0 };
            NTSTATUS status = ntdll_->NtOpenProcess(
                &hProcess,
                desired_access,
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

        HANDLE Analyzer::GetProcessToken(HANDLE hProcess) {
            if (!ntdll_) {
                throw std::runtime_error("Need to setup ntdll ptr before"
                    " using Nt functions in analyzers");
            }
            HANDLE hToken{ 0 };
            ntdll_->NtOpenProcessToken(
                hProcess,
                TOKEN_QUERY,
                &hToken);

            if (!hToken || hToken == INVALID_HANDLE_VALUE) {
                throw std::runtime_error("Error while nt open token. Error code: "
                    + std::to_string(GetLastError()));
            }

            return hToken;
        }

        std::vector<std::byte> Analyzer::GetTokenInfo
        (HANDLE hToken, TOKEN_INFORMATION_CLASS requested_info)
        {
            if (!ntdll_) {
                throw std::runtime_error("Need to setup ntdll ptr before"
                    " using Nt functions in analyzers");
            }
            ULONG tokeninfo_len = GetTokeninfoLen(hToken, requested_info);
            std::vector<std::byte> buffer(tokeninfo_len);
            ntdll_->NtQueryInformationToken(
                hToken,
                requested_info,
                buffer.data(),
                tokeninfo_len,
                &tokeninfo_len
            );

            return buffer;
        }

        ULONG Analyzer::GetTokeninfoLen(HANDLE hToken, TOKEN_INFORMATION_CLASS requested_info) {
            if (!ntdll_) {
                throw std::runtime_error("Need to setup ntdll ptr before"
                    " using Nt functions in analyzers");
            }
            ULONG tokeninfo_len = 0;
            ntdll_->NtQueryInformationToken(
                hToken,
                TokenPrivileges,
                NULL,
                0,
                &tokeninfo_len
            );
            return tokeninfo_len;
        }

    }

}