#include "privilege_escalator.h"

#include "../Logger/logger.h"
#include "../NtDll/ntdll.h"
#include "../NtDll/ntdll_domain.h"

#include <Windows.h>
#include <winternl.h>

#include <exception>
#include <ios>
#include <ostream>
#include <sstream>
#include <string_view>
#include <string>
#include <stdexcept>


namespace maltech {

    namespace escalator {

        void PrivilegeEscalator::EscalateToTCB() {
            EscalateTo(PrivilegeName::TCB);
        }

        void PrivilegeEscalator::EscalateToDebug() {
            EscalateTo(PrivilegeName::DEBUG);
        }

        void PrivilegeEscalator::EscalateToShutdown() {
            EscalateTo(PrivilegeName::SHUTDOWN);
        }

        void PrivilegeEscalator::ResetPrivilege() {
            EscalateTo("", true);
        }

        void PrivilegeEscalator::EscalateTo(const std::string_view privilege,
            BOOLEAN is_disable) {
            try {
                TOKEN_PRIVILEGES token_privileges{ NULL };
                token_privileges.PrivilegeCount = 1;
                token_privileges.Privileges[0].Luid = GetPrivilegeLUID(privilege);
                token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                
                HANDLE hProcess = GetNtHandle(GetCurrentProcessId());
                HANDLE hToken = GetProcessToken(hProcess);

                NTSTATUS status = ntdll_.NtAdjustPrivilege(
                    hToken,
                    FALSE,
                    &token_privileges,
                    sizeof(token_privileges),
                    NULL,
                    NULL);

                if (NT_SUCCESS(status) && status == 0x00) {
                    LogStatus(status);
                    current_privilege_ = std::string(privilege);
                    is_escaled_ = true;
                }
                else {
                    if (is_disable) {
                        LOG_CRITICAL("Can't reset privileges!");
                        return;
                    }
                    LOG_ERROR("Can't escalate privilege! Try to reset...");
                    ResetPrivilege();
                }
            }
            catch (const std::exception& e) {
                LOG_CRITICAL("Escalating error:"s.append(e.what()));
            }
        }

        void PrivilegeEscalator::LogStatus(NTSTATUS status) {
            std::ostringstream strm{};
            strm << "Privilege adjust status: 0x" << std::hex << status << std::endl;
            LOG_INFO(strm.str());
        }

        HANDLE PrivilegeEscalator::GetNtHandle(DWORD pid) {
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

        HANDLE PrivilegeEscalator::GetProcessToken(HANDLE hProcess) {
            HANDLE hToken{ 0 };
            NTSTATUS status = ntdll_.NtOpenProcessToken(
                hProcess,
                TOKEN_ADJUST_PRIVILEGES,
                &hToken);

            if (!NT_SUCCESS(status)) {
                throw std::runtime_error("Error while nt open token. Error code: 0x"
                    + ntdll::domain::GetHexStatusCode(status));
            }

            return hToken;
        }

        ULONG PrivilegeEscalator::GetTokeninfoLen(HANDLE hToken) {
            ULONG tokeninfo_len = 0;
            NTSTATUS status = ntdll_.NtQueryInformationToken(
                hToken,
                TokenPrivileges,
                NULL,
                0,
                &tokeninfo_len
            );

            if (!NT_SUCCESS(status)) {
                throw std::runtime_error("Error while nt query information. Error code: 0x"
                    + ntdll::domain::GetHexStatusCode(status));
            }
            return tokeninfo_len;
        }

        LUID PrivilegeEscalator::GetPrivilegeLUID(const std::string_view privilege_name) {
            LUID luid{ 0 };
            LookupPrivilegeValueA(NULL, privilege_name.data(), &luid);
            return luid;
        }

    }

}
