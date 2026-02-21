#include "privilege_escalator.h"

#include "../Logger/logger.h"
#include "../MalwareTechniques/ntdll.h"

#include <Windows.h>
#include <winternl.h>

#include <exception>
#include <ios>
#include <ostream>
#include <sstream>


namespace maltech {

    namespace escalator {

        void PrivilegeEscalator::EscalateToTCB() {
            EscalateTo(3);
        }

        void PrivilegeEscalator::EscalateToDebug() {
            EscalateTo(20);
        }

        void PrivilegeEscalator::EscalateToShutdown() {
            EscalateTo(SE_SHUTDOWN_PRIVILEGE);
        }

        void PrivilegeEscalator::ResetPrivilege() {
            try {
                auto status = ntdll_
                    .RtlAdjustPrivilege(current_privilege_, FALSE, FALSE, &was_enabled_);
                if (NT_SUCCESS(status)) {
                    LOG_INFO("Successfully reset privilege");
                    is_escaled_ = false;
                }
                else {
                    LOG_ERROR("Error reseting privileges");
                }
            }
            catch (const std::exception& e) {
                LOG_CRITICAL("Can't reset privilege!");
            }
        }

        void PrivilegeEscalator::EscalateTo(ULONG privilege) {
            try {
                auto status = ntdll_
                    .RtlAdjustPrivilege(privilege, TRUE, FALSE, &was_enabled_);
                if (NT_SUCCESS(status)) {
                    LogStatus(status);
                    current_privilege_ = privilege;
                    is_escaled_ = true;
                }
                else {
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

    }

}
