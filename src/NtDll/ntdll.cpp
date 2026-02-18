#include "ntdll.h"
#include "../domain.h"

#include <Windows.h>

namespace maltech {

    namespace ntdll {

        NtDll::NtDll() {
            ntdll_ = labaratory::domain::LoadModule(Names::NTDLL);
            LOG_DEBUG("NtModule loaded");
        }

        NTSTATUS NtDll::RtlAdjustPrivilege(ULONG privilege,
            BOOLEAN enable, BOOLEAN client, PBOOLEAN was_enabled)
        {
            LoadRtlAdjustPrivelege();
            return RtlAdjustPrivilege_(privilege, enable, client, was_enabled);
        }

        NTSTATUS NtDll::NtQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass,
            PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength)
        {
            LoadNtQuerySystemInformation();
            return NtQuerySystemInformation_(SystemInformationClass,
                SystemInformation, SystemInformationLength, ReturnLength);
        }

        void NtDll::LoadRtlAdjustPrivelege() {
            if (RtlAdjustPrivilege_) return;
            RtlAdjustPrivilege_ = labaratory::domain::LoadFunctionFromModule
                <pRtlAdjustPrivilege>(ntdll_, Names::ADJUST_PRIVILEGE);
        }

        void NtDll::LoadNtQuerySystemInformation() {
            if (NtQuerySystemInformation_) {
                return;
            }
            NtQuerySystemInformation_ = labaratory::domain::LoadFunctionFromModule
                <pNtQuerySystemInformation>(ntdll_, Names::NTQSI);
        }

    }

}